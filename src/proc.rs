//! Contained child processes on Windows (DESIGN.md §9). Every invocation runs in its own Job Object
//! with kill-on-close: the child is created suspended, assigned to the job, then resumed, so no
//! descendant can start outside it. When the invocation ends (exit, deadline, park request), the
//! whole job is terminated and the conductor confirms the job's active-process count is zero. If
//! the conductor itself dies, the job handle closes and Windows kills the tree.
//!
//! No crates: the few kernel32/ntdll entry points are declared here.

use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

type Handle = *mut c_void;

const CREATE_SUSPENDED: u32 = 0x0000_0004;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS: i32 = 1;

#[repr(C)]
#[derive(Default)]
struct BasicLimit {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[repr(C)]
#[derive(Default)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[repr(C)]
#[derive(Default)]
struct ExtendedLimit {
    basic: BasicLimit,
    io: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[repr(C)]
#[derive(Default)]
struct BasicAccounting {
    total_user_time: i64,
    total_kernel_time: i64,
    this_period_total_user_time: i64,
    this_period_total_kernel_time: i64,
    total_page_fault_count: u32,
    total_processes: u32,
    active_processes: u32,
    total_terminated_processes: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> Handle;
    fn SetInformationJobObject(job: Handle, class: i32, info: *mut c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
    fn CancelSynchronousIo(thread: Handle) -> i32;
    fn QueryInformationJobObject(
        job: Handle,
        class: i32,
        info: *mut c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32;
    fn CloseHandle(h: Handle) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateIoCompletionPort(file: Handle, existing: Handle, key: usize, threads: u32) -> Handle;
    fn GetQueuedCompletionStatus(
        port: Handle,
        bytes: *mut u32,
        key: *mut usize,
        overlapped: *mut *mut c_void,
        ms: u32,
    ) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: u32,
        name: *mut u16,
        size: *mut u32,
    ) -> i32;
}

const JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION: i32 = 7;
const JOB_OBJECT_MSG_NEW_PROCESS: u32 = 6;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

#[repr(C)]
struct AssociatePort {
    key: *mut c_void,
    port: Handle,
}

/// The job's process-creation notices, delivered by Windows itself: every process that starts in
/// the job is reported, however briefly it lives. The image name is read at once; a process that
/// already exited is recorded by PID only.
struct Watch {
    port: Handle,
    images: Vec<String>,
}

impl Watch {
    fn attach(job: &Job) -> std::io::Result<Watch> {
        let port = unsafe { CreateIoCompletionPort(-1isize as Handle, std::ptr::null_mut(), 0, 1) };
        if port.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut info = AssociatePort {
            key: std::ptr::null_mut(),
            port,
        };
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<AssociatePort>() as u32,
            )
        };
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            unsafe { CloseHandle(port) };
            return Err(e);
        }
        Ok(Watch {
            port,
            images: Vec::new(),
        })
    }

    /// Drains notices, waiting up to `ms` for the first.
    fn drain(&mut self, mut ms: u32) {
        loop {
            let (mut msg, mut key, mut ov) = (0u32, 0usize, std::ptr::null_mut());
            let got =
                unsafe { GetQueuedCompletionStatus(self.port, &mut msg, &mut key, &mut ov, ms) };
            if got == 0 {
                return;
            }
            ms = 0;
            if msg == JOB_OBJECT_MSG_NEW_PROCESS {
                let pid = ov as usize as u32;
                self.images.push(
                    image_name(pid)
                        .unwrap_or_else(|| format!("pid {pid} (exited before it could be named)")),
                );
            }
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.port) };
    }
}

fn image_name(pid: u32) -> Option<String> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(h) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

#[link(name = "ntdll")]
extern "system" {
    fn NtResumeProcess(process: Handle) -> i32;
}

/// A kill-on-close job. Dropping it closes the handle, which kills anything still in it.
pub struct Job(Handle);

impl Job {
    pub fn new() -> std::io::Result<Job> {
        let h = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
        if h.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Job(h);
        let mut info = ExtendedLimit::default();
        info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<ExtendedLimit>() as u32,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }

    pub fn active_processes(&self) -> std::io::Result<u32> {
        let mut info = BasicAccounting::default();
        let ok = unsafe {
            QueryInformationJobObject(
                self.0,
                JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<BasicAccounting>() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info.active_processes)
    }

    pub fn total_processes(&self) -> std::io::Result<u32> {
        let mut info = BasicAccounting::default();
        let ok = unsafe {
            QueryInformationJobObject(
                self.0,
                JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<BasicAccounting>() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info.total_processes)
    }

    fn terminate(&self) -> std::io::Result<()> {
        let ok = unsafe { TerminateJobObject(self.0, 1) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Closes the last owned job handle so kill-on-close is an explicit cleanup fallback.
    fn close(mut self) -> std::io::Result<()> {
        let handle = std::mem::replace(&mut self.0, std::ptr::null_mut());
        let ok = unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

const JOB_CONFIRM_GRACE: Duration = Duration::from_secs(5);
const CHILD_REAP_GRACE: Duration = Duration::from_secs(2);
const CLEANUP_POLL: Duration = Duration::from_millis(100);

trait CleanupOps {
    fn terminate_job(&mut self) -> std::io::Result<()>;
    fn job_empty(&mut self) -> std::io::Result<bool>;
    fn close_job(&mut self) -> std::io::Result<()>;
    fn child_reaped(&mut self) -> std::io::Result<bool>;
}

struct WindowsCleanup<'a> {
    job: Option<Job>,
    child: &'a mut Child,
}

impl CleanupOps for WindowsCleanup<'_> {
    fn terminate_job(&mut self) -> std::io::Result<()> {
        self.job.as_ref().expect("open job").terminate()
    }

    fn job_empty(&mut self) -> std::io::Result<bool> {
        self.job
            .as_ref()
            .expect("open job")
            .active_processes()
            .map(|active| active == 0)
    }

    fn close_job(&mut self) -> std::io::Result<()> {
        self.job.take().expect("open job").close()
    }

    fn child_reaped(&mut self) -> std::io::Result<bool> {
        self.child.try_wait().map(|status| status.is_some())
    }
}

#[derive(Debug)]
struct CleanupReport {
    termination_succeeded: bool,
    active_processes_zero: bool,
    kill_on_close_succeeded: bool,
    child_reaped: bool,
    errors: Vec<String>,
}

impl CleanupReport {
    fn confirmed(&self) -> bool {
        self.termination_succeeded
            && self.active_processes_zero
            && self.kill_on_close_succeeded
            && self.child_reaped
            && self.errors.is_empty()
    }
}

fn bounded_poll(
    label: &str,
    timeout: Duration,
    interval: Duration,
    errors: &mut Vec<String>,
    mut check: impl FnMut() -> std::io::Result<bool>,
) -> bool {
    let started = Instant::now();
    loop {
        match check() {
            Ok(true) => return true,
            Ok(false) => {}
            Err(error) => {
                errors.push(format!("{label}: {error}"));
                return false;
            }
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            errors.push(format!(
                "{label}: timed out after {} ms",
                timeout.as_millis()
            ));
            return false;
        }
        std::thread::sleep(interval.min(timeout - elapsed));
    }
}

/// Terminates the job, confirms it empty for a bounded interval, closes the job handle to invoke
/// kill-on-close even after a failed termination, and reaps the root child for a second bounded
/// interval. Every failure is retained in the report; no cleanup step can block indefinitely.
fn bounded_cleanup(
    ops: &mut impl CleanupOps,
    job_confirm_grace: Duration,
    child_reap_grace: Duration,
    poll: Duration,
) -> CleanupReport {
    let mut errors = Vec::new();
    let termination_succeeded = match ops.terminate_job() {
        Ok(()) => true,
        Err(error) => {
            errors.push(format!("TerminateJobObject: {error}"));
            false
        }
    };
    let active_processes_zero = bounded_poll(
        "job active-process confirmation",
        job_confirm_grace,
        poll,
        &mut errors,
        || ops.job_empty(),
    );
    let kill_on_close_succeeded = match ops.close_job() {
        Ok(()) => true,
        Err(error) => {
            errors.push(format!("kill-on-close handle close: {error}"));
            false
        }
    };
    let child_reaped = bounded_poll(
        "root child reap",
        child_reap_grace,
        poll,
        &mut errors,
        || ops.child_reaped(),
    );
    CleanupReport {
        termination_succeeded,
        active_processes_zero,
        kill_on_close_succeeded,
        child_reaped,
        errors,
    }
}

/// How an invocation ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ending {
    Exited(i32),
    Deadline,
    ParkRequested,
    OutputLimitExceeded,
}

/// Accounting for the one combined raw stdout/stderr capture budget.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaptureReport {
    pub limit_bytes: u64,
    pub captured_bytes: u64,
    /// Bytes actually read after the shared budget was exhausted. This is a lower bound when
    /// `discard_count_complete` is false.
    pub discarded_bytes_observed: u64,
    /// True only when both applicable pipes reached actual EOF.
    pub discard_count_complete: bool,
    /// Successful invocations require this to be true. Overflow always makes it false.
    pub capture_complete: bool,
    pub output_limit_exceeded: bool,
    /// Names the coverage of hashes made from the retained bytes.
    pub retained_digest_coverage: String,
}

#[derive(Debug)]
pub struct Outcome {
    pub ending: Ending,
    /// The explicit Job Object termination call succeeded, the job reached zero active processes,
    /// kill-on-close succeeded, the root child was reaped, and captured streams reached EOF.
    pub windows_tree_confirmed: bool,
    /// Machine-readable cleanup details. Any false field prevents confirmation and promotion.
    pub termination_succeeded: bool,
    pub active_processes_zero: bool,
    pub kill_on_close_succeeded: bool,
    pub child_reaped: bool,
    pub cleanup_errors: Vec<String>,
    /// Every process that ever ran in the job, for the record.
    pub total_processes: u32,
    /// The image path of every process that started in the job, from Windows' own notices.
    pub images: Vec<String>,
    pub elapsed: Duration,
    pub capture: Option<CaptureReport>,
    /// These remain visible when output overflow is the irreversible primary ending.
    pub deadline_observed: bool,
    pub park_observed: bool,
}

pub struct Spec<'a> {
    /// Fixed argv: program and arguments. Never built from artifact text.
    pub argv: &'a [String],
    pub cwd: &'a Path,
    /// Written to stdin, which is then closed. `None` closes stdin at once.
    pub stdin: Option<&'a [u8]>,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub deadline: Duration,
    /// A park request: this file appearing ends the invocation (checked about once a second).
    pub park_file: Option<&'a Path>,
}

/// Runs one contained invocation to its end and confirms the Windows tree is gone.
pub fn run(spec: &Spec) -> std::io::Result<Outcome> {
    run_inner(spec, false).map(|(outcome, _)| outcome)
}

/// Captures both streams in memory. The caller scans them before any stage-file write, including
/// when the process is parked, times out, fails, or leaves termination unconfirmed.
pub type Captured = (Outcome, Vec<u8>, Vec<u8>);
type Streams = (Vec<u8>, Vec<u8>);

pub fn run_captured(spec: &Spec) -> std::io::Result<Captured> {
    let (outcome, streams) = run_inner(spec, true)?;
    let (stdout, stderr) = streams.expect("capture requested");
    Ok((outcome, stdout, stderr))
}

pub const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;
const CAPTURE_EOF_GRACE: Duration = Duration::from_millis(500);
const CAPTURE_CANCEL_GRACE: Duration = Duration::from_secs(2);

struct CaptureState {
    bytes: Mutex<Vec<u8>>,
    stop: AtomicBool,
    finished: AtomicBool,
    clean_eof: AtomicBool,
}

#[derive(Default)]
struct CaptureAccounting {
    captured: u64,
    discarded: u64,
}

struct CaptureBudget {
    limit: u64,
    accounting: Mutex<CaptureAccounting>,
    overflow: AtomicBool,
}

struct CaptureReader {
    thread: Option<JoinHandle<()>>,
    state: Arc<CaptureState>,
}

fn capture_reader<R: Read + Send + 'static>(
    mut stream: R,
    budget: Arc<CaptureBudget>,
) -> CaptureReader {
    let state = Arc::new(CaptureState {
        bytes: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
        finished: AtomicBool::new(false),
        clean_eof: AtomicBool::new(false),
    });
    let worker_state = Arc::clone(&state);
    let thread = std::thread::spawn(move || read_capture(&mut stream, &worker_state, &budget));
    CaptureReader {
        thread: Some(thread),
        state,
    }
}

fn read_capture<R: Read>(stream: &mut R, state: &CaptureState, budget: &CaptureBudget) {
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => {
                state.clean_eof.store(true, Ordering::Release);
                break;
            }
            Ok(n) => {
                let keep = {
                    let mut accounting = budget.accounting.lock().unwrap();
                    let room = budget.limit.saturating_sub(accounting.captured);
                    let keep = (n as u64).min(room) as usize;
                    accounting.captured += keep as u64;
                    accounting.discarded += (n - keep) as u64;
                    if keep != n {
                        budget.overflow.store(true, Ordering::Release);
                    }
                    keep
                };
                if keep != 0 {
                    state
                        .bytes
                        .lock()
                        .unwrap()
                        .extend_from_slice(&chunk[..keep]);
                }
                if state.stop.load(Ordering::Acquire) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    state.finished.store(true, Ordering::Release);
}

fn wait_for_reader(reader: &CaptureReader, timeout: Duration) -> bool {
    let started = Instant::now();
    while !reader.state.finished.load(Ordering::Acquire) && started.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(10));
    }
    reader.state.finished.load(Ordering::Acquire)
}

/// Obtains a bounded snapshot. A writer outside the Job Object may keep an inherited pipe open;
/// cancelling this thread's synchronous read prevents that writer from stalling quarantine and
/// marks the invocation unconfirmed.
fn finish_reader(mut reader: CaptureReader) -> (Vec<u8>, bool, bool) {
    let mut forced = false;
    if !wait_for_reader(&reader, CAPTURE_EOF_GRACE) {
        forced = true;
        reader.state.stop.store(true, Ordering::Release);
        if let Some(thread) = reader.thread.as_ref() {
            unsafe {
                CancelSynchronousIo(thread.as_raw_handle() as Handle);
            }
        }
        wait_for_reader(&reader, CAPTURE_CANCEL_GRACE);
    }
    let finished = reader.state.finished.load(Ordering::Acquire);
    if finished {
        if let Some(thread) = reader.thread.take() {
            if thread.join().is_err() {
                forced = true;
            }
        }
    }
    let bytes = if finished {
        std::mem::take(&mut *reader.state.bytes.lock().unwrap())
    } else {
        reader.state.bytes.lock().unwrap().clone()
    };
    let actual_eof = finished && reader.state.clean_eof.load(Ordering::Acquire);
    let confirmed = !forced && actual_eof;
    (bytes, actual_eof, confirmed)
}

fn choose_ending(
    exited: Option<i32>,
    output_limit_exceeded: bool,
    deadline: bool,
    park: bool,
) -> Option<Ending> {
    if output_limit_exceeded {
        Some(Ending::OutputLimitExceeded)
    } else if deadline {
        Some(Ending::Deadline)
    } else if park {
        Some(Ending::ParkRequested)
    } else {
        exited.map(Ending::Exited)
    }
}

fn run_inner(spec: &Spec, capture: bool) -> std::io::Result<(Outcome, Option<Streams>)> {
    let (program, args) = spec
        .argv
        .split_first()
        .ok_or_else(|| std::io::Error::other("empty argv"))?;
    let job = Job::new()?;
    let mut watch = Watch::attach(&job)?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(spec.cwd)
        .stdin(if spec.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::from(File::create(&spec.stdout)?)
        })
        .stderr(if capture {
            Stdio::piped()
        } else {
            Stdio::from(File::create(&spec.stderr)?)
        })
        .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
    let started = Instant::now();
    let mut child = cmd.spawn()?;
    let capture_budget = capture.then(|| {
        Arc::new(CaptureBudget {
            limit: MAX_CAPTURE_BYTES,
            accounting: Mutex::new(CaptureAccounting::default()),
            overflow: AtomicBool::new(false),
        })
    });
    let readers = if capture {
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let budget = capture_budget.as_ref().expect("capture budget");
        Some((
            capture_reader(stdout, Arc::clone(budget)),
            capture_reader(stderr, Arc::clone(budget)),
        ))
    } else {
        None
    };
    let handle = child.as_raw_handle() as Handle;
    if unsafe { AssignProcessToJobObject(job.0, handle) } == 0 {
        let err = std::io::Error::last_os_error();
        let _ = child.kill();
        return Err(err);
    }
    if unsafe { NtResumeProcess(handle) } != 0 {
        let _ = job.terminate();
        return Err(std::io::Error::other("NtResumeProcess failed"));
    }
    if let Some(bytes) = spec.stdin {
        if let Some(mut pipe) = child.stdin.take() {
            // A child that stops reading gets a broken pipe here; the deadline still applies.
            let _ = pipe.write_all(bytes);
        }
    }
    let mut last_park_check = Instant::now();
    let mut deadline_observed = false;
    let mut park_observed = false;
    let mut ending = loop {
        let exited = child.try_wait()?.map(|status| status.code().unwrap_or(-1));
        let output_limit_exceeded = capture_budget
            .as_ref()
            .is_some_and(|budget| budget.overflow.load(Ordering::Acquire));
        deadline_observed |= started.elapsed() >= spec.deadline;
        if output_limit_exceeded || exited.is_some() {
            // Sample the park condition at the same decision point as overflow. A PARK file that
            // appears during cleanup is not concurrent with the producer's ending. Sampling on
            // exit also covers a reader publishing overflow just after the child exits.
            park_observed |= spec.park_file.is_some_and(Path::exists);
        }
        if let Some(p) = spec.park_file {
            if last_park_check.elapsed() >= Duration::from_millis(900) {
                last_park_check = Instant::now();
                park_observed |= p.exists();
            }
        }
        if let Some(ending) = choose_ending(
            exited,
            output_limit_exceeded,
            deadline_observed,
            park_observed,
        ) {
            break ending;
        }
        watch.drain(100);
    };
    // The invocation is over either way: nothing it started may outlive it. Keep the total before
    // closing the job handle; after the bounded confirmation window, closing that handle invokes
    // the kill-on-close fallback. Root-child reaping is polled and never uses blocking wait().
    let (total_processes, total_processes_error) = match job.total_processes() {
        Ok(total) => (total, None),
        Err(error) => (0, Some(format!("job total-process accounting: {error}"))),
    };
    let mut cleanup = WindowsCleanup {
        job: Some(job),
        child: &mut child,
    };
    let mut cleanup_report = bounded_cleanup(
        &mut cleanup,
        JOB_CONFIRM_GRACE,
        CHILD_REAP_GRACE,
        CLEANUP_POLL,
    );
    if let Some(error) = total_processes_error {
        cleanup_report.errors.push(error);
    }
    let mut confirmed = cleanup_report.confirmed();
    watch.drain(0);
    let (streams, capture_report) = match readers {
        Some((stdout, stderr)) => {
            let (stdout, stdout_eof, stdout_confirmed) = finish_reader(stdout);
            let (stderr, stderr_eof, stderr_confirmed) = finish_reader(stderr);
            if !stdout_confirmed {
                cleanup_report
                    .errors
                    .push("stdout capture reader did not reach confirmed EOF".to_string());
            }
            if !stderr_confirmed {
                cleanup_report
                    .errors
                    .push("stderr capture reader did not reach confirmed EOF".to_string());
            }
            confirmed &= stdout_confirmed && stderr_confirmed;
            let budget = capture_budget.as_ref().expect("capture budget");
            let accounting = budget.accounting.lock().unwrap();
            let output_limit_exceeded = budget.overflow.load(Ordering::Acquire);
            let discard_count_complete = stdout_eof && stderr_eof;
            let capture_complete = !output_limit_exceeded && discard_count_complete;
            let report = CaptureReport {
                limit_bytes: budget.limit,
                captured_bytes: accounting.captured,
                discarded_bytes_observed: accounting.discarded,
                discard_count_complete,
                capture_complete,
                output_limit_exceeded,
                retained_digest_coverage: if capture_complete {
                    "complete-streams".to_string()
                } else {
                    "captured-prefix".to_string()
                },
            };
            drop(accounting);
            if output_limit_exceeded {
                ending = Ending::OutputLimitExceeded;
            }
            (Some((stdout, stderr)), Some(report))
        }
        None => (None, None),
    };
    Ok((
        Outcome {
            ending,
            windows_tree_confirmed: confirmed,
            termination_succeeded: cleanup_report.termination_succeeded,
            active_processes_zero: cleanup_report.active_processes_zero,
            kill_on_close_succeeded: cleanup_report.kill_on_close_succeeded,
            child_reaped: cleanup_report.child_reaped,
            cleanup_errors: cleanup_report.errors,
            total_processes,
            images: std::mem::take(&mut watch.images),
            elapsed: started.elapsed(),
            capture: capture_report,
            deadline_observed,
            park_observed,
        },
        streams,
    ))
}

#[cfg(test)]
mod tests {
    use super::{bounded_cleanup, choose_ending, CleanupOps, Ending};
    use std::time::{Duration, Instant};

    #[test]
    fn output_limit_remains_primary_when_timeout_or_park_are_also_observed() {
        assert_eq!(
            choose_ending(Some(0), true, true, false),
            Some(Ending::OutputLimitExceeded)
        );
        assert_eq!(
            choose_ending(None, true, false, true),
            Some(Ending::OutputLimitExceeded)
        );
    }

    struct StalledCleanup {
        close_calls: usize,
    }

    impl CleanupOps for StalledCleanup {
        fn terminate_job(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("synthetic termination failure"))
        }

        fn job_empty(&mut self) -> std::io::Result<bool> {
            Ok(false)
        }

        fn close_job(&mut self) -> std::io::Result<()> {
            self.close_calls += 1;
            Ok(())
        }

        fn child_reaped(&mut self) -> std::io::Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn failed_termination_and_stalled_reap_are_bounded_and_fail_closed() {
        let mut ops = StalledCleanup { close_calls: 0 };
        let started = Instant::now();
        let report = bounded_cleanup(
            &mut ops,
            Duration::from_millis(20),
            Duration::from_millis(20),
            Duration::from_millis(1),
        );

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            ops.close_calls, 1,
            "kill-on-close fallback is always invoked"
        );
        assert!(!report.confirmed());
        assert!(!report.termination_succeeded);
        assert!(!report.active_processes_zero);
        assert!(report.kill_on_close_succeeded);
        assert!(!report.child_reaped);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("synthetic termination failure")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("job active-process confirmation: timed out")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("root child reap: timed out")));
    }
}
