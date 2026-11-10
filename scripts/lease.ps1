param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("acquire", "release", "status")]
    [string]$Action,

    [string]$Root = "",
    [string]$LaneId = "",
    [string]$Scope = "",
    [string]$Boundary = ""
)

$ErrorActionPreference = "Stop"
$RegistryDir = $PSScriptRoot

function Get-NormalizedRoot([string]$PathText) {
    $full = [System.IO.Path]::GetFullPath($PathText)
    if ($full.Length -gt 3) {
        $full = $full.TrimEnd('\', '/')
    }
    return $full
}

function Test-SameOrAncestor([string]$CandidateAncestor, [string]$CandidateChild) {
    $a = $CandidateAncestor.ToLowerInvariant().TrimEnd('\', '/')
    $c = $CandidateChild.ToLowerInvariant().TrimEnd('\', '/')
    if ($a -eq $c) { return $true }
    return $c.StartsWith("$a\")
}

function Get-LeaseDir([string]$NormalizedRoot) {
    $leaf = [System.IO.Path]::GetFileName($NormalizedRoot)
    if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = "root" }
    $slug = ($leaf.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($slug)) { $slug = "root" }
    if ($slug.Length -gt 36) { $slug = $slug.Substring(0, 36).Trim('-') }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($NormalizedRoot.ToLowerInvariant())
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hex = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant().Substring(0, 12)
    return Join-Path $RegistryDir "$slug-$hex.lease"
}

if ($Action -eq "status") {
    $held = @(Get-ChildItem -LiteralPath $RegistryDir -Directory -Filter "*.lease" -ErrorAction SilentlyContinue)
    Write-Output "LEASE REGISTRY : $RegistryDir"
    Write-Output "HELD           : $($held.Count)"
    foreach ($d in $held) {
        $metaPath = Join-Path $d.FullName "lease.json"
        if (Test-Path -LiteralPath $metaPath) {
            Write-Output (Get-Content -LiteralPath $metaPath -Raw)
        } else {
            Write-Output "  $($d.Name) (initializing)"
        }
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Root) -or [string]::IsNullOrWhiteSpace($LaneId)) {
    Write-Error "-Root and -LaneId are required for $Action"
    exit 64
}

$NormRoot = Get-NormalizedRoot $Root
if (-not (Test-Path -LiteralPath $NormRoot)) {
    Write-Error "Target root does not exist: $NormRoot"
    exit 2
}

$LeaseDir = Get-LeaseDir $NormRoot

if ($Action -eq "acquire") {
    $existing = @(Get-ChildItem -LiteralPath $RegistryDir -Directory -Filter "*.lease" -ErrorAction SilentlyContinue)
    foreach ($d in $existing) {
        $metaPath = Join-Path $d.FullName "lease.json"
        if (-not (Test-Path -LiteralPath $metaPath)) {
            Write-Output "LEASE HELD (initializing): $($d.Name)"
            exit 1
        }
        $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
        $otherRoot = [string]$meta.protected_root
        $otherLane = [string]$meta.lane_id
        if ((Test-SameOrAncestor $otherRoot $NormRoot) -or (Test-SameOrAncestor $NormRoot $otherRoot)) {
            if ($otherRoot.ToLowerInvariant() -eq $NormRoot.ToLowerInvariant() -and $otherLane -eq $LaneId) {
                Write-Output "ALREADY HELD BY THIS LANE"
                exit 0
            }
            Write-Output "LEASE CONFLICT: held by $otherLane on $otherRoot"
            exit 1
        }
    }

    try {
        $null = New-Item -ItemType Directory -Path $LeaseDir -ErrorAction Stop
    } catch {
        $metaPath = Join-Path $LeaseDir "lease.json"
        if (Test-Path -LiteralPath $metaPath) {
            $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
            if ([string]$meta.lane_id -eq $LaneId) {
                Write-Output "ALREADY HELD BY THIS LANE"
                exit 0
            }
        }
        Write-Output "LEASE CONFLICT: $($LeaseDir)"
        exit 1
    }

    $payload = [ordered]@{
        protected_root = $NormRoot
        lane_id        = $LaneId
        scope          = $Scope
        boundary       = $Boundary
        acquired_at    = [DateTimeOffset]::UtcNow.ToString("o")
    } | ConvertTo-Json -Depth 4
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $LeaseDir "lease.json"), $payload + "`n", $utf8NoBom)
    Write-Output "LEASE ACQUIRED"
    exit 0
}

if ($Action -eq "release") {
    if (-not (Test-Path -LiteralPath $LeaseDir)) {
        Write-Error "No active lease found at $LeaseDir"
        exit 1
    }
    $metaPath = Join-Path $LeaseDir "lease.json"
    if (Test-Path -LiteralPath $metaPath) {
        $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
        if ([string]$meta.lane_id -ne $LaneId) {
            Write-Error "Lease held by $([string]$meta.lane_id), not $LaneId"
            exit 1
        }
    }
    $releasedRoot = Join-Path $RegistryDir "_released"
    if (-not (Test-Path -LiteralPath $releasedRoot)) {
        $null = New-Item -ItemType Directory -Path $releasedRoot -Force
    }
    $stamp = [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffffffZ")
    $leafName = Split-Path -Leaf $LeaseDir
    Move-Item -LiteralPath $LeaseDir -Destination (Join-Path $releasedRoot "$leafName-$stamp")
    Write-Output "LEASE RELEASED"
    exit 0
}
