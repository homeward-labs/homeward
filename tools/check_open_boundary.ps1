# Homeward open-source boundary self-check (PowerShell edition)
# Equivalent to tools/check_open_boundary.sh / .py (same 7 checks).
#
# Usage (PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\check_open_boundary.ps1
#
# Exit code: 0 = all pass (safe to push) ; 1 = violations found (do NOT push).
#
# NOTE: output is ASCII-only on purpose - Windows PowerShell 5.1 misreads
# non-ASCII .ps1 files saved without BOM.

$ErrorActionPreference = "Continue"

# CRITICAL on Windows: decode child-process (git) stdout as UTF-8 and force
# UTF-8 when reading files. Without this, non-ASCII repo paths (e.g. a
# Chinese workspace folder) come back mojibake and .gitignore line structure
# gets corrupted by ANSI misdecoding.
$Utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $Utf8
$OutputEncoding = $Utf8

$script:fail = 0
$script:warn = 0

function Pass([string]$m) { Write-Host "  [PASS] $m" }
function Bad([string]$m)  { $script:fail++; Write-Host "  [FAIL] $m" -ForegroundColor Red }
function WarnP([string]$m){ $script:warn++; Write-Host "  [WARN] $m" -ForegroundColor Yellow }

$CLOSED_DIRS = @("src/enforcers", "src/editions")
$SENTINEL_RE = "@closed-source|@standard-only|@pro-only"

Write-Host ""
Write-Host "=============================================="
Write-Host " Homeward open-source boundary self-check"
Write-Host " Closed dirs : $($CLOSED_DIRS -join ' ')"
Write-Host " Sentinels   : $SENTINEL_RE"
Write-Host "=============================================="

# ---------- 0. locate repo root ----------
$top = git rev-parse --show-toplevel 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($top)) {
    Write-Host "  [FAIL] not inside a git repository."
    exit 1
}
Set-Location $top.Trim()

# ---------- 1. hooks ----------
Write-Host ""
Write-Host "1) Hook defenses"
$hp = (git config core.hooksPath 2>$null)
if ("$hp" -eq "hooks") { Pass "core.hooksPath = hooks" }
else { Bad "core.hooksPath is '$hp' (expected 'hooks'). Run: git config core.hooksPath hooks" }

foreach ($h in @("pre-commit", "pre-push")) {
    if (Test-Path (Join-Path "hooks" $h)) { Pass "hooks/$h exists" }
    else { Bad "hooks/$h is MISSING - one gate is gone" }
}

# ---------- 2. .gitignore rules ----------
Write-Host ""
Write-Host "2) .gitignore rules"
$gi = ""
if (Test-Path ".gitignore") {
    # ReadAllText with explicit UTF-8: Get-Content defaults to ANSI(GBK) and
    # misdecoding UTF-8 Chinese comments corrupts line boundaries.
    # Also normalize CRLF -> LF so regex anchors work regardless of checkout.
    $gi = [System.IO.File]::ReadAllText((Join-Path (Get-Location) ".gitignore"), $Utf8)
    $gi = $gi -replace "`r`n", "`n"
}
foreach ($d in $CLOSED_DIRS) {
    $pattern = "(?m)^" + [regex]::Escape($d) + "/?$"
    if ($gi -match $pattern) { Pass ".gitignore has rule '$d' (directory itself)" }
    else { Bad ".gitignore is missing rule '$d' (no inline comments after the path!)" }
}

# ---------- 3. ignore rules actually effective ----------
Write-Host ""
Write-Host "3) Ignore rules really in effect (probe paths)"
foreach ($d in $CLOSED_DIRS) {
    git check-ignore -q --no-index "$d/probe.py" 2>$null
    if ($LASTEXITCODE -eq 0) { Pass "'$d/probe.py' would be ignored" }
    else { Bad "'$d/probe.py' NOT ignored - files under '$d' can be git-added" }
}

# ---------- 4. tracked files ----------
Write-Host ""
Write-Host "4) Tracked files (git ls-files)"
$tracked = @(git ls-files 2>$null) | Where-Object { $_ }
$hits = @($tracked | Where-Object { $f = $_; ($CLOSED_DIRS | Where-Object { $f -eq $_ -or $f.StartsWith($_ + "/") }).Count -gt 0 })
if ($hits.Count -gt 0) {
    Bad "closed-source paths found in the index:"
    $hits | ForEach-Object { Write-Host "         $_" }
} else { Pass "no closed-source paths tracked" }

# ---------- 5. full history ----------
Write-Host ""
Write-Host "5) Full commit history (incl. deleted files)"
$hist = @(git log --all --pretty=format: --name-only 2>$null) | Where-Object { $_ } | Sort-Object -Unique
$hits = @($hist | Where-Object { $f = $_; ($CLOSED_DIRS | Where-Object { $f -eq $_ -or $f.StartsWith($_ + "/") }).Count -gt 0 })
if ($hits.Count -gt 0) {
    Bad "closed-source paths found in history (even deleted ones):"
    $hits | ForEach-Object { Write-Host "         $_" }
} else { Pass "no closed-source paths in history" }

# ---------- 6. sentinels under src/ (HEAD tree only) ----------
Write-Host ""
Write-Host "6) Sentinel markers (HEAD, src/ only)"
git rev-parse --verify HEAD 2>$null *> $null
if ($LASTEXITCODE -eq 0) {
    $out = git grep -l -E $SENTINEL_RE HEAD -- src/ 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) {
        Bad "files containing closed-source sentinels:"
        @($out) | ForEach-Object { Write-Host "         $_" }
    } else { Pass "no sentinels under src/ in HEAD" }
} else { WarnP "no commits yet, skipping sentinel scan" }

# ---------- 7. local closed dirs ----------
Write-Host ""
Write-Host "7) Local closed-source dirs (exist-but-ignored = OK)"
foreach ($d in $CLOSED_DIRS) {
    if (-not (Test-Path $d)) { Pass "'$d' does not exist locally (safest shape)"; continue }
    git check-ignore -q --no-index $d 2>$null
    if ($LASTEXITCODE -eq 0) { Pass "'$d' exists locally and is ignored (never pushed)" }
    else { WarnP "'$d' exists locally but is NOT ignored - git add -A would pick it up" }
}

# ---------- verdict ----------
Write-Host ""
Write-Host "=============================================="
if ($script:fail -gt 0) {
    Write-Host " RESULT: $($script:fail) failure(s), $($script:warn) warning(s) - do NOT push."
    Write-Host " Fix and re-run before 'git push'."
    Write-Host "=============================================="
    exit 1
}
Write-Host " RESULT: all checks passed ($($script:warn) warning(s)) - safe to push."
Write-Host " Remember: the pre-push hook will check again, and CI is the last gate."
Write-Host "=============================================="
exit 0
