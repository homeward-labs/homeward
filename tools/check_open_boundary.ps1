# Homeward open-source boundary self-check (PowerShell edition)
# Equivalent to tools/check_open_boundary.sh / .py (same checks).
#
# The rules all come from the single source of truth tools/closed_assets.txt
# (dir / file / kbignore / pattern). Change the list, and every gate follows.
#
# Usage (PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\check_open_boundary.ps1
#
# Exit code: 0 = all pass (safe to push) ; 1 = violations found (do NOT push).
#
# NOTE: output is ASCII-only on purpose - Windows PowerShell 5.1 misreads
# non-ASCII .ps1 files saved without BOM.
#
# NOTE: file reads go through Get-Content (provider-aware), NOT the .NET
# System.IO.File APIs. On a mapped network drive (e.g. Z: -> \\host\share)
# Join-Path (Get-Location) returns a provider-qualified path
# ("Microsoft.PowerShell.Core\FileSystem::\\host\...") that .NET rejects with
# "The given path's format is not supported." A silent empty read would make
# every rule list empty and every check "pass" - a fail-open. Never do that.

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

$LIST = "tools/closed_assets.txt"
$LIST_EXCLUDE = ":(exclude)" + $LIST
$SENTINEL_RE = "@closed-source|@standard-only|@pro-only"

# ---------- 0. locate repo root ----------
$top = git rev-parse --show-toplevel 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($top)) {
    Write-Host "  [FAIL] not inside a git repository."
    exit 1
}
Set-Location $top.Trim()

Write-Host ""
Write-Host "=============================================================="
Write-Host " Homeward open-source boundary self-check"

if (-not (Test-Path $LIST)) {
    Write-Host "  [FAIL] single source of truth $LIST is MISSING - all gates lost their rules."
    Write-Host "=============================================================="
    exit 1
}

# ---------- parse the single list ----------
$dirs = New-Object System.Collections.Generic.List[string]
$files = New-Object System.Collections.Generic.List[string]
$kbignore = New-Object System.Collections.Generic.List[string]
$patterns = New-Object System.Collections.Generic.List[string]
foreach ($raw in (Get-Content -Encoding UTF8 $LIST)) {
    $line = "$raw".Trim()
    if ($line -eq "" -or $line.StartsWith("#")) { continue }
    if ($line.StartsWith("dir:"))      { $dirs.Add($line.Substring(4).Trim()) }
    elseif ($line.StartsWith("file:")) { $files.Add($line.Substring(5).Trim()) }
    elseif ($line.StartsWith("kbignore:")) { $kbignore.Add($line.Substring(9).Trim()) }
    elseif ($line.StartsWith("pattern:"))  { $patterns.Add($line.Substring(8).Trim()) }
}

# Fail-closed: an empty rule list means the list file could not be parsed.
if (($dirs.Count + $files.Count + $kbignore.Count + $patterns.Count) -eq 0) {
    Write-Host "  [FAIL] could not parse any rule from $LIST - refusing to claim 'safe'."
    Write-Host "=============================================================="
    exit 1
}

function Is-Closed([string]$p) {
    foreach ($d in $dirs) { if ($p -eq $d -or $p.StartsWith($d + "/")) { return $true } }
    return ($files -contains $p)
}

$PAT_RE = ""
if ($patterns.Count -gt 0) { $PAT_RE = ($patterns | ForEach-Object { "($_)" }) -join "|" }

Write-Host " list: $LIST (edit it and every gate follows)"
Write-Host " closed dirs $($dirs.Count) / closed files $($files.Count) / live-source rules $($patterns.Count)"
Write-Host " closed dirs : $($dirs -join ' ')"
Write-Host " sentinels   : $SENTINEL_RE"
Write-Host "=============================================================="

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

# ---------- 2. .gitignore rules (dirs) ----------
Write-Host ""
Write-Host "2) .gitignore rules (closed dirs)"
$gi = ""
if (Test-Path ".gitignore") {
    $gi = (Get-Content -Raw -Encoding UTF8 ".gitignore")
    $gi = $gi -replace "`r`n", "`n"
}
foreach ($d in $dirs) {
    $pattern = "(?m)^" + [regex]::Escape($d) + "/?$"
    if ($gi -match $pattern) { Pass ".gitignore has rule '$d' (directory itself)" }
    else { Bad ".gitignore is missing rule '$d' (no inline comments after the path!)" }
}

# ---------- 2b. KB .gitignore integrity ----------
Write-Host ""
Write-Host "2b) src/knowledge_base/.gitignore integrity"
$KB_GI = "src/knowledge_base/.gitignore"
if (-not (Test-Path $KB_GI)) {
    Bad "src/knowledge_base/.gitignore is MISSING - the KB data ignore line is gone"
} else {
    $kbLines = @{}
    foreach ($l in (Get-Content -Encoding UTF8 $KB_GI)) { $kbLines["$l".Trim()] = $true }
    $miss = @($kbignore | Where-Object { -not $kbLines.ContainsKey($_) })
    if ($miss.Count -gt 0) {
        Bad "src/knowledge_base/.gitignore is missing required rules: $($miss -join ', ')"
    } else { Pass "src/knowledge_base/.gitignore intact ($($kbignore.Count) required rules present)" }
}

# ---------- 3. ignore rules actually effective ----------
Write-Host ""
Write-Host "3) Ignore rules really in effect (probe paths)"
foreach ($d in $dirs) {
    git check-ignore -q --no-index "$d/probe.py" 2>$null
    if ($LASTEXITCODE -eq 0) { Pass "'$d/probe.py' would be ignored" }
    else { Bad "'$d/probe.py' NOT ignored - files under '$d' can be git-added" }
}

# ---------- 4. tracked files ----------
Write-Host ""
Write-Host "4) Tracked files (git ls-files)"
$tracked = @(git ls-files 2>$null) | Where-Object { $_ }
$hits = @($tracked | Where-Object { Is-Closed $_ })
if ($hits.Count -gt 0) {
    Bad "closed-source paths found in the index ($($hits.Count) item(s)):"
    $hits | Select-Object -First 40 | ForEach-Object { Write-Host "         $_" }
} else { Pass "no closed-source paths tracked" }

# ---------- 5. full history (file names) ----------
Write-Host ""
Write-Host "5) Full commit history file names (incl. deleted files)"
$hist = @(git log --all --pretty=format: --name-only 2>$null) | Where-Object { $_ } | Sort-Object -Unique
$hits = @($hist | Where-Object { Is-Closed $_ })
if ($hits.Count -gt 0) {
    Bad "closed-source paths found in history ($($hits.Count) item(s)):"
    $hits | Select-Object -First 40 | ForEach-Object { Write-Host "         $_" }
} else { Pass "no closed-source paths in history" }

# ---------- 6. sentinels under src/ (HEAD tree only) ----------
Write-Host ""
Write-Host "6) Sentinel markers (HEAD, src/ only)"
git rev-parse --verify HEAD 2>$null *> $null
$haveHead = ($LASTEXITCODE -eq 0)
if ($haveHead) {
    $out = git grep -l -E $SENTINEL_RE HEAD -- src/ 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) {
        Bad "files containing closed-source sentinels:"
        @($out) | ForEach-Object { Write-Host "         $_" }
    } else { Pass "no sentinels under src/ in HEAD" }
} else { WarnP "no commits yet, skipping sentinel scan" }

# ---------- 6b. live-source patterns: HEAD whole tree ----------
Write-Host ""
Write-Host "6b) Live-source / secret markers (HEAD whole tree content scan)"
if ($patterns.Count -eq 0) {
    WarnP "no pattern rules in list, skipping"
} elseif (-not $haveHead) {
    WarnP "no commits yet, skipping"
} else {
    $grepArgs = @("grep", "-l")
    foreach ($p in $patterns) { $grepArgs += @("-e", $p) }
    $grepArgs += @("HEAD", "--", ".", $LIST_EXCLUDE)
    $out = & git @grepArgs 2>$null
    $rc = $LASTEXITCODE
    if ($rc -gt 1) {
        Bad "git grep failed (rc=$rc) - fail-closed"
    } elseif ($out) {
        Bad "HEAD contains live-source / secret markers in:"
        @($out) | ForEach-Object { Write-Host "         $_" }
    } else { Pass "HEAD has no live-source / secret markers" }
}

# ---------- 6c. live-source patterns: full history (git log -G) ----------
Write-Host ""
Write-Host "6c) Live-source / secret markers (full history content scan, git log -G)"
if ($patterns.Count -eq 0) {
    WarnP "no pattern rules in list, skipping"
} else {
    $out = git log --all --pretty=format:%h -G $PAT_RE -- . $LIST_EXCLUDE 2>$null
    $rc = $LASTEXITCODE
    if ($rc -ne 0) {
        Bad "git log -G failed (rc=$rc) - fail-closed"
    } elseif ($out) {
        $commits = @($out | Where-Object { $_ })
        Bad "history introduced live-source / secret markers in $($commits.Count) commit(s):"
        Write-Host "         $(($commits | Select-Object -First 20) -join ' ')"
    } else { Pass "history has no live-source / secret markers" }
}

# ---------- 7. local closed dirs ----------
Write-Host ""
Write-Host "7) Local closed-source dirs (exist-but-ignored = OK)"
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { Pass "'$d' does not exist locally (safest shape)"; continue }
    git check-ignore -q --no-index $d 2>$null
    if ($LASTEXITCODE -eq 0) { Pass "'$d' exists locally and is ignored (never pushed)" }
    else { WarnP "'$d' exists locally but is NOT ignored - git add -A would pick it up" }
}

# ---------- verdict ----------
Write-Host ""
Write-Host "=============================================================="
if ($script:fail -gt 0) {
    Write-Host " RESULT: $($script:fail) failure(s), $($script:warn) warning(s) - do NOT push."
    Write-Host " Fix and re-run before 'git push'."
    Write-Host "=============================================================="
    exit 1
}
Write-Host " RESULT: all checks passed ($($script:warn) warning(s)) - safe to push."
Write-Host " Remember: the pre-push hook will check again, and CI is the last gate."
Write-Host "=============================================================="
exit 0