<#
.SYNOPSIS
  Generates ../project_configure/gen_ver.h with Git metadata.
#>

# Determine paths
$currentDir = Get-Location
$projectDir = (Resolve-Path "$currentDir\..").Path
$outPath    = Join-Path $projectDir 'project_configure\gen_ver.h'

# Remove old file if it exists
if (Test-Path $outPath) {
    Remove-Item $outPath -Force
}

# Helper to call Git and fall back to "unknown"
function Get-GitValue {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true, Mandatory)]
        [string[]] $GitArgs
    )
    # Run git and capture output
    $output = & git @GitArgs 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($output)) {
        return 'unknown'
    }
    return $output.Trim()
}

# Grab Git info
$commit = Get-GitValue rev-parse --short HEAD
$branch = Get-GitValue rev-parse --abbrev-ref HEAD
$author = Get-GitValue config --get user.name
$email  = Get-GitValue config --get user.email

# ISO-8601 timestamp with offset
$date = Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz'

# Dirty/clean check
try {
    $status = & git status --porcelain 2>$null
    $exit   = $LASTEXITCODE
} catch {
    $exit = 1
}

if ($exit -ne 0) {
    Write-Host 'Not a git repository'
    $dirty = 'unknown'
    exit 1
} elseif ($status) {
    $dirty = 'Dirty'
} else {
    $dirty = 'Clean'
}

# Project name = folder name
$projName = Split-Path $projectDir -Leaf

# Build header lines
$headerLines = @(
    '/* auto-generated; do not edit */',
    '#ifndef GEN_VER_H__',
    '#define GEN_VER_H__',
    '',
    "#define PROJECT_GIT_COMMIT_HASH   `"$commit`"",
    "#define PROJECT_GIT_BRANCH        `"$branch`"",
    "#define PROJECT_GIT_AUTHOR_NAME   `"$author`"",
    "#define PROJECT_GIT_AUTHOR_EMAIL  `"$email`"",
    "#define PROJECT_BUILD_DATE        `"$date`"",
    "#define PROJECT_GIT_DIRTY_FLAG    `"$dirty`"",
    "#define PROJECT_NAME              `"$projName`"",
    '',
    '#endif /* GEN_VER_H__ */'
)

# Write out with UTF-8 encoding
$headerLines | Set-Content -Path $outPath -Encoding UTF8
