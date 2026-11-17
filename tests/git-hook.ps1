param(
    [string]$GitRoot = 'C:\Program Files\Git',
    [string]$BinaryDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build/bin'),
    [ValidateSet('Psec','WriteRestricted','FullRestricted')][string]$Environment = 'Psec',
    [string]$EvidenceDirectory = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$root = Split-Path $PSScriptRoot -Parent
$binaries = [IO.Path]::GetFullPath($BinaryDirectory)
$suite = 'git-hook-' + $Environment.ToLowerInvariant()
$state = Join-Path $root ('unused/runtime/' + $suite + '-' + [guid]::NewGuid().ToString('N'))
$repository = Join-Path $state 'repository with spaces'
$report = if ($EvidenceDirectory) { [IO.Path]::GetFullPath($EvidenceDirectory) } else {
    Join-Path $root "unused/evidence/current/$suite"
}
New-Item -ItemType Directory -Force $report,$state | Out-Null
$git = Join-Path $GitRoot 'mingw64/bin/git.exe'
$runtime = Join-Path $GitRoot 'usr/bin/msys-2.0.dll'
$denied = Join-Path $state 'denied.txt'
$policyProbe = ''
if ($Environment -eq 'Psec') {
    $policy = Join-Path $state 'policy.json'
    [IO.File]::WriteAllText($denied, 'protected')
    @{filesystem = @{readonlyPaths = @($env:SystemRoot, $GitRoot, $binaries);
        readwritePaths = @($state); deniedPaths = @($denied)}} |
        ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policy
    $launcher = Get-PsecLauncher $binaries
    $prefix = @($policy)
    $compat = Join-Path $binaries 'msys-sandbox-compat.exe'
    $hooks = Join-Path $state 'hooks'
    New-Item -ItemType Directory $hooks,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
} else {
    $staged = Initialize-RestrictedTestFiles $binaries $state
    $launcher = Join-Path (Get-TestFixtureDirectory $binaries) 'restricted-run.exe'
    $policyProbe = (Join-Path $staged 'restricted-run.exe').Replace('\','/')
    $mode = if ($Environment -eq 'WriteRestricted') { 'write' } else { 'full' }
    $prefix = @($mode, $state)
    $compat = Join-Path $staged 'msys-sandbox-compat.exe'
    $hooks = $staged
}
$gitConfig = Join-Path $hooks 'empty.gitconfig'
[IO.File]::WriteAllText($gitConfig, '')
$configuration = @{
    TEMP = (Join-Path $state 'tmp'); TMP = (Join-Path $state 'tmp'); HOME = (Join-Path $state 'home')
    GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = $gitConfig; GIT_CONFIG_COUNT = '0'
    GIT_DIR = ''; GIT_WORK_TREE = ''; GIT_INDEX_FILE = ''; GIT_COMMON_DIR = ''
    LC_ALL = 'C'; HOOK_DENIED = $denied.Replace('\','/'); HOOK_POLICY_PROBE = $policyProbe
    HOOK_POLICY_ROOT = $state.Replace('\','/')
}

function Invoke-FixtureGit([string]$Label, [string[]]$GitArguments, [switch]$Isolated,
    [string[]]$Setup = @(), [switch]$AllowFailure) {
    $GitArguments = @('-C', $repository) + $GitArguments
    if ($Isolated) {
        # PSEC initializes the environment, so configure the test Git inside it.
        $entry = Join-Path $hooks "$Label.cmd"
        $lines = @('@echo off', 'setlocal DisableDelayedExpansion')
        foreach ($item in $configuration.GetEnumerator()) {
            $lines += ('set "{0}={1}"' -f $item.Key, $item.Value.Replace('%', '%%'))
        }
        $lines += $Setup
        $command = @($compat, '--native-relay', '--runtime', $runtime, $git) + $GitArguments
        $lines += ($command.ForEach({ '"' + $_.Replace('%', '%%') + '"' }) -join ' ')
        $lines += 'exit /b %errorlevel%'
        Set-Content -LiteralPath $entry -Value $lines -Encoding oem
        $cmd = Join-Path $env:SystemRoot 'System32/cmd.exe'
        $info = New-TestProcessInfo $launcher ($prefix + @($cmd, '/d', '/c', $entry)) $state
    } else {
        $info = New-TestProcessInfo $git $GitArguments $repository
        foreach ($item in $configuration.GetEnumerator()) {
            if ($item.Value) { $info.Environment[$item.Key] = $item.Value }
            else { $null = $info.Environment.Remove($item.Key) }
        }
    }
    $result = Invoke-TestProcess $info 30000
    Save-TestOutput $result $report $Label
    if ($result.ExitCode -ne 0 -and !$AllowFailure) {
        throw "$Label failed ($($result.ExitCode))`n$($result.Output)`n$($result.Error)"
    }
    return $result
}

$hook = @'
#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
export MSYS2_ARG_CONV_EXCL='*'
if [ -n "${HOOK_POLICY_PROBE:-}" ]; then
    "$HOOK_POLICY_PROBE" probe "$HOOK_POLICY_ROOT"
fi
if cat "$HOOK_DENIED"; then
    echo 'HOOK-ERROR: protected file was readable' >&2
    exit 81
fi
if (printf forbidden > "$HOOK_DENIED"); then
    echo 'HOOK-ERROR: protected file was writable' >&2
    exit 82
fi
first=$(printf '%s\n' beta alpha | sort | head -n 1)
number=$(perl -e 'print 6 * 7')
test "$first:$number" = alpha:42
echo 'HOOK-PASS: alpha:42; policy intact'
if [ -f reject-commit ]; then
    echo 'HOOK-REJECT: fixture rejected the commit' >&2
    exit 19
fi
'@
[IO.File]::WriteAllText((Join-Path $hooks 'pre-commit'), ($hook -replace "`r`n", "`n") + "`n")
$repositoryPath = $repository.Replace('%','%%')
$tracked = "$repositoryPath\payload.txt"
Invoke-FixtureGit setup @('--version') -Isolated `
    -Setup ('mkdir "{0}" || exit /b 1' -f $repositoryPath) | Out-Null
Invoke-FixtureGit init @('init', '--template=', '--initial-branch=main') | Out-Null
$commit = @('-c', 'user.name=MSYS compatibility test', '-c', 'user.email=msys-test@example.invalid',
    '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', '-c', ('core.hooksPath=' + $hooks.Replace('\','/')),
    'commit', '-m')
Invoke-FixtureGit add @('-c', 'core.autocrlf=false', 'add', '--', 'payload.txt') -Isolated `
    -Setup ('>"{0}" echo accepted || exit /b 1' -f $tracked) | Out-Null
$accepted = Invoke-FixtureGit accepted ($commit + 'accepted') -Isolated
$head = (Invoke-FixtureGit head @('rev-parse', 'HEAD')).Output.Trim()
$content = (Invoke-FixtureGit committed @('show', 'HEAD:payload.txt')).Output.Trim()
$count = (Invoke-FixtureGit count @('rev-list', '--count', 'HEAD')).Output.Trim()
if (($accepted.Output + $accepted.Error) -notmatch 'HOOK-PASS: alpha:42; policy intact' -or
    $content -cne 'accepted' -or $count -ne '1') {
    throw 'Accepted hook or resulting commit did not match the fixture'
}

Invoke-FixtureGit add-rejected @('-c', 'core.autocrlf=false', 'add', '--', 'payload.txt') -Isolated `
    -Setup @('type nul >"{0}\reject-commit" || exit /b 1' -f $repositoryPath;
        '>"{0}" echo staged but rejected || exit /b 1' -f $tracked) | Out-Null
$rejected = Invoke-FixtureGit rejected ($commit + 'must not commit') -Isolated -AllowFailure
$after = (Invoke-FixtureGit head-after-rejection @('rev-parse', 'HEAD')).Output.Trim()
$stagedContent = (Invoke-FixtureGit staged-after-rejection @('show', ':payload.txt')).Output.Trim()
$diagnostic = $rejected.Output + $rejected.Error
if ($rejected.ExitCode -eq 0 -or $after -ne $head -or $stagedContent -cne 'staged but rejected' -or
    $diagnostic -notmatch 'HOOK-PASS: alpha:42; policy intact' -or $diagnostic -notmatch 'HOOK-REJECT:') {
    throw "Rejected hook or repository state did not match the fixture`n$diagnostic"
}
Write-Output "GIT-HOOK-PASS: $Environment, real pre-commit workload, intact file policy, accepted and rejected commits"
