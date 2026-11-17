param(
    [string]$BinaryDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build/bin'),
    [string]$EvidenceDirectory = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$root = Split-Path $PSScriptRoot -Parent
$binaries = [IO.Path]::GetFullPath($BinaryDirectory)
$fixtures = Get-TestFixtureDirectory $binaries
$state = Join-Path $root 'unused/runtime/conpty-resize'
$report = if ($EvidenceDirectory) { [IO.Path]::GetFullPath($EvidenceDirectory) } else {
    Join-Path $root 'unused/evidence/current/conpty-resize'
}
New-Item -ItemType Directory -Force $state,$report,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$policy = Join-Path $state 'policy.json'
@{filesystem = @{readonlyPaths = @($env:SystemRoot, $binaries, $fixtures); readwritePaths = @($state)}} |
    ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policy

$launcher = Get-PsecLauncher $binaries
$compat = Join-Path $binaries 'msys-sandbox-compat.exe'
$probe = Join-Path $fixtures 'conpty-resize-probe.exe'
foreach ($mode in @('adaptive', 'fixed')) {
    $fixedSize = $mode -eq 'fixed'
    $driverMode = if ($fixedSize) { '--drive-fixed' } else { '--drive' }
    $processArgs = @($driverMode, $launcher, $policy, $compat, '--conpty')
    $processArgs += if ($fixedSize) { @('--conpty-size', '80x24', $probe, '--probe-fixed') } else {
        @($probe, '--probe')
    }
    $info = New-TestProcessInfo $probe $processArgs $state
    $result = Invoke-TestProcess $info 30000
    Save-TestOutput $result $report $mode
    $initial = if ($fixedSize) { '80x24' } else { '96x28' }
    $final = if ($fixedSize) { '80x24' } else { '112x36' }
    if ($result.ExitCode -ne 0 -or !$result.Output.Contains("VIEWPORT-READY=$initial") -or
        !$result.Output.Contains("VIEWPORT-FINAL=$final")) {
        throw "$mode ConPTY resize failed (exit $($result.ExitCode))`n$($result.Output)`n$($result.Error)"
    }
    Write-Output "CONPTY-RESIZE-PASS: $mode $initial -> $final"
}
