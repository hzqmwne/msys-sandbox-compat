param([string]$GitRoot = 'C:\Program Files\Git',
      [string]$BinaryDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build/bin'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$root = Split-Path $PSScriptRoot -Parent
$state = Join-Path $root 'unused/runtime/shim'
$deployment = Join-Path $state 'single-file'
New-Item -ItemType Directory -Force $state,$deployment,(Join-Path $state 'tmp'),(Join-Path $state 'home') |
    Out-Null
$shim = Join-Path $deployment 'shim.exe'
Copy-Item -LiteralPath (Join-Path $BinaryDirectory 'msys-sandbox-compat-shim.exe') -Destination $shim
if (@(Get-ChildItem -LiteralPath $deployment -Force).Count -ne 1) {
    throw 'The test deployment must contain only shim.exe'
}

foreach ($case in @(@('-h', '--disable-modules'), @('--help', '--disable-modules'), @('--version', '^\d+\.\d+\.\d+'))) {
    $result = Invoke-TestProcess (New-TestProcessInfo $shim @($case[0]) $state)
    if ($result.ExitCode -ne 0 -or $result.Error -or $result.Output -notmatch $case[1]) {
        throw "Expected $($case[0]) on stdout with exit 0"
    }
}
$result = Invoke-TestProcess (New-TestProcessInfo $shim @('--terminal=inherit','cmd.exe') $state)
if ($result.ExitCode -ne 2 -or $result.Output -or $result.Error -notmatch 'expected --') {
    throw 'The public launcher must require the command separator'
}
foreach ($size in '0x24','80x32768','4294967297x24','80x24extra') {
    $result = Invoke-TestProcess (New-TestProcessInfo $shim @("--conpty-size=$size",'--','cmd.exe') $state)
    if ($result.ExitCode -ne 2 -or $result.Output -or $result.Error -notmatch 'expects COLSxROWS') {
        throw "Expected the launcher to reject ConPTY dimensions $size"
    }
}
$info = New-TestProcessInfo $shim @() $state
$info.Arguments = '--disable-modules=ipc,heap-window --conpty-size=80x24 -- cmd /d /c "exit 37"'
$result = Invoke-TestProcess $info
if ($result.ExitCode -ne 37 -or $result.Error -or $result.Output) {
    throw 'The original cmd tail must be forwarded without shim output'
}

$fixtures = Get-TestFixtureDirectory $BinaryDirectory
$psec = Get-PsecLauncher $BinaryDirectory
$policy = Join-Path $state 'policy.json'
$log = Join-Path $state ('trace-' + [guid]::NewGuid().ToString('N') + '.log')
Write-TestJson $policy @{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot,$fixtures);readwritePaths=@($state)}}
$bash = Join-Path $GitRoot 'usr/bin/bash.exe'
$bridge = Join-Path $fixtures 'native-bridge.exe'
$work = 'echo STDOUT-MARKER; echo STDERR-MARKER >&2; (echo FORK-MARKER); exit 37'
foreach ($terminal in 'inherit','conpty') {
    $launchArgs = @("--policy=$policy",'--',$shim,"--terminal=$terminal",'--log-level=trace',
        "--log-file=$log",'--',$bridge,'--relay','--suspended','1',$bash,'--noprofile','--norc','-c',$work)
    $result = Invoke-TestProcess (New-TestProcessInfo $psec $launchArgs $state)
    if ($result.ExitCode -ne 37 -or !$result.Output.Contains('FORK-MARKER') -or
        ($result.Output + $result.Error) -match '\[(launcher|summary|agent)\]') {
        throw ($result | Out-String)
    }
    if ($terminal -eq 'inherit' -and ($result.Output.Contains('STDERR-MARKER') -or
        !$result.Error.Contains('STDERR-MARKER'))) {
        throw 'Target stderr must keep its own stream'
    }
}
$trace = [IO.File]::ReadAllText($log)
if ($trace -notmatch '\[agent\] child modules' -or $trace -notmatch '\[agent\] injected MSYS child' -or
    [regex]::Matches($trace, '\[summary\] exit=37').Count -ne 2 -or
    $trace -match 'trace file unavailable|FORK-MARKER|STDERR-MARKER') {
    throw "Shim diagnostics were not separated from the target streams: $log"
}
Write-Output 'SHIM-PASS: single file, native command tail, raw stdio, relay, fork, ConPTY and file diagnostics'
