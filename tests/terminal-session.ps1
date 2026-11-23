param(
    [string]$BinaryDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build/bin'),
    [string]$EvidenceDirectory = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root = Split-Path $PSScriptRoot -Parent
$binaries = [IO.Path]::GetFullPath($BinaryDirectory)
$fixtures = Get-TestFixtureDirectory $binaries
$state = Join-Path $root 'unused/runtime/terminal-session'
$report = if ($EvidenceDirectory) { [IO.Path]::GetFullPath($EvidenceDirectory) } else {
    Join-Path $root 'unused/evidence/current/terminal-session'
}
New-Item -ItemType Directory -Force $state,$report | Out-Null
$policy = Join-Path $state 'policy.json'
Write-TestJson $policy @{filesystem = @{readonlyPaths = @($env:SystemRoot, $binaries, $fixtures);
    readwritePaths = @($state)}}
$probe = Join-Path $fixtures 'conpty-resize-probe.exe'
$launcher = Get-PsecLauncher $binaries
$compat = Join-Path $binaries 'msys-sandbox-compat.exe'
$info = New-TestProcessInfo $probe @('--drive-terminal',$probe,'--outer-state',
    $launcher,$policy,$compat,'--conpty',$probe,'--screen-probe') $state
$result = Invoke-TestProcess $info 30000
Save-TestOutput $result $report 'screen'
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('OUTER-STATE-PASS')) {
    throw "Nested terminal rendering/state test failed ($($result.ExitCode))`n$($result.Output)`n$($result.Error)"
}
Write-Output 'TERMINAL-SCREEN-PASS: standalone Escape, Unicode, cursor movement, native mouse events and restored console state'

$missing = Join-Path $state 'missing-program.exe'
$info = New-TestProcessInfo $probe @('--drive-terminal',$probe,'--outer-failure',
    $launcher,$policy,$compat,'--conpty',$missing) $state
$result = Invoke-TestProcess $info 30000
Save-TestOutput $result $report 'launch-failure'
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('OUTER-STATE-PASS')) {
    throw "Terminal state did not recover from launch failure`n$($result.Output)`n$($result.Error)"
}
Write-Output 'TERMINAL-FAILURE-PASS: outer console state restored after target launch failed'

$info = New-TestProcessInfo $probe @('--drive-close',$launcher,$policy,$compat,'--conpty',
    $probe,'--close-target') $state
$result = Invoke-TestProcess $info 35000
Save-TestOutput $result $report 'outer-close'
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('OUTER-CLOSE-PASS')) {
    throw "Closing the outer ConPTY left test processes running`n$($result.Output)`n$($result.Error)"
}
Write-Output 'TERMINAL-CLOSE-PASS: closing the outer ConPTY releases the launcher, target and descendant'

# Exercise the demo entry with its default Bash arguments and the selected build.
$shell = (Get-Process -Id $PID).Path
# Windows PowerShell changes the shared console mode even for an empty command.
# The native screen/failure tests above check the bridge's mode restoration.
$outerCheck = if ($PSVersionTable.PSEdition -eq 'Desktop') { '--outer-screen' } else { '--outer-state' }
$shellArgs = @($shell,'-NoProfile','-ExecutionPolicy','Bypass')
$info = New-TestProcessInfo $probe (@('--drive-bash',$probe,$outerCheck) + $shellArgs + @(
    '-File',(Join-Path $root 'run.ps1'),'-ConPty','-BinaryDirectory',$binaries)) $state
$result = Invoke-TestProcess $info 35000
Save-TestOutput $result $report 'bash-demo'
if ($result.Output.Contains('Cannot query console owner') -or
    $result.Error.Contains('Cannot query console owner')) {
    throw "Bash could not open its console owner for synchronization. See $report/bash-demo.*.txt"
}
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('DEMO-CTRL-C-PASS') -or
    !$result.Output.Contains('OUTER-STATE-PASS') -or !$result.Output.Contains('EDITED=中文Xb')) {
    throw "Bash demo failed ($($result.ExitCode))`n$($result.Output)`n$($result.Error)"
}
Write-Output 'TERMINAL-BASH-PASS: no idle mouse tracking, demo PATH, arrow-key editing, size, screen and Ctrl+C survival'

$winPS = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$inputScript = Join-Path $state 'powershell51-input.txt'
[IO.File]::WriteAllText($inputScript, '')
$legacyDemo = @'
$bash = 'test "$#" = 3 && test "$1" = ''x" y'' && test -z "$2" && test "$3" = ''C:\with space\'' && echo PS51-DEMO-PASS && exit 37; exit 42'
& $env:MSC_DEMO_SCRIPT -BinaryDirectory $env:MSC_DEMO_BIN -ConPtyScript $env:MSC_DEMO_INPUT -CommandArguments @('--noprofile','--norc','-c',$bash,'bash','x" y','','C:\with space\')
exit $LASTEXITCODE
'@
$encodedDemo = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($legacyDemo))
$info = New-TestProcessInfo $winPS @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encodedDemo) $state
$info.EnvironmentVariables['MSC_DEMO_SCRIPT'] = Join-Path $root 'run.ps1'
$info.EnvironmentVariables['MSC_DEMO_BIN'] = $binaries
$info.EnvironmentVariables['MSC_DEMO_INPUT'] = $inputScript
$result = Invoke-TestProcess $info 35000
Save-TestOutput $result $report 'powershell51-launch'
if ($result.ExitCode -ne 37 -or !$result.Output.Contains('PS51-DEMO-PASS')) {
    throw "Bash demo via Windows PowerShell 5.1 failed ($($result.ExitCode))`n$($result.Output)`n$($result.Error)"
}
$command = @'
Write-Host 'DEMO-PS-READY'
$line = [Console]::ReadLine()
if ($line -cne '中文-é-Ａ') { exit 84 }
[Console]::WriteLine('SCREEN-' + $line)
[Console]::Write("CURSOR-NO`e[2DOK`r`n")
exit 0
'@
# Windows PowerShell 5.1 has no backtick-e escape.
$command = $command.Replace('`e', [string][char]27)
$entry = Join-Path $state 'powershell-demo.ps1'
$rootQuoted = $root.Replace("'", "''")
$programQuoted = $winPS.Replace("'", "''")
$binaryQuoted = $binaries.Replace("'", "''")
$scriptEncoding = [Text.UTF8Encoding]::new($true)
[IO.File]::WriteAllLines($entry, [string[]]@(
    '$command = @''', $command, '''@',
    "& '$rootQuoted/run.ps1' -ConPty -BinaryDirectory '$binaryQuoted' -Program '$programQuoted' -CommandArguments @('-NoProfile','-Command',`$command)"), $scriptEncoding)
$info = New-TestProcessInfo $probe (@('--drive-powershell',$probe,$outerCheck) + $shellArgs + @('-File',$entry)) $state
$result = Invoke-TestProcess $info 35000
Save-TestOutput $result $report 'powershell-demo'
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('OUTER-STATE-PASS')) {
    throw "PowerShell demo failed ($($result.ExitCode))`n$($result.Output)`n$($result.Error)"
}
Write-Output 'TERMINAL-POWERSHELL-PASS: real console Unicode input/output and rendered screen'

# Run the same interactive PSReadLine entry used during manual acceptance.
$entry = Join-Path $state 'readline-demo.ps1'
[IO.File]::WriteAllText($entry,
    "& '$rootQuoted/run.ps1' -ConPty -BinaryDirectory '$binaryQuoted' -Program '$programQuoted' -CommandArguments @('-NoProfile','-NoLogo')", $scriptEncoding)
$info = New-TestProcessInfo $probe (@('--drive-readline',$probe,$outerCheck) + $shellArgs + @('-File',$entry)) $state
$result = Invoke-TestProcess $info 35000
Save-TestOutput $result $report 'readline-demo'
$history = Join-Path $root 'unused/runtime/powershell-history/powershell_history.txt'
$marker = [regex]::Match($result.Output, 'HISTORY-CHECK-\d+').Value
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('OUTER-STATE-PASS') -or
    $result.Output.Contains('ConsoleHost_history.txt') -or $result.Output.Contains('ưm') -or
    !$marker -or !(Test-Path -LiteralPath $history) -or
    ![IO.File]::ReadAllText($history).Contains($marker)) {
    throw "Interactive PSReadLine history failed ($($result.ExitCode))`n$($result.Output)`n$($result.Error)"
}
Write-Output 'TERMINAL-PSREADLINE-PASS: interactive command saved to the demo history and Unicode screen rendered'
