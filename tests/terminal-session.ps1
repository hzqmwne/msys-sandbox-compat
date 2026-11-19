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
@{filesystem = @{readonlyPaths = @($env:SystemRoot, $binaries, $fixtures);
    readwritePaths = @($state)}} | ConvertTo-Json -Depth 4 |
    Set-Content -Encoding utf8NoBOM -LiteralPath $policy
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
Write-Output 'TERMINAL-SCREEN-PASS: rendered Unicode, cursor movement, native mouse events and restored console state'

$missing = Join-Path $state 'missing-program.exe'
$info = New-TestProcessInfo $probe @('--drive-terminal',$probe,'--outer-failure',
    $launcher,$policy,$compat,'--conpty',$missing) $state
$result = Invoke-TestProcess $info 30000
Save-TestOutput $result $report 'launch-failure'
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('OUTER-STATE-PASS')) {
    throw "Terminal state did not recover from launch failure`n$($result.Output)`n$($result.Error)"
}
Write-Output 'TERMINAL-FAILURE-PASS: outer console state restored after target launch failed'

# Exercise the demo entry with its default Bash arguments and the selected build.
$pwsh = (Get-Command pwsh).Source
$info = New-TestProcessInfo $probe @('--drive-bash',$probe,'--outer-state',$pwsh,'-NoProfile',
    '-File',(Join-Path $root 'run.ps1'),'-ConPty','-BinaryDirectory',$binaries) $state
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
Set-Content -LiteralPath $entry -Encoding utf8NoBOM -Value @(
    '$command = @''', $command, '''@',
    "& '$rootQuoted/run.ps1' -ConPty -BinaryDirectory '$binaryQuoted' -Program '$programQuoted' -CommandArguments @('-NoProfile','-Command',`$command)")
$info = New-TestProcessInfo $probe @('--drive-powershell',$probe,'--outer-state',$pwsh,'-NoProfile',
    '-File',$entry) $state
$result = Invoke-TestProcess $info 35000
Save-TestOutput $result $report 'powershell-demo'
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('OUTER-STATE-PASS')) {
    throw "PowerShell demo failed ($($result.ExitCode))`n$($result.Output)`n$($result.Error)"
}
Write-Output 'TERMINAL-POWERSHELL-PASS: real console Unicode input/output, rendered screen and state restoration'

# Run the same interactive PSReadLine entry used during manual acceptance.
$entry = Join-Path $state 'readline-demo.ps1'
Set-Content -LiteralPath $entry -Encoding utf8NoBOM -Value (
    "& '$rootQuoted/run.ps1' -ConPty -BinaryDirectory '$binaryQuoted' -Program '$programQuoted' -CommandArguments @('-NoProfile','-NoLogo')")
$info = New-TestProcessInfo $probe @('--drive-readline',$probe,'--outer-state',$pwsh,'-NoProfile',
    '-File',$entry) $state
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
Write-Output 'TERMINAL-PSREADLINE-PASS: interactive command saved to the demo history, Unicode screen and restored state'
