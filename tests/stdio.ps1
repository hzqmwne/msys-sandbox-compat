param(
    [string]$BinaryDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build/bin'),
    [string]$EvidenceDirectory = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$root = Split-Path $PSScriptRoot -Parent
$binaries = [IO.Path]::GetFullPath($BinaryDirectory)
$fixtures = Get-TestFixtureDirectory $binaries
$state = Join-Path $root 'unused/runtime/stdio'
$report = if ($EvidenceDirectory) { [IO.Path]::GetFullPath($EvidenceDirectory) } else {
    Join-Path $root 'unused/evidence/current/stdio'
}
New-Item -ItemType Directory -Force $state,$report,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$policy = Join-Path $state 'policy.json'
@{filesystem = @{readonlyPaths = @($env:SystemRoot, $binaries, $fixtures); readwritePaths = @($state)}} |
    ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policy

$launcher = Get-PsecLauncher $binaries
$compat = Join-Path $binaries 'msys-sandbox-compat.exe'
$probe = Join-Path $fixtures 'stdio-probe.exe'
$info = New-TestProcessInfo $launcher @($policy, $compat, $probe, '--echo') $state
$info.RedirectStandardInput = $true
$info.StandardInputEncoding = [Text.UTF8Encoding]::new($false)

# Repeat every byte value, including NUL and Ctrl+Z, beyond pipe capacity.
[byte[]]$pattern = 0..255
$inputBytes = [byte[]]::new(1MB)
for ($offset = 0; $offset -lt $inputBytes.Length; $offset += $pattern.Length) {
    [Array]::Copy($pattern, 0, $inputBytes, $offset, $pattern.Length)
}
$inputHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($inputBytes))
$process = [Diagnostics.Process]::Start($info)
$output = [IO.MemoryStream]::new()
try {
    $stdout = $process.StandardOutput.BaseStream.CopyToAsync($output)
    $stderr = $process.StandardError.ReadToEndAsync()
    $write = $process.StandardInput.BaseStream.WriteAsync($inputBytes, 0, $inputBytes.Length)
    if (!$write.Wait(30000)) { throw 'Timed out writing binary input' }
    $process.StandardInput.Close()
    if (!$process.WaitForExit(30000)) { throw 'Process did not exit after stdin EOF' }
    if (![Threading.Tasks.Task]::WaitAll(@($stdout, $stderr), 30000)) {
        throw 'Timed out reading redirected streams'
    }
    $errorText = $stderr.GetAwaiter().GetResult()
    $outputHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($output.ToArray()))
    [IO.File]::WriteAllText((Join-Path $report 'binary.stderr.txt'), $errorText)
    [IO.File]::WriteAllText((Join-Path $report 'binary-hashes.txt'), "stdin=$inputHash`nstdout=$outputHash`n")
    if ($process.ExitCode -ne 37 -or $outputHash -ne $inputHash -or $errorText -notmatch '(?m)^STDIO-EOF\r?$') {
        throw "Binary stdio or EOF mismatch, root exit $($process.ExitCode), stdout length $($output.Length)"
    }
} finally {
    if (!$process.HasExited) { $process.Kill($true) }
    $process.Dispose()
    $output.Dispose()
}
Write-Output "STDIO-PASS: $($inputBytes.Length) bytes, stderr kept separate, stdin EOF, exit=37"

$info = New-TestProcessInfo $launcher @($policy, $compat, $probe, '--pipe-close') $state
$process = [Diagnostics.Process]::Start($info)
try {
    $stderr = $process.StandardError.ReadToEndAsync()
    $ready = $process.StandardOutput.ReadLineAsync()
    if (!$ready.Wait(10000) -or $ready.GetAwaiter().GetResult() -ne 'PIPE-READY') {
        throw 'Producer did not report readiness'
    }
    $process.StandardOutput.Close()
    if (!$process.WaitForExit(10000) -or !$stderr.Wait(10000)) {
        throw 'Process tree did not exit after the downstream reader closed'
    }
    $errorText = $stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $report 'pipe-close.stderr.txt'), $errorText)
    if ($process.ExitCode -ne 37 -or $errorText -notmatch '(?m)^PIPE-CLOSED\r?$') {
        throw "Broken-pipe behavior mismatch, exit $($process.ExitCode)`n$errorText"
    }
} finally {
    if (!$process.HasExited) { $process.Kill($true) }
    $process.Dispose()
}
Write-Output 'STDIO-PIPE-CLOSE-PASS: producer saw ERROR_BROKEN_PIPE and returned exit=37'

$info = New-TestProcessInfo $launcher @($policy, $compat, '--conpty', $probe, '--conpty-burst') $state
$info.RedirectStandardInput = $true
foreach ($sink in 'drain', 'close') {
    $process = [Diagnostics.Process]::Start($info)
    try {
        $stderr = $process.StandardError.ReadToEndAsync()
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $ready = $process.StandardOutput.ReadLineAsync()
            $remaining = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (!$ready.Wait($remaining) -or $null -eq ($line = $ready.GetAwaiter().GetResult())) {
                throw 'ConPTY producer did not report readiness'
            }
        } until ($line.Contains('CONPTY-PIPE-READY'))
        if ($sink -eq 'close') {
            $process.StandardOutput.Close()
        } else {
            $stdout = $process.StandardOutput.ReadToEndAsync()
        }
        $process.StandardInput.BaseStream.WriteByte(65)
        $process.StandardInput.Close()
        if (!$process.WaitForExit(10000) -or !$stderr.Wait(5000)) {
            throw "ConPTY producer did not exit with downstream set to $sink"
        }
        $errorText = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $report "conpty-output-$sink.stderr.txt"), $errorText)
        if ($sink -eq 'close') {
            if ($process.ExitCode -ne 1 -or !$errorText.Contains('[fatal] forward ConPTY output')) {
                throw "Expected ConPTY output failure (exit $($process.ExitCode))`n$errorText"
            }
        } elseif ($process.ExitCode -ne 37 -or !$stdout.Wait(5000) -or
                  !$stdout.GetAwaiter().GetResult().Contains('CONPTY-BURST-COMPLETE')) {
            throw "ConPTY output drain control failed (exit $($process.ExitCode))`n$errorText"
        }
    } finally {
        if (!$process.HasExited) { $process.Kill($true) }
        $process.Dispose()
    }
}
Write-Output 'CONPTY-PIPE-CLOSE-PASS: full drain preserves target exit, closed downstream ends the session'

$inputScript = Join-Path $state 'conpty-input.txt'
[IO.File]::WriteAllText($inputScript, 'A')
$info = New-TestProcessInfo $launcher @($policy, $compat, '--conpty-script', $inputScript,
    $probe, '--conpty-read-one') $state
$result = Invoke-TestProcess $info 30000
Save-TestOutput $result $report 'conpty-script'
if ($result.ExitCode -ne 37 -or !$result.Output.Contains('CONPTY-INPUT-COMPLETE')) {
    throw "ConPTY script input did not let the target finish (exit $($result.ExitCode))`n$($result.Error)"
}
Write-Output 'CONPTY-SCRIPT-PASS: target consumes finite input and returns its exit code'

$outer = Join-Path $fixtures 'conpty-resize-probe.exe'
$cmd = Join-Path $env:SystemRoot 'System32/cmd.exe'
$entry = Join-Path $state 'mixed-stdin.cmd'
$command = (@($launcher,$policy,$compat,$probe,'--mixed-stdin').ForEach({ '"' + $_.Replace('%','%%') + '"' }) -join ' ')
Set-Content -LiteralPath $entry -Encoding oem -Value @('@echo off', 'setlocal DisableDelayedExpansion',
    ('{0} <"{1}"' -f $command,$inputScript.Replace('%','%%')), 'exit /b %errorlevel%')
$info = New-TestProcessInfo $outer @('--drive-stdio',$cmd,'/d','/c',$entry) $state
$result = Invoke-TestProcess $info 30000
Save-TestOutput $result $report 'mixed-stdin'
if ($result.ExitCode -ne 37 -or !$result.Output.Contains('STDIO-CONSOLE')) {
    throw "Auto mode did not preserve redirected stdin and its EOF (exit $($result.ExitCode))`n$($result.Output)"
}
Write-Output 'STDIO-MIXED-PASS: stdin file reached EOF, stdout and stderr stayed attached to the console'

$expected = [Text.Encoding]::Latin1.GetString([byte[]](83,84,68,73,79,0,255,13,10))
foreach ($stream in 'stdout', 'stderr') {
    $entry = Join-Path $state "mixed-$stream.cmd"
    $destination = Join-Path $state "mixed-$stream.data.bin"
    $fd = if ($stream -eq 'stdout') { 1 } else { 2 }
    $command = (@($launcher,$policy,$compat,$probe,"--mixed-$stream").ForEach({ '"' + $_.Replace('%','%%') + '"' }) -join ' ')
    Set-Content -LiteralPath $entry -Encoding oem -Value @('@echo off', 'setlocal DisableDelayedExpansion',
        ('{0} {1}>"{2}"' -f $command,$fd,$destination.Replace('%','%%')), 'exit /b %errorlevel%')
    $info = New-TestProcessInfo $outer @('--drive-stdio',$cmd,'/d','/c',$entry) $state
    $result = Invoke-TestProcess $info 30000
    Save-TestOutput $result $report "mixed-$stream"
    Copy-Item -LiteralPath $destination -Destination $report
    $bytes = [Text.Encoding]::Latin1.GetString([IO.File]::ReadAllBytes($destination))
    if ($result.ExitCode -ne 37 -or !$result.Output.Contains('STDIO-CONSOLE') -or
        !$bytes.Contains($expected) -or $bytes.Contains('STDIO-CONSOLE') -or
        ($stream -eq 'stdout' -and $bytes -cne $expected)) {
        throw "Mixed $stream did not preserve the selected file and the remaining console streams (exit $($result.ExitCode))"
    }
    Write-Output "STDIO-MIXED-PASS: $stream file with binary bytes, other streams kept attached to the console"
}

$info = New-TestProcessInfo $launcher @($policy, $compat, '--conpty', $probe, '--descendant') $state
$result = Invoke-TestProcess $info 30000
Save-TestOutput $result $report 'descendant'
if ($result.ExitCode -ne 37 -or !$result.Output.Contains('DESCENDANT-TAIL')) {
    throw "ConPTY lost descendant output or the root exit code, actual exit $($result.ExitCode)"
}
Write-Output 'CONPTY-DESCENDANT-PASS: output after the root exited, root exit=37'
