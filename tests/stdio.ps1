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

$info = New-TestProcessInfo $launcher @($policy, $compat, '--conpty', $probe, '--descendant') $state
$result = Invoke-TestProcess $info 30000
Save-TestOutput $result $report 'descendant'
if ($result.ExitCode -ne 37 -or !$result.Output.Contains('DESCENDANT-TAIL')) {
    throw "ConPTY lost descendant output or the root exit code, actual exit $($result.ExitCode)"
}
Write-Output 'CONPTY-DESCENDANT-PASS: output after the root exited, root exit=37'
