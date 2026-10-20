# Shared process setup for the isolation integration suites.
function New-TestProcessInfo([string]$Program, [string[]]$Arguments, [string]$WorkingDirectory) {
    $info = [Diagnostics.ProcessStartInfo]::new($Program)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.WorkingDirectory = $WorkingDirectory
    $info.Environment['TEMP'] = Join-Path $WorkingDirectory 'tmp'
    $info.Environment['TMP'] = $info.Environment['TEMP']
    $info.Environment['HOME'] = Join-Path $WorkingDirectory 'home'
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    return $info
}

function Invoke-TestProcess([Diagnostics.ProcessStartInfo]$Info, [int]$Timeout=60000) {
    $process = [Diagnostics.Process]::Start($Info)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit($Timeout)) { throw "Timeout running $($Info.FileName)" }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $stdout.GetAwaiter().GetResult()
            Error = $stderr.GetAwaiter().GetResult()
        }
    } finally {
        if (!$process.HasExited) { $process.Kill($true) }
        $process.Dispose()
    }
}

function Save-TestOutput($Result, [string]$Directory, [string]$Name) {
    [IO.File]::WriteAllText((Join-Path $Directory "$Name.stdout.txt"), $Result.Output)
    [IO.File]::WriteAllText((Join-Path $Directory "$Name.stderr.txt"), $Result.Error)
}
