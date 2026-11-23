. (Join-Path $PSScriptRoot '../tools/windows-command-line.ps1')

function Write-TestJson([string]$Path, $Value, [int]$Depth = 4) {
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Value -Depth $Depth))
}

# Product, fixture and tool outputs share the same CMake build root.
function Get-TestFixtureDirectory([string]$BinaryDirectory) {
    return Join-Path (Split-Path $BinaryDirectory -Parent) 'tests\bin'
}
function Get-PsecLauncher([string]$BinaryDirectory) {
    return Join-Path (Split-Path $BinaryDirectory -Parent) 'tools\psec-run.exe'
}

# Shared process setup for the isolation integration suites.
function New-TestProcessInfo([string]$Program, [string[]]$Arguments, [string]$WorkingDirectory) {
    $info = [Diagnostics.ProcessStartInfo]::new($Program)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.WorkingDirectory = $WorkingDirectory
    $info.StandardOutputEncoding = [Text.Encoding]::UTF8
    $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    $info.EnvironmentVariables['TEMP'] = Join-Path $WorkingDirectory 'tmp'
    $info.EnvironmentVariables['TMP'] = $info.EnvironmentVariables['TEMP']
    $info.EnvironmentVariables['HOME'] = Join-Path $WorkingDirectory 'home'
    $info.Arguments = ConvertTo-WindowsCommandLine $Arguments
    return $info
}

function Stop-TestProcess([Diagnostics.Process]$Process) {
    if ($Process.HasExited) { return }
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $taskkill = Join-Path $env:SystemRoot 'System32/taskkill.exe'
        $ErrorActionPreference = 'Continue'
        & $taskkill /PID $Process.Id /T /F 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -and !$Process.HasExited) { $Process.Kill() }
    } else {
        $Process.Kill($true)
    }
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
        Stop-TestProcess $process
        $process.Dispose()
    }
}

function Save-TestOutput($Result, [string]$Directory, [string]$Name) {
    [IO.File]::WriteAllText((Join-Path $Directory "$Name.stdout.txt"), $Result.Output)
    [IO.File]::WriteAllText((Join-Path $Directory "$Name.stderr.txt"), $Result.Error)
}

# This stages only test files; the test runner establishes their initial ACLs.
# Production launchers never use this fixture setup.
function Initialize-RestrictedTestFiles([string]$BinaryDirectory, [string]$WorkingDirectory) {
    $readonly = Join-Path $WorkingDirectory 'readonly'
    New-Item -ItemType Directory -Force $readonly | Out-Null
    [IO.File]::WriteAllText((Join-Path $WorkingDirectory '.restricted-fixture'),'test-only')
    foreach ($name in @('msys-sandbox-compat.exe','msys-sandbox-compat.dll')) {
        Copy-Item -LiteralPath (Join-Path $BinaryDirectory $name) -Destination $readonly
    }
    $fixtures = Get-TestFixtureDirectory $BinaryDirectory
    foreach ($name in @('native-bridge.exe','restricted-run.exe')) {
        Copy-Item -LiteralPath (Join-Path $fixtures $name) -Destination $readonly
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures\fork.pl') -Destination $readonly
    return $readonly
}
