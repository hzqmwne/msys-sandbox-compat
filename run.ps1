param(
    [string]$GitRoot = 'C:\Program Files\Git',
    [string]$BinaryDirectory = (Join-Path $PSScriptRoot 'build/bin'),
    [string]$Program = '',
    [string[]]$CommandArguments = @('--noprofile', '--norc', '-c', 'echo PSEC-ready; (echo fork-ok); /usr/bin/uname -a'),
    [switch]$Raw,
    [switch]$Trace,
    [switch]$NativeRelay,
    [switch]$NoNativeRelay,
    [string[]]$DisableModule = @(),
    [switch]$ConPty,
    [string]$ConPtyScript = '',
    [string]$TerminalSize,
    [switch]$NoConPty
)
$ErrorActionPreference = 'Stop'
$BinaryDirectory = [IO.Path]::GetFullPath($BinaryDirectory)
if ($NativeRelay -and $NoNativeRelay) { throw '-NoNativeRelay conflicts with -NativeRelay' }
if ($Raw -and ($NativeRelay -or $NoNativeRelay)) { throw 'Relay options require the compatibility launcher' }
if ($Raw -and $DisableModule) { throw '-DisableModule requires the compatibility launcher' }
if ($NoConPty -and ($ConPty -or $ConPtyScript)) { throw '-NoConPty conflicts with -ConPty or -ConPtyScript' }
$defaultProgram = !$Program
if ($defaultProgram) { $Program = Join-Path $GitRoot 'usr\bin\bash.exe' }
if (($ConPty -or $ConPtyScript) -and !$PSBoundParameters.ContainsKey('CommandArguments')) {
    if ($defaultProgram) {
        $CommandArguments = @('--noprofile','--norc','-c',
            'export PATH="/usr/bin:/bin:$PATH"; export TERM=xterm-256color LANG=C.UTF-8; exec /usr/bin/bash --noprofile --norc -i')
    } else { $CommandArguments = @() }
}
$state = Join-Path $PSScriptRoot 'unused\runtime'
New-Item -ItemType Directory -Force $state,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$programName = [IO.Path]::GetFileName($Program)
if ($ConPty -and $programName -in @('powershell.exe','pwsh.exe') -and
    @($CommandArguments | Where-Object { $_ -notin @('-NoProfile','-NoLogo','-NoExit') }).Count -eq 0) {
    $historyDirectory = Join-Path $state 'powershell-history'
    New-Item -ItemType Directory -Force $historyDirectory | Out-Null
    $historyPath = Join-Path $historyDirectory ([IO.Path]::GetFileNameWithoutExtension($Program) + '_history.txt')
    $initialize = "Import-Module PSReadLine -ErrorAction Stop; Set-PSReadLineOption -HistorySavePath '" +
        $historyPath.Replace("'", "''") + "'"
    if ($CommandArguments -notcontains '-NoExit') { $CommandArguments += '-NoExit' }
    $CommandArguments += @('-Command', $initialize)
}
$policy = @{ filesystem = @{
    readonlyPaths = @($env:SystemRoot, $GitRoot, $BinaryDirectory)
    readwritePaths = @($PSScriptRoot)
    deniedPaths = @((Join-Path $PSScriptRoot 'tests\fixtures\denied.txt'))
} }
$policyPath = Join-Path $state ('policy-' + [Guid]::NewGuid().ToString('N') + '.json')
$previousTemp=$env:TEMP; $previousTmp=$env:TMP; $previousHome=$env:HOME
try {
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 4))
    $env:TEMP=Join-Path $state 'tmp'; $env:TMP=$env:TEMP; $env:HOME=Join-Path $state 'home'
    $launchArgs = @("--policy=$policyPath", '--')
    if (!$Raw) {
        $developmentExe = Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'
        if ($ConPtyScript) {
            $launchArgs += $developmentExe
            if ($NativeRelay) { $launchArgs += '--native-relay' }
            if ($NoNativeRelay) { $launchArgs += '--no-native-relay' }
            foreach ($module in $DisableModule) { $launchArgs += @('--disable-module',$module) }
            if ($Trace) { $launchArgs += '--trace' }
            $launchArgs += @('--conpty-script',[IO.Path]::GetFullPath($ConPtyScript))
            if ($TerminalSize) { $launchArgs += @('--conpty-size',$TerminalSize) }
        } else {
            $shim = Join-Path $BinaryDirectory 'msys-sandbox-compat-shim.exe'
            if (!(Test-Path -LiteralPath $shim)) { $shim = $developmentExe }
            $launchArgs += $shim
            if ($NativeRelay) { $launchArgs += '--native-relay=on' }
            if ($NoNativeRelay) { $launchArgs += '--native-relay=off' }
            if ($DisableModule) { $launchArgs += '--disable-modules=' + ($DisableModule -join ',') }
            if ($Trace) { $launchArgs += '--log-level=trace' }
            if ($ConPty) { $launchArgs += '--terminal=conpty' }
            if ($NoConPty) { $launchArgs += '--terminal=inherit' }
            if ($TerminalSize) { $launchArgs += "--conpty-size=$TerminalSize" }
            $launchArgs += '--'
        }
    }
    $launchArgs += $Program
    $launchArgs += $CommandArguments
    $launcher = Join-Path (Split-Path $BinaryDirectory -Parent) 'tools/psec-run.exe'
    if ($PSVersionTable.PSVersion -lt [version]'7.3') {
        # Pass a Win32 command line without the legacy native binder reinterpreting it.
        . (Join-Path $PSScriptRoot 'tools/windows-command-line.ps1')
        $startInfo = [Diagnostics.ProcessStartInfo]::new($launcher)
        $startInfo.UseShellExecute = $false
        $startInfo.WorkingDirectory = $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath
        $startInfo.Arguments = ConvertTo-WindowsCommandLine $launchArgs
        $process = [Diagnostics.Process]::Start($startInfo)
        try {
            $process.WaitForExit()
            $result = $process.ExitCode
        } finally {
            $process.Dispose()
        }
    } else {
        $PSNativeCommandArgumentPassing = 'Standard'
        & $launcher @launchArgs
        $result = $LASTEXITCODE
    }
} finally {
    $env:TEMP=$previousTemp; $env:TMP=$previousTmp; $env:HOME=$previousHome
    Remove-Item -LiteralPath $policyPath -ErrorAction SilentlyContinue
}
exit $result
