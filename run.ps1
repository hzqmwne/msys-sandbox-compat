param(
    [string]$GitRoot = 'C:\Program Files\Git',
    [string]$BinaryDirectory = (Join-Path $PSScriptRoot 'build/bin'),
    [string]$Program = '',
    [string[]]$CommandArguments = @('--noprofile', '--norc', '-c', 'echo PSEC-ready; (echo fork-ok); /usr/bin/uname -a'),
    [switch]$Raw,
    [switch]$Trace,
    [switch]$NativeRelay,
    [string[]]$DisableModule = @(),
    [switch]$ConPty,
    [string]$ConPtyScript = '',
    [string]$TerminalSize,
    [switch]$NoConPty
)
$ErrorActionPreference = 'Stop'
$BinaryDirectory = [IO.Path]::GetFullPath($BinaryDirectory)
if ($Raw -and $NativeRelay) { throw '-NativeRelay requires the compatibility launcher' }
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
    $policy | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policyPath
    $env:TEMP=Join-Path $state 'tmp'; $env:TMP=$env:TEMP; $env:HOME=Join-Path $state 'home'
    $launchArgs=@($policyPath)
    if (!$Raw) {
        $launchArgs += (Join-Path $BinaryDirectory 'msys-sandbox-compat.exe')
        if ($NativeRelay) { $launchArgs += '--native-relay' }
        foreach ($module in $DisableModule) { $launchArgs += @('--disable-module',$module) }
        $launchArgs += @('--runtime',(Join-Path $GitRoot 'usr\bin\msys-2.0.dll'))
        if ($Trace) { $launchArgs += '--trace' }
        if ($ConPtyScript) { $launchArgs += @('--conpty-script',[IO.Path]::GetFullPath($ConPtyScript)) }
        elseif ($ConPty) { $launchArgs += '--conpty' }
        elseif ($NoConPty) { $launchArgs += '--no-conpty' }
        if ($PSBoundParameters.ContainsKey('TerminalSize')) {
            $launchArgs += @('--conpty-size',$TerminalSize)
        }
    }
    $launchArgs += $Program
    $launchArgs += $CommandArguments
    & (Join-Path (Split-Path $BinaryDirectory -Parent) 'tools/psec-run.exe') @launchArgs
    $result=$LASTEXITCODE
} finally {
    $env:TEMP=$previousTemp; $env:TMP=$previousTmp; $env:HOME=$previousHome
    Remove-Item -LiteralPath $policyPath -ErrorAction SilentlyContinue
}
exit $result
