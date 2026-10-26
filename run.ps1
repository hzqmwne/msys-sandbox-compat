param(
    [string]$GitRoot = 'C:\Program Files\Git',
    [string]$Program = '',
    [string[]]$CommandArguments = @('--noprofile', '--norc', '-c', 'echo PSEC-ready; (echo fork-ok); /usr/bin/uname -a'),
    [switch]$Raw,
    [switch]$Trace,
    [switch]$NativeRelay,
    [switch]$ConPty,
    [string]$ConPtyScript = '',
    [string]$TerminalSize = '100x30'
)
$ErrorActionPreference = 'Stop'
if ($Raw -and $NativeRelay) { throw '-NativeRelay requires the compatibility launcher' }
if (!$Program) { $Program = Join-Path $GitRoot 'usr\bin\bash.exe' }
if (($ConPty -or $ConPtyScript) -and !$PSBoundParameters.ContainsKey('CommandArguments')) {
    $CommandArguments = @('--noprofile','--norc','-i')
}
$state = Join-Path $PSScriptRoot 'unused\runtime'
New-Item -ItemType Directory -Force $state,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$policy = @{ filesystem = @{
    readonlyPaths = @($env:SystemRoot, $GitRoot)
    readwritePaths = @($PSScriptRoot)
    deniedPaths = @((Join-Path $PSScriptRoot 'tests\fixtures\denied.txt'))
} }
$policyPath = Join-Path $state 'policy.json'
$policy | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policyPath
$previousTemp=$env:TEMP; $previousTmp=$env:TMP; $previousHome=$env:HOME
try {
    $env:TEMP=Join-Path $state 'tmp'; $env:TMP=$env:TEMP; $env:HOME=Join-Path $state 'home'
    $launchArgs=@($policyPath)
    if (!$Raw) {
        $launchArgs += (Join-Path $PSScriptRoot 'build\bin\msys-sandbox-compat.exe')
        if ($NativeRelay) { $launchArgs += '--native-relay' }
        $launchArgs += @('--runtime',(Join-Path $GitRoot 'usr\bin\msys-2.0.dll'))
        if ($Trace) { $launchArgs += '--trace' }
        if ($ConPtyScript) { $launchArgs += @('--conpty-script',[IO.Path]::GetFullPath($ConPtyScript)) }
        elseif ($ConPty) { $launchArgs += '--conpty' }
        if ($ConPty -or $ConPtyScript) { $launchArgs += @('--conpty-size',$TerminalSize) }
    }
    $launchArgs += $Program
    $launchArgs += $CommandArguments
    & (Join-Path $PSScriptRoot 'build\tools\psec-run.exe') @launchArgs
    $result=$LASTEXITCODE
} finally { $env:TEMP=$previousTemp; $env:TMP=$previousTmp; $env:HOME=$previousHome }
exit $result
