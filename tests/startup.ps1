param([string]$GitRoot = 'C:\Program Files\Git',
      [string]$BinaryDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root = Split-Path $PSScriptRoot -Parent
$state = Join-Path $root 'unused\runtime\ordinary-startup'
$evidence = Join-Path $root 'unused\evidence\current\ordinary-startup'
New-Item -ItemType Directory -Force $state,$evidence,(Join-Path $state tmp),(Join-Path $state home) |
    Out-Null
$compat = Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'
$bridge = Join-Path (Get-TestFixtureDirectory $BinaryDirectory) 'native-bridge.exe'
$bash = Join-Path $GitRoot 'usr\bin\bash.exe'
$work = 'set -eu; test "$(/usr/bin/uname -s >/dev/null; printf fork-ok)" = fork-ok; echo ORDINARY-STARTUP-PASS; exit 37'
$arguments = @('--no-conpty','--native-relay',$bridge,'--relay','--suspended','2',
    $bash,'--noprofile','--norc','-c',$work)
$result = Invoke-TestProcess (New-TestProcessInfo $compat $arguments $state)
Save-TestOutput $result $evidence 'suspended-relay'
$suspended = [regex]::Matches($result.Error, 'suspended-preserved=1').Count
if ($result.ExitCode -ne 37 -or $suspended -ne 3 -or
    !$result.Output.Contains('ORDINARY-STARTUP-PASS')) {
    throw "Ordinary startup exit=$($result.ExitCode), suspended children=$suspended"
}
