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
$arguments = @('--no-conpty',$bridge,'--relay','--suspended','2',
    $bash,'--noprofile','--norc','-c',$work)
$result = Invoke-TestProcess (New-TestProcessInfo $compat $arguments $state)
Save-TestOutput $result $evidence 'suspended-relay'
$suspended = [regex]::Matches($result.Error, 'suspended-preserved=1').Count
if ($result.ExitCode -ne 37 -or $suspended -ne 3 -or
    !$result.Output.Contains('ORDINARY-STARTUP-PASS')) {
    throw "Ordinary startup exit=$($result.ExitCode), suspended children=$suspended"
}

$wow64 = Join-Path $env:SystemRoot 'SysWOW64\cmd.exe'
if (Test-Path -LiteralPath $wow64) {
    $client = Join-Path (Get-TestFixtureDirectory $BinaryDirectory) 'import-name\import-name-client.exe'
    $outer = 'relay-x86-root.cmd'
    $inner = 'relay-x86-child.cmd'
    @('@echo off', 'echo RELAY-%PROCESSOR_ARCHITECTURE%',
        ('"{0}" --relay --suspended 0 "{1}" /d /c {2}' -f $bridge,$wow64,$inner),
        'exit /b %errorlevel%') |
        Set-Content -LiteralPath (Join-Path $state $outer) -Encoding oem
    @('@echo off', 'echo RELAY-%PROCESSOR_ARCHITECTURE%', ('"{0}" 060' -f $client),
        'exit /b %errorlevel%') |
        Set-Content -LiteralPath (Join-Path $state $inner) -Encoding oem
    $result = Invoke-TestProcess (New-TestProcessInfo $compat @('--no-conpty',$wow64,'/d','/c',$outer) $state)
    Save-TestOutput $result $evidence 'wow64-relay'
    if ($result.ExitCode -ne 0 -or [regex]::Matches($result.Output, 'RELAY-x86').Count -ne 2 -or
        !$result.Output.Contains('hooks=060') -or !$result.Error.Contains('suspended-preserved=1')) {
        throw "Mixed architecture startup exit=$($result.ExitCode)"
    }
}

# An ordinary relay process may explicitly create a child with a restricted token.
$transition = Join-Path $state 'restricted-child'
$staged = Initialize-RestrictedTestFiles $BinaryDirectory $transition
$runner = Join-Path (Get-TestFixtureDirectory $BinaryDirectory) 'restricted-run.exe'
$target = Join-Path $staged 'restricted-run.exe'
$arguments = @('--no-conpty','--trace',$runner,'full',$transition,$target,'probe',$transition)
$result = Invoke-TestProcess (New-TestProcessInfo $compat $arguments $state)
Save-TestOutput $result $evidence 'restricted-child-relay'
if ($result.ExitCode -ne 0 -or !$result.Output.Contains('RESTRICTED-TOKEN-AND-ACL-PASS') -or
    !$result.Error.Contains('injected native relay')) {
    throw "Restricted child relay exit=$($result.ExitCode): $($result.Error)"
}
