param([string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root = Split-Path $PSScriptRoot -Parent
$state = Join-Path $root 'unused\runtime\process-chain'
$evidence = if ($EvidenceDirectory) { [IO.Path]::GetFullPath($EvidenceDirectory) }
            else { Join-Path $root 'unused\evidence\current\process-chain' }
New-Item -ItemType Directory -Force $state,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$policy = Join-Path $state 'policy.json'
$canary = Join-Path $PSScriptRoot 'denied.txt'
@{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot,$root);readwritePaths=@($state);deniedPaths=@($canary)}} |
    ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $policy -Encoding utf8NoBOM
$launcher = Join-Path $BinaryDirectory 'psec-run.exe'
$compat = Join-Path $BinaryDirectory 'msys-compat.exe'
$bridge = Join-Path $BinaryDirectory 'native-bridge.exe'
$bash = Join-Path $GitRoot 'usr\bin\bash.exe'
$runtime = Join-Path $GitRoot 'usr\bin\msys-2.0.dll'
function Shell-Command([object[]]$Arguments) {
    return (($Arguments | ForEach-Object { "'" + ([string]$_).Replace("'","'\''") + "'" }) -join ' ')
}
$fork = (Join-Path $PSScriptRoot 'fork.pl').Replace('\','/')
$deny = $canary.Replace('\','/')
$payload = "set -eu; export PATH=/usr/bin:/bin; perl '$fork' 10; " +
    'test "$(printf fork-command)" = fork-command; test "$(printf ''b\na\n'' | sort | head -1)" = a; ' +
    "if cat '$deny'; then exit 81; fi; if printf forbidden > '$deny'; then exit 82; fi; " +
    'printf permitted > chain-write.txt; test "$(cat chain-write.txt)" = permitted; echo CHAIN-WORKLOAD-PASS; exit 37'
$results = [Collections.Generic.List[object]]::new()
foreach ($depth in @(0,2)) {
    $inner = Shell-Command (@($bridge.Replace('\','/'),$depth,$compat.Replace('\','/'),
        '--runtime',$runtime.Replace('\','/'),$bash.Replace('\','/'),'--noprofile','--norc','-c',$payload))
    $outer = 'export MSYS2_ARG_CONV_EXCL="*"; ' + $inner
    # The first native bridge records the original runner ACL, before MSYS has run.
    $arguments = @($policy,$bridge,0,$compat,'--runtime',$runtime,$bash,'--noprofile','--norc','-c',$outer)
    $info = New-TestProcessInfo $launcher $arguments $state
    $result = Invoke-TestProcess $info 60000
    $name = "native-depth-$($depth+1)"
    Save-TestOutput $result $evidence $name
    $acls = @([regex]::Matches($result.Error,'\[bridge\] clean=1 depth=\d+ default=([^\r\n]+)') |
        ForEach-Object { $_.Groups[1].Value })
    $passed = $result.ExitCode -eq 37 -and $result.Output.Contains('CHAIN-WORKLOAD-PASS') -and
        $result.Output.Contains('fork from a secondary POSIX thread works') -and $result.Output -notmatch '(?m)^not ok' -and
        $acls.Count -eq ($depth+2) -and @($acls | Select-Object -Unique).Count -eq 1 -and
        $result.Error -notmatch 'fatal error|fork: retry|child_copy:|\[fatal\]'
    $results.Add([pscustomobject]@{Name=$name;Passed=$passed;ExitCode=$result.ExitCode;NativeBridges=$acls.Count})
    Write-Output "$name pass=$passed exit=$($result.ExitCode) bridges=$($acls.Count)"
}
$results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'results.json') -Encoding utf8NoBOM
if (@($results | Where-Object {!$_.Passed}).Count) { throw 'Real MSYS process-chain workload failed' }
Write-Output 'PROCESS-CHAIN-ALL-PASS'
