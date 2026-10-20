param([int]$Repetitions=5,[string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root=Split-Path $PSScriptRoot -Parent
$state=Join-Path $root 'unused\runtime'
$evidence=Join-Path $root 'unused\evidence\current\verify'
if($EvidenceDirectory){$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)}
New-Item -ItemType Directory -Force $state,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$canary=Join-Path $PSScriptRoot 'denied.txt'
$allowed=Join-Path $PSScriptRoot 'allowed.txt'
[IO.File]::WriteAllText($allowed, "read-ok`n")
$canaryHash=(Get-FileHash -LiteralPath $canary).Hash
$allowedHash=(Get-FileHash -LiteralPath $allowed).Hash
$policy=Join-Path $state 'verify-policy.json'
@{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot,$root);readwritePaths=@($state);deniedPaths=@($canary)}} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policy
$launcher=Join-Path $BinaryDirectory 'psec-run.exe'
$supervisor=Join-Path $BinaryDirectory 'msys-compat.exe'
$results=[System.Collections.Generic.List[object]]::new()
function Invoke-Case([string]$Name,[string]$Program,[string[]]$Arguments,[int]$Expected=0,[switch]$Raw,[string]$Match='') {
    $start=New-TestProcessInfo $launcher @() $state
    $start.ArgumentList.Add($policy)
    if(!$Raw){$start.ArgumentList.Add($supervisor);$start.ArgumentList.Add('--runtime');$start.ArgumentList.Add((Join-Path $GitRoot 'usr\bin\msys-2.0.dll'))}
    $start.ArgumentList.Add($Program)
    foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
    $result=Invoke-TestProcess $start
    $out=$result.Output; $err=$result.Error
    Save-TestOutput $result $evidence $Name
    $diagnosticFailure=(!$Raw -and $err -match '\[exception\]|fatal error|fork: retry|child_copy:|Resource temporarily unavailable|\[image-error\]|\[fatal\]')
    $pass=($result.ExitCode -eq $Expected -and !$diagnosticFailure -and (!$Match -or $out -match $Match))
    if($Raw){$pass=($result.ExitCode -ne 0 -and $err -match 'NtCreateDirectoryObject.*C0000022')}
    $results.Add([pscustomobject]@{Name=$Name;Passed=$pass;ExitCode=$result.ExitCode;Expected=$Expected;DiagnosticFailure=$diagnosticFailure})
    Write-Output "$Name pass=$pass exit=$($result.ExitCode)"
}
$bash=Join-Path $GitRoot 'usr\bin\bash.exe'
$perl=Join-Path $GitRoot 'usr\bin\perl.exe'
Invoke-Case 'raw-baseline' $bash @('--noprofile','--norc','-c','echo unexpected') -Raw
for($i=1;$i -le $Repetitions;$i++) {
    Invoke-Case "fork-$i" $perl @((Join-Path $PSScriptRoot 'fork.pl')) -Match 'ok 15 - fork from a secondary'
    Invoke-Case "shell-$i" $bash @('--noprofile','--norc',(Join-Path $PSScriptRoot 'shell.sh')) -Match 'SHELL-PASS'
}
$allowedPosix=$allowed.Replace('\','/'); $denyPosix=$canary.Replace('\','/')
$boundary='set -eu; export PATH=/usr/bin:/bin; test "$(cat "'+$allowedPosix+'")" = read-ok; if cat "'+$denyPosix+'"; then exit 81; fi; if printf forbidden > "'+$denyPosix+'"; then exit 82; fi; if printf forbidden > "'+$allowedPosix+'"; then exit 83; fi; printf write-ok > allowed-write.txt; test "$(cat allowed-write.txt)" = write-ok; echo BOUNDARY-PASS'
Invoke-Case 'boundary' $bash @('--noprofile','--norc','-c',$boundary) -Match 'BOUNDARY-PASS'
Invoke-Case 'exit-status' $bash @('--noprofile','--norc','-c','exit 37') -Expected 37
Invoke-Case 'native-child' $bash @('--noprofile','--norc','-c','/c/Windows/System32/cmd.exe /d /c "echo NATIVE-CHILD"') -Match 'NATIVE-CHILD'
$unchanged=((Get-FileHash -LiteralPath $canary).Hash -eq $canaryHash -and (Get-FileHash -LiteralPath $allowed).Hash -eq $allowedHash)
$results.Add([pscustomobject]@{Name='boundary-files-unchanged';Passed=$unchanged})
$results | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath (Join-Path $evidence 'verification.json')
if(@($results | Where-Object {!$_.Passed}).Count){throw 'Verification failures: inspect unused/evidence/current/verify/verification.json and corresponding logs'}
Write-Output "ALL-PASS cases=$($results.Count)"
