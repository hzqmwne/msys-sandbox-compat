param([ValidateRange(1,1000)][int]$Repetitions=1,[string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root=Split-Path $PSScriptRoot -Parent
$state=Join-Path $root 'unused\runtime'
$evidence=Join-Path $root 'unused\evidence\current\verify'
if($EvidenceDirectory){$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)}
New-Item -ItemType Directory -Force $state,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$canary=Join-Path $PSScriptRoot 'fixtures\denied.txt'
$allowed=Join-Path $PSScriptRoot 'fixtures\allowed.txt'
$canaryHash=(Get-FileHash -LiteralPath $canary).Hash
$allowedHash=(Get-FileHash -LiteralPath $allowed).Hash
$policy=Join-Path $state 'verify-policy.json'
Write-TestJson $policy @{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot,$root);readwritePaths=@($state);deniedPaths=@($canary)}}
$launcher=Get-PsecLauncher $BinaryDirectory
$supervisor=Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'
$results=[System.Collections.Generic.List[object]]::new()
function Invoke-Case([string]$Name,[string]$Program,[string[]]$Arguments,[int]$Expected=0,
                     [string]$Match='',[switch]$CheckHeapHandoff) {
    $launchArgs=@("--policy=$policy",'--',$supervisor)
    if($CheckHeapHandoff){$launchArgs+='--trace'}
    $launchArgs+=@('--runtime',(Join-Path $GitRoot 'usr\bin\msys-2.0.dll'),$Program) + $Arguments
    $start=New-TestProcessInfo $launcher $launchArgs $state
    $result=Invoke-TestProcess $start
    $out=$result.Output; $err=$result.Error
    Save-TestOutput $result $evidence $Name
    $diagnosticFailure=$err -match '\[exception\]|fatal error|fork: retry|child_copy:|Resource temporarily unavailable|\[image-error\]|\[fatal\]'
    $pass=($result.ExitCode -eq $Expected -and !$diagnosticFailure -and (!$Match -or $out -match $Match))
    if($CheckHeapHandoff){
        $launcherLine=$err.IndexOf('[launcher]')
        $release='(?m)^\[agent\] released MSYS heap window 0000000600000000\r?$'
        $pass=$pass -and $launcherLine -ge 0 -and
            $err.Substring(0,$launcherLine) -match $release -and
            $err.Substring($launcherLine) -match $release
    }
    $results.Add([pscustomobject]@{Name=$Name;Passed=$pass;ExitCode=$result.ExitCode;Expected=$Expected;DiagnosticFailure=$diagnosticFailure})
    Write-Output "$Name pass=$pass exit=$($result.ExitCode)"
}
$bash=Join-Path $GitRoot 'usr\bin\bash.exe'
$perl=Join-Path $GitRoot 'usr\bin\perl.exe'
for($i=1;$i -le $Repetitions;$i++) {
    Invoke-Case "fork-$i" $perl @((Join-Path $PSScriptRoot 'fixtures\fork.pl')) -Match 'fork from a secondary POSIX thread works' -CheckHeapHandoff
    Invoke-Case "shell-$i" $bash @('--noprofile','--norc',(Join-Path $PSScriptRoot 'fixtures\shell.sh')) -Match 'SHELL-PASS'
}
$allowedPosix=$allowed.Replace('\','/'); $denyPosix=$canary.Replace('\','/')
$boundary='set -eu; export PATH=/usr/bin:/bin; test "$(cat "'+$allowedPosix+'")" = read-ok; if cat "'+$denyPosix+'"; then exit 81; fi; if printf forbidden > "'+$denyPosix+'"; then exit 82; fi; if printf forbidden > "'+$allowedPosix+'"; then exit 83; fi; printf write-ok > allowed-write.txt; test "$(cat allowed-write.txt)" = write-ok; echo BOUNDARY-PASS'
Invoke-Case 'boundary' $bash @('--noprofile','--norc','-c',$boundary) -Match 'BOUNDARY-PASS'
Invoke-Case 'exit-status' $bash @('--noprofile','--norc','-c','exit 37') -Expected 37
Invoke-Case 'native-child' $bash @('--noprofile','--norc','-c','/c/Windows/System32/cmd.exe /d /c "echo NATIVE-CHILD"') -Match 'NATIVE-CHILD'
$unchanged=((Get-FileHash -LiteralPath $canary).Hash -eq $canaryHash -and (Get-FileHash -LiteralPath $allowed).Hash -eq $allowedHash)
$results.Add([pscustomobject]@{Name='boundary-files-unchanged';Passed=$unchanged})
Write-TestJson (Join-Path $evidence 'verification.json') $results
if(@($results | Where-Object {!$_.Passed}).Count){throw 'Verification failures: inspect unused/evidence/current/verify/verification.json and corresponding logs'}
Write-Output "ALL-PASS cases=$($results.Count)"
