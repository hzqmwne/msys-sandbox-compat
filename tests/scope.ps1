param([string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root=Split-Path $PSScriptRoot -Parent
$state=Join-Path $root 'unused\runtime'
$evidence=Join-Path $root 'unused\evidence\current\scope'
if($EvidenceDirectory){$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)}
$fixtureBinaries=Get-TestFixtureDirectory $BinaryDirectory
$fixtures=Join-Path $fixtureBinaries 'renamed'
New-Item -ItemType Directory -Force $fixtures,$evidence,$state,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$policy=Join-Path $state 'scope-policy.json'
@{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot);readwritePaths=@($root);deniedPaths=@((Join-Path $PSScriptRoot 'fixtures\denied.txt'))}} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policy
$launcher=Get-PsecLauncher $BinaryDirectory
$compat=Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'
$probe=Join-Path $fixtureBinaries 'native-probe.exe'
$bash=Join-Path $GitRoot 'usr\bin\bash.exe'
Copy-Item -LiteralPath $probe -Destination (Join-Path $fixtures 'bash.exe')
function Run([string]$Name,[string[]]$Arguments,[string]$Report='') {
    $info=New-TestProcessInfo $launcher @() $state
    $info.ArgumentList.Add($policy)
    $info.ArgumentList.Add($Arguments[0])
    $info.ArgumentList.Add('--no-native-relay')
    foreach($argument in ($Arguments | Select-Object -Skip 1)){$info.ArgumentList.Add($argument)}
    $result=Invoke-TestProcess $info
    $err=$result.Error
    Save-TestOutput $result $evidence $Name
    if($result.ExitCode -ne 0){throw "$Name exit=$($result.ExitCode): $err"}
    if($Report -and (Get-Content -Raw -LiteralPath $Report) -notmatch 'clean=1'){throw "$Name not clean"}
    Write-Output "$Name PASS"
}
$report=Join-Path $evidence 'native-root.report.txt'
Run 'native-root' @($compat,'--trace',$probe,$report) $report
$report=Join-Path $evidence 'renamed-native.report.txt'
Run 'renamed-native' @($compat,'--trace',(Join-Path $fixtures 'bash.exe'),$report) $report
Run 'runtime-import-name' @($compat,'--trace',(Join-Path $fixtureBinaries 'import-name\import-name-client.exe'))
$report=Join-Path $evidence 'native-child.report.txt'
$command='"'+$probe.Replace('\','/')+'" --inspect-parent "'+$report.Replace('\','/')+'"; s=$?; echo PROBE-EXIT:$s; exit "$s"'
Run 'native-child-parent-check' @($compat,'--trace',$bash,'--noprofile','--norc','-c',$command) $report
$report=Join-Path $evidence 'native-child-fork-parent-check.report.txt'
$command='("'+$probe.Replace('\','/')+'" --inspect-parent "'+$report.Replace('\','/')+'"; exit $?); exit $?'
Run 'native-child-fork-parent-check' @($compat,'--trace',$bash,'--noprofile','--norc','-c',$command) $report
Run 'native-root-explicit-reentry' @($compat,'--trace',$probe,'--reenter',$compat,$bash)
$before = Join-Path $evidence 'msys-native-context-before.report.txt'
$after = Join-Path $evidence 'msys-native-context-after.report.txt'
$runtime = Join-Path $GitRoot 'usr\bin\msys-2.0.dll'
$command = 'export MSYS2_ARG_CONV_EXCL="*"; "' + $probe.Replace('\','/') +
    '" "' + $before.Replace('\','/') + '" || exit $?; "' + $compat.Replace('\','/') +
    '" --trace --no-native-relay --runtime "' + $runtime.Replace('\','/') + '" "' + $probe.Replace('\','/') +
    '" "' + $after.Replace('\','/') + '"'
Run 'msys-native-host-reentry' @($compat,'--trace',$bash,'--noprofile','--norc','-c',$command) $after
$beforeDacl = @(Get-Content -LiteralPath $before | Where-Object { $_ -like 'token-default-dacl=*' })
$afterDacl = @(Get-Content -LiteralPath $after | Where-Object { $_ -like 'token-default-dacl=*' })
if ($beforeDacl.Count -ne 1 -or $afterDacl.Count -ne 1 -or $beforeDacl[0] -ne $afterDacl[0]) {
    throw 'Native reentry changed token default DACL'
}

$command = 'export MSYS2_ARG_CONV_EXCL="*"; "' + $probe.Replace('\','/') +
    '" --reenter "' + $compat.Replace('\','/') + '" "' + $bash.Replace('\','/') + '"'
$info = New-TestProcessInfo $launcher @(
    $policy,$compat,'--no-native-relay','--runtime',$runtime,$bash,'--noprofile','--norc','-c',$command
) $state
$result = Invoke-TestProcess $info 30000
Save-TestOutput $result $evidence 'msys-native-msys-reentry'
if ($result.ExitCode -ne 0 -or $result.Output -notmatch 'EXPLICIT-REENTRY') {
    throw 'MSYS native bridge reentry failed'
}
Write-Output 'msys-native-msys-reentry PASS'
Write-Output 'SCOPE-ALL-PASS'
