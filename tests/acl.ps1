param([string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build/bin'),
      [switch]$Existing,[string]$EvidenceDirectory='',
      [ValidateSet('Psec','WriteRestricted','FullRestricted')][string]$Environment='Psec')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root=Split-Path $PSScriptRoot -Parent
$suite='acl-'+$Environment.ToLowerInvariant()
$state=Join-Path $root ('unused/runtime/'+$suite)
$evidence=if($EvidenceDirectory){[IO.Path]::GetFullPath($EvidenceDirectory)}else{Join-Path $root ('unused/evidence/current/'+$suite)}
New-Item -ItemType Directory -Force $state,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$compat=Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'
$perl='C:\Program Files\Git\usr\bin\perl.exe'
$probe=Join-Path (Get-TestFixtureDirectory $BinaryDirectory) 'acl-probe.dll'
$script=Join-Path $PSScriptRoot 'fixtures/acl-probe.pl'
if(!$Existing -and $Environment -ne 'Psec'){
    $fixtureBinaries=Get-TestFixtureDirectory $BinaryDirectory
    $staged=Initialize-RestrictedTestFiles $BinaryDirectory $state
    Copy-Item -LiteralPath $probe,$script -Destination $staged
    $compat=Join-Path $staged 'msys-sandbox-compat.exe'
    $probe=Join-Path $staged 'acl-probe.dll'
    $script=Join-Path $staged 'acl-probe.pl'
}
$arguments=@('--native-relay','--trace',$perl,$script,$probe)
if($Existing){$info=New-TestProcessInfo $compat $arguments $state}
elseif($Environment -ne 'Psec'){
    $mode=if($Environment -eq 'WriteRestricted'){'write'}else{'full'}
    $info=New-TestProcessInfo (Join-Path $fixtureBinaries 'restricted-run.exe') (@($mode,$state,$compat)+$arguments) $state
}
else{
    $policy=Join-Path $state 'policy.json'
    Write-TestJson $policy @{filesystem=@{readonlyPaths=@($env:SystemRoot,'C:\Program Files\Git',$root);readwritePaths=@($state);deniedPaths=@()}}
    $info=New-TestProcessInfo (Get-PsecLauncher $BinaryDirectory) (@($policy,$compat)+$arguments) $state
}
$result=Invoke-TestProcess $info 30000
Save-TestOutput $result $evidence 'settings'
if($result.ExitCode -ne 0 -or !$result.Output.Contains('MUTATION-SUITE PASS') -or
   $result.Output -match 'pass=0' -or !$result.Output.Contains('PERL-AFTER-MUTATION-PASS')){
    throw "ACL setting contract failed: $($result.ExitCode) $($result.Output) $($result.Error)"
}
Write-Output 'ACL-SETTINGS-PASS: real MSYS, explicit caller inputs, restricted handle rights and unchanged other tokens'
