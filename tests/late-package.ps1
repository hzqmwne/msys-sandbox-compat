param([string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root=Split-Path $PSScriptRoot -Parent
$state=Join-Path $root 'unused\runtime'
$evidence=Join-Path $root 'unused\evidence\current\late-package'
if($EvidenceDirectory){$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)}
$package=Join-Path $state ('late-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $package,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$exe=Join-Path $package 'new-printf.exe'
$dll=Join-Path $package 'new-module.dll'
$helper=Join-Path $package 'late-msys-helper.dll'
$aslr=Join-Path $package 'late-aslr-module.dll'
$conflict=Join-Path $package 'late-conflict-module.dll'
$low=Join-Path $package 'late-low-module.dll'
$policy=Join-Path $state 'late-policy.json'
@{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot);readwritePaths=@($root);deniedPaths=@()}} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM $policy
$fixtureBinaries=Get-TestFixtureDirectory $BinaryDirectory
$bash=Join-Path $GitRoot 'usr\bin\bash.exe'
$moduleTest=(Join-Path $PSScriptRoot 'fixtures\late-module.pl').Replace('\','/')
$command='export PATH=/usr/bin:/bin; echo WAITING-FOR-PACKAGE; read -r ready; test "$ready" = installed || exit 80; export PATH="'+$package.Replace('\','/')+':/usr/bin:/bin"; "'+$exe.Replace('\','/')+'" "LATE-EXE-PASS\n" || exit 81; /usr/bin/perl "'+$moduleTest+'" "'+$dll.Replace('\','/')+'" "'+$helper.Replace('\','/')+'" || exit $?; echo LATE-PACKAGE-PASS'
$info=New-TestProcessInfo (Get-PsecLauncher $BinaryDirectory) @() $state
$info.RedirectStandardInput=$true
foreach($a in @($policy,(Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'),'--trace','--runtime',(Join-Path $GitRoot 'usr\bin\msys-2.0.dll'),$bash,'--noprofile','--norc','-c',$command)){$info.ArgumentList.Add($a)}
$p=[Diagnostics.Process]::Start($info)
$errorText=$p.StandardError.ReadToEndAsync()
try {
    $first=$p.StandardOutput.ReadLineAsync()
    if(!$first.Wait(30000) -or $first.Result -ne 'WAITING-FOR-PACKAGE'){throw 'Target did not reach installation barrier'}
    foreach($path in @($exe,$dll,$helper,$aslr,$conflict,$low)) {
        if(Test-Path -LiteralPath $path){throw 'Package files must not exist before target is ready'}
    }
    Copy-Item -LiteralPath (Join-Path $GitRoot 'usr\bin\printf.exe') -Destination $exe
    Copy-Item -LiteralPath (Join-Path $fixtureBinaries 'late-msys-module.dll') -Destination $dll
    Copy-Item -LiteralPath (Join-Path $fixtureBinaries 'late-msys-helper.dll') -Destination $helper
    Copy-Item -LiteralPath (Join-Path $fixtureBinaries 'late-aslr-module.dll') -Destination $aslr
    Copy-Item -LiteralPath $dll -Destination $conflict
    Copy-Item -LiteralPath (Join-Path $fixtureBinaries 'late-low-module.dll') -Destination $low
    $p.StandardInput.Write("installed`n");$p.StandardInput.Flush()
    $output=$p.StandardOutput.ReadToEndAsync()
    if(!$p.WaitForExit(60000)){throw 'Late package timeout'}
    $text=$output.GetAwaiter().GetResult();$err=$errorText.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $evidence 'late-package.stdout.txt'),$first.Result+"`n"+$text)
    [IO.File]::WriteAllText((Join-Path $evidence 'late-package.stderr.txt'),$err)
    if($p.ExitCode -ne 0 -or $text -notmatch 'LATE-EXE-PASS' -or $text -notmatch 'LATE-PACKAGE-PASS' -or ([regex]::Matches($text,'LATE-DLL-PASS')).Count -ne 2){throw "Late package failed exit=$($p.ExitCode): $text $err"}
    Write-Output 'LATE-PACKAGE-PASS: EXE and DLL created after target ready; dynamic module and fork both use preferred address'
} finally {
    if(!$p.HasExited){$p.Kill($true)}
    $p.Dispose()
}
