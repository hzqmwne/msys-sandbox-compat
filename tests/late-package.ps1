param([string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root=Split-Path $PSScriptRoot -Parent
$state=Join-Path $root 'unused\runtime'
$evidence=Join-Path $root 'unused\evidence\current\late-package'
if($EvidenceDirectory){$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)}
$fixture=Join-Path $state ('late-'+[guid]::NewGuid().ToString('N'))
$install=Join-Path $fixture 'root'
$package=Join-Path $install 'usr\bin'
$outside=Join-Path $fixture 'root-other'
New-Item -ItemType Directory -Force $package,$outside,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null

# Stage a standard installation layout without writing into the real Git install.
$originalBin=Join-Path $GitRoot 'usr\bin'
Get-ChildItem -LiteralPath $originalBin -File | Where-Object {
    $_.Name -in @('bash.exe','perl.exe','msys-2.0.dll') -or
    $_.Name -match '^msys-(perl|crypt-|gcc_s-|iconv-|intl-).*\.dll$'
} | Copy-Item -Destination $package
foreach ($part in 'lib','share') {
    $source=Join-Path $GitRoot "usr\$part\perl5\core_perl"
    if (Test-Path -LiteralPath $source) {
        $destination=Join-Path $install "usr\$part\perl5"
        New-Item -ItemType Directory -Force $destination | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Recurse
    }
}
$exe=Join-Path $package 'new-printf.exe'
$dll=Join-Path $package 'new-module.dll'
$helper=Join-Path $package 'late-msys-helper.dll'
$aslr=Join-Path $package 'late-aslr-module.dll'
$outsideDll=Join-Path $outside 'new-module.dll'
$policy=Join-Path $state 'late-policy.json'
@{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot);readwritePaths=@($root);deniedPaths=@()}} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM $policy
$fixtureBinaries=Get-TestFixtureDirectory $BinaryDirectory
$bash=Join-Path $package 'bash.exe'
$moduleTest=(Join-Path $PSScriptRoot 'fixtures\late-module.pl').Replace('\','/')
$command='export PATH=/usr/bin:/bin; echo WAITING-FOR-PACKAGE; read -r ready; test "$ready" = installed || exit 80; /usr/bin/new-printf "LATE-EXE-PASS\n" || exit 81; /usr/bin/perl "'+$moduleTest+'" /usr/bin/new-module.dll /usr/bin/late-msys-helper.dll || exit $?; echo LATE-PACKAGE-PASS'
$info=New-TestProcessInfo (Get-PsecLauncher $BinaryDirectory) @() $state
$info.RedirectStandardInput=$true
foreach($a in @($policy,(Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'),'--trace',$bash,'--noprofile','--norc','-c',$command)){$info.ArgumentList.Add($a)}
$p=[Diagnostics.Process]::Start($info)
$errorText=$p.StandardError.ReadToEndAsync()
try {
    $first=$p.StandardOutput.ReadLineAsync()
    if(!$first.Wait(30000) -or $first.Result -ne 'WAITING-FOR-PACKAGE'){throw 'Target did not reach installation barrier'}
    foreach($path in @($exe,$dll,$helper,$aslr,$outsideDll)) {
        if(Test-Path -LiteralPath $path){throw 'Package files must not exist before target is ready'}
    }
    Copy-Item -LiteralPath (Join-Path $originalBin 'printf.exe') -Destination $exe
    Copy-Item -LiteralPath (Join-Path $fixtureBinaries 'late-msys-module.dll') -Destination $dll
    Copy-Item -LiteralPath (Join-Path $fixtureBinaries 'late-msys-helper.dll') -Destination $helper
    Copy-Item -LiteralPath (Join-Path $fixtureBinaries 'late-aslr-module.dll') -Destination $aslr
    Copy-Item -LiteralPath $dll -Destination $outsideDll
    $p.StandardInput.Write("installed`n");$p.StandardInput.Flush()
    $output=$p.StandardOutput.ReadToEndAsync()
    if(!$p.WaitForExit(60000)){throw 'Late package timeout'}
    $text=$output.GetAwaiter().GetResult();$err=$errorText.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $evidence 'late-package.stdout.txt'),$first.Result+"`n"+$text)
    [IO.File]::WriteAllText((Join-Path $evidence 'late-package.stderr.txt'),$err)
    if($p.ExitCode -ne 0 -or $text -notmatch 'LATE-EXE-PASS' -or $text -notmatch 'LATE-PACKAGE-PASS' -or ([regex]::Matches($text,'LATE-DLL-PASS')).Count -ne 2){throw "Late package failed exit=$($p.ExitCode): $text $err"}
    Write-Output 'LATE-PACKAGE-PASS: new in-root EXE and DLL, fork, and mapping boundaries'
} finally {
    if(!$p.HasExited){$p.Kill($true)}
    $p.Dispose()
}
