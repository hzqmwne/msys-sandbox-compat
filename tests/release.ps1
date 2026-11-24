#requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [Parameter(Mandatory)][string]$Version,
    [string]$GitRoot = 'C:\Program Files\Git',
    [switch]$Psec,
    [switch]$RuntimeOnly
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$state = Join-Path (Split-Path $PSScriptRoot -Parent) ('unused/runtime/release-smoke/' + [guid]::NewGuid())
New-Item -ItemType Directory -Force $state,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$bin = Join-Path $package 'bin'
$shim = Join-Path $bin 'msys-sandbox-compat-shim.exe'
$launcher = Join-Path $bin 'psec-run.exe'
if ((@(Get-ChildItem -LiteralPath $bin -Force).Name | Sort-Object) -join ' ' -ne
    'msys-sandbox-compat-shim.exe psec-run.exe') {
    throw 'Expected exactly the two standalone programs in bin'
}
$runtimeFiles = @('bin/msys-sandbox-compat-shim.exe','bin/psec-run.exe','LICENSE',
    'share/msys-sandbox-compat/licenses/LICENSE.minhook','share/msys-sandbox-compat/licenses/LICENSE.mxc',
    'share/msys-sandbox-compat/licenses/LICENSE.flatbuffers','share/msys-sandbox-compat/licenses/LICENSE.nlohmann')
foreach ($file in $runtimeFiles) {
    if (!(Test-Path -LiteralPath (Join-Path $package $file) -PathType Leaf)) { throw "Missing $file" }
}
if ($RuntimeOnly) {
    $actualFiles = Get-ChildItem -LiteralPath $package -Recurse -File -Force | ForEach-Object {
        $_.FullName.Substring($package.Length + 1).Replace('\', '/')
    }
    $differences = Compare-Object $runtimeFiles $actualFiles
    if ($differences) { throw ('Unexpected release package contents: ' + ($differences.InputObject -join ', ')) }
}
$result = Invoke-TestProcess (New-TestProcessInfo $shim @('--version') $state)
if ($result.ExitCode -ne 0 -or $result.Output.Trim() -cne $Version -or $result.Error) {
    throw "Expected shim version $Version"
}
$result = Invoke-TestProcess (New-TestProcessInfo $launcher @('--help') $state)
if ($result.ExitCode -ne 0 -or $result.Output -notmatch '--policy=FILE' -or $result.Error) {
    throw 'Expected psec-run help'
}

$bash = Join-Path $GitRoot 'usr\bin\bash.exe'
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$canary = Join-Path $state 'canary.txt'
[IO.File]::WriteAllText($canary, 'release-canary')
[IO.File]::WriteAllLines((Join-Path $state 'smoke.cmd'), @(
    '@echo off',
    ('"{0}" --noprofile --norc ./smoke.sh %1' -f $bash.Replace('%','%%')),
    'exit /b %errorlevel%'
))
$program = @'
set -eu
export PATH=/usr/bin:/bin
test "$(printf 'b\na\n' | sort | head -n 1)" = a
(printf allowed > release-write.txt)
test "$(cat release-write.txt)" = allowed
if [ "$1" = psec ]; then
    if cat canary.txt; then exit 81; fi
else
    test "$(cat canary.txt)" = release-canary
fi
echo RELEASE-SMOKE-PASS
exit 37
'@
[IO.File]::WriteAllText((Join-Path $state 'smoke.sh'), ($program.Replace("`r`n", "`n") + "`n"))
$target = @('--terminal=inherit','--',$cmd,'/d','/c','smoke.cmd')
if ($Psec) {
    $policy = Join-Path $state 'policy.json'
    Write-TestJson $policy @{filesystem=@{
        readonlyPaths=@($env:SystemRoot,$GitRoot,$package)
        readwritePaths=@($state)
        deniedPaths=@($canary)
    }}
    $info = New-TestProcessInfo $launcher (@("--policy=$policy",'--psec-version=1.0','--',$shim) + $target + 'psec') $state
} else {
    $info = New-TestProcessInfo $shim ($target + 'ordinary') $state
}
$result = Invoke-TestProcess $info 30000
if ($result.ExitCode -ne 37 -or $result.Output.Trim() -cne 'RELEASE-SMOKE-PASS' -or
    ($Psec -and ($result.Error -notmatch '\[PSEC\] native contract=1\.0\b' -or
        $result.Error -notmatch 'canary\.txt: Permission denied')) -or (!$Psec -and $result.Error)) {
    throw ($result | Out-String)
}
if ($Psec) { Write-Output 'RELEASE-PSEC-PASS: native relay, fork, denied canary and exit code' }
else { Write-Output 'RELEASE-PASS: installed binaries, native relay, fork and exit code' }
