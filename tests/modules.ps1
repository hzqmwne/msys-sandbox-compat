param([string]$BinaryDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root = Split-Path $PSScriptRoot -Parent
$state = Join-Path $root 'unused\runtime\modules'
$evidence = Join-Path $root 'unused\evidence\current\modules'
New-Item -ItemType Directory -Force $state,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$policy = Join-Path $state 'policy.json'
@{filesystem=@{readonlyPaths=@($env:SystemRoot,$root);readwritePaths=@($state);
    deniedPaths=@((Join-Path $PSScriptRoot 'fixtures\denied.txt'))}} |
    ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policy

$launcher = Get-PsecLauncher $BinaryDirectory
$compat = Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'
$fixtures = Get-TestFixtureDirectory $BinaryDirectory
$client = Join-Path $fixtures 'import-name\import-name-client.exe'
$fixedClient = Join-Path $fixtures 'import-name\import-name-fixed.exe'
$bridge = Join-Path $fixtures 'native-bridge.exe'
$exeAttempt = 'preferred EXE (mapped|mapping skipped)'

function Invoke-Case([string]$Name, [string[]]$Arguments, [string[]]$Required = @(),
                     [string[]]$Absent = @(), [int]$ExitCode = 0, [string]$CompatPath = $compat) {
    $info = New-TestProcessInfo $launcher (@($policy,$CompatPath,'--trace') + $Arguments) $state
    $result = Invoke-TestProcess $info
    Save-TestOutput $result $evidence $Name
    $output = $result.Output + $result.Error
    if ($result.ExitCode -ne $ExitCode) { throw "$Name exit=$($result.ExitCode) expected=$ExitCode" }
    foreach ($pattern in $Required) {
        if ($output -notmatch $pattern) { throw "$Name missing $pattern" }
    }
    foreach ($pattern in $Absent) {
        if ($output -match $pattern) { throw "$Name unexpectedly matched $pattern" }
    }
    Write-Output "$Name PASS"
}

Invoke-Case 'dll-placement-off' @('--disable-module','dll-placement',$client,'1df') `
    @('hooks=1df','root heap preflight','released MSYS heap window','root=msys hooks=8') `
    @('image mapping requested base',$exeAttempt)
Invoke-Case 'exe-placement-off' @('--disable-module','exe-placement',$client) `
    @('hooks=1ff','root heap preflight','released MSYS heap window') @($exeAttempt)
Invoke-Case 'heap-window-off' @('--native-relay','--disable-module','heap-window',
    $bridge,'--relay','0',$client) @('hooks=1ff') `
    @('heap preflight','released MSYS heap window',$exeAttempt)
Invoke-Case 'propagation-off' @('--disable-module','propagation',$client,'1bf') `
    @('hooks=1bf','root=msys hooks=8')
Invoke-Case 'ipc-and-dacl-off' @('--disable-module','ipc','--disable-module','process-dacl',
    '--disable-module','token-dacl',$client,'060') @('hooks=060','root=msys hooks=2')
Invoke-Case 'relay-policy-with-token-dacl-off' @('--native-relay','--disable-module','token-dacl',
    $bridge,'--relay','--narrow-default','0',$client) `
    @('relay=1 hooks=1','RELAY-NARROWED-POLICY-REJECTED')

$layoutOff = @('--disable-module','heap-window','--disable-module','exe-placement',
    '--disable-module','dll-placement')
$absentLayout = @('heap preflight','released MSYS heap window',$exeAttempt,
    'image mapping requested base')
Invoke-Case 'conpty-config' (@('--conpty','--no-native-relay') + $layoutOff + @($client,'1df')) `
    @('modules=71','hooks=1df') $absentLayout
Invoke-Case 'conpty-relay-config' (@('--conpty','--native-relay') + $layoutOff +
    @($bridge,'--relay','1',$client,'1df')) `
    @('child modules 0000000000000071','relay=1 hooks=1','hooks=1df') $absentLayout
Invoke-Case 'inherited-relay-conflict' (@('--native-relay') + $layoutOff +
    @($bridge,'--relay','0',$compat,'--disable-module','ipc',$client)) `
    @('module options conflict with inherited relay') @('IMPORT-NAME-MATCH') 1
Invoke-Case 'inherited-relay-disable' @($bridge,'--relay','0',$compat,'--no-native-relay',$client) `
    @('--no-native-relay conflicts with inherited relay') @('IMPORT-NAME-MATCH') 1
Invoke-Case 'propagation-relay-conflict' @('--disable-module','propagation','--native-relay',$client) `
    @('--native-relay requires the propagation module') @('IMPORT-NAME-MATCH') 1
Invoke-Case 'unknown-module' @('--disable-module','unknown',$client) `
    @('unknown compatibility module') @('IMPORT-NAME-MATCH') 1
$allOff = $layoutOff + @('--disable-module','propagation','--disable-module','ipc',
    '--disable-module','process-dacl','--disable-module','token-dacl')
Invoke-Case 'all-modules-off' ($allOff + @($client,'000')) `
    @('classification=skipped hooks=0','hooks=000') $absentLayout
$hostOnly = New-Item -ItemType Directory -Force (Join-Path $state 'host-only')
$standalone = Join-Path $hostOnly.FullName 'msys-sandbox-compat.exe'
Copy-Item -LiteralPath $compat -Destination $standalone -Force
$preparationOnly = @('--disable-module','dll-placement','--disable-module','propagation',
    '--disable-module','ipc','--disable-module','process-dacl','--disable-module','token-dacl')
Invoke-Case 'root-preparation-without-agent' ($preparationOnly + @($client,'000')) `
    @('hooks=000','root=msys hooks=0','root heap preflight') `
    @('image mapping requested base',$exeAttempt) -CompatPath $standalone
Invoke-Case 'fixed-root-exe-placement-only' ($preparationOnly +
    @('--disable-module','heap-window',$fixedClient,'000')) `
    @('hooks=000 base=0*170000000','preferred EXE mapped 0*170000000') @('heap preflight')
Invoke-Case 'fixed-root-exe-placement-off' ($allOff + @($fixedClient,'000')) `
    @('hooks=000 base=(?!0*170000000\b)[0-9a-f]+') @($exeAttempt)
$canary = Join-Path $PSScriptRoot 'fixtures\denied.txt'
$allowed = Join-Path $PSScriptRoot 'fixtures\allowed.txt'
$probe = Join-Path $fixtures 'native-probe.exe'
Invoke-Case 'all-modules-off-policy' ($allOff + @($probe,'--file-access',$allowed,$canary)) `
    @('classification=skipped hooks=0','allowed-read-error=0 denied-read-error=5') $absentLayout 37
