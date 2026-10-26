param([string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'),
      [ValidateSet('Psec','WriteRestricted','FullRestricted')][string]$Environment='Psec',
      [switch]$NativeRelay,
      [ValidateRange(1,1000)][int]$ThreadRepetitions=1)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root = Split-Path $PSScriptRoot -Parent
$restricted = $Environment -ne 'Psec'
$suite = if ($restricted) { 'restricted-' + $Environment.ToLowerInvariant() } else { 'process-chain' }
if ($NativeRelay) { $suite = 'relay-' + $suite }
$state = Join-Path $root ('unused\runtime\' + $suite)
$evidence = if ($EvidenceDirectory) { [IO.Path]::GetFullPath($EvidenceDirectory) }
            else { Join-Path $root ('unused\evidence\current\' + $suite) }
New-Item -ItemType Directory -Force $state,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$sourceBinaries = $BinaryDirectory
$fixtureBinaries = Get-TestFixtureDirectory $sourceBinaries
if ($restricted) {
    $BinaryDirectory = Initialize-RestrictedTestFiles $sourceBinaries $state
}
$policy = Join-Path $state 'policy.json'
$canary = if ($restricted) { Join-Path $state 'denied.txt' } else { Join-Path $PSScriptRoot 'fixtures\denied.txt' }
if (!$restricted) {
    @{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot,$root);readwritePaths=@($state);deniedPaths=@($canary)}} |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $policy -Encoding utf8NoBOM
}
$launcher = if ($restricted) { Join-Path $fixtureBinaries 'restricted-run.exe' }
            else { Get-PsecLauncher $BinaryDirectory }
$compat = Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'
$bridge = Join-Path $(if ($restricted) {$BinaryDirectory} else {$fixtureBinaries}) 'native-bridge.exe'
$bash = Join-Path $GitRoot 'usr\bin\bash.exe'
$runtime = Join-Path $GitRoot 'usr\bin\msys-2.0.dll'
[string[]]$prefix = if ($restricted) {
    @($(if ($Environment -eq 'WriteRestricted') {'write'} else {'full'}),$state)
} else { @($policy) }
function Shell-Command([object[]]$Arguments) {
    return (($Arguments | ForEach-Object { "'" + ([string]$_).Replace("'","'\''") + "'" }) -join ' ')
}
$fork = (Join-Path $(if ($restricted) {$BinaryDirectory} else {(Join-Path $PSScriptRoot 'fixtures')}) 'fork.pl').Replace('\','/')
$deny = $canary.Replace('\','/')
$payload = "set -eu; export PATH=/usr/bin:/bin; perl '$fork' $ThreadRepetitions; " +
    'test "$(printf fork-command)" = fork-command; test "$(printf ''b\na\n'' | sort | head -1)" = a; ' +
    "if cat '$deny'; then exit 81; fi; if printf forbidden > '$deny'; then exit 82; fi; " +
    'printf permitted > chain-write.txt; test "$(cat chain-write.txt)" = permitted; echo CHAIN-WORKLOAD-PASS; exit 37'
if ($restricted) {
    $check = Shell-Command @((Join-Path $BinaryDirectory 'restricted-run.exe').Replace('\','/'),
        'probe',$state.Replace('\','/'))
    $payload = 'set -e; ' + $check + '; ' + $payload
}
$results = [Collections.Generic.List[object]]::new()
$ordinary = $null
try {
    if ($restricted) {
        # Record the same-token unmodified baseline; its failure is not an acceptance result.
        $rawInfo = New-TestProcessInfo $launcher ($prefix + @($bash,'--noprofile','--norc','-c',
            'set -euo pipefail; test "$(printf raw-fork | cat)" = raw-fork; echo RAW-WORKLOAD-PASS')) $state
        $raw = Invoke-TestProcess $rawInfo 30000
        Save-TestOutput $raw $evidence 'raw-baseline'
        @{ExitCode=$raw.ExitCode;WorkloadCompleted=$raw.Output.Contains('RAW-WORKLOAD-PASS')} |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'raw-baseline.json') -Encoding utf8NoBOM
        # An ordinary MSYS session holds its global objects throughout both restricted chains.
        $ordinaryInfo = New-TestProcessInfo $bash @('--noprofile','--norc','-c',
            'echo ORDINARY-MSYS-READY; read -r done') $state
        $ordinaryInfo.RedirectStandardInput = $true
        $ordinary = [Diagnostics.Process]::Start($ordinaryInfo)
        $ordinaryError = $ordinary.StandardError.ReadToEndAsync()
        $ready = $ordinary.StandardOutput.ReadLineAsync()
        if (!$ready.Wait(10000) -or $ready.GetAwaiter().GetResult() -ne 'ORDINARY-MSYS-READY') {
            throw 'Ordinary MSYS coexistence fixture did not start'
        }
    }
    $cases=@(@{Depth=0;Root='native';Explicit=$false},@{Depth=2;Root='native';Explicit=$false})
    if ($NativeRelay) {
        $cases+=@(@{Depth=2;Root='msys';Explicit=$false},@{Depth=0;Root='native';Explicit=$true})
        $cases+=@(@{Depth=2;Root='native';Explicit=$false;Suspended=$true})
    }
    foreach ($case in $cases) {
        $depth=$case.Depth
        $nativeArgs=@($bridge.Replace('\','/'))
        if ($NativeRelay) {$nativeArgs+='--relay'}
        if ($case.Suspended) {$nativeArgs+='--suspended'}
        $nativeArgs+=@($depth)
        if (!$NativeRelay -or $case.Explicit) {
            $nativeArgs+=@($compat.Replace('\','/'))
            if ($NativeRelay) {$nativeArgs+='--trace'}
            $nativeArgs+=@('--runtime',$runtime.Replace('\','/'))
        }
        $inner = Shell-Command ($nativeArgs+@($bash.Replace('\','/'),'--noprofile','--norc','-c',$payload))
        $outer = 'export MSYS2_ARG_CONV_EXCL="*"; ' + $inner
        # The first native bridge records the original runner ACL, before MSYS has run.
        $expectedBridges=$depth+2
        $arguments = if ($NativeRelay) {
            $target=@($compat,'--native-relay','--runtime',$runtime)
            if ($case.Root -eq 'native') {$target+=@($bridge,'--relay',0)}
            else {$expectedBridges--}
            $prefix+$target+@($bash,'--noprofile','--norc','-c',$outer)
        } else {
            $prefix+@($bridge,0,$compat,'--runtime',$runtime,$bash,'--noprofile','--norc','-c',$outer)
        }
        $info = New-TestProcessInfo $launcher $arguments $state
        $result = Invoke-TestProcess $info 60000
        $name = "native-depth-$($depth+1)"
        if ($NativeRelay) {$name="$($case.Root)-depth-$($depth+1)-explicit-$($case.Explicit)"}
        if ($case.Suspended) {$name+='-suspended'}
        Save-TestOutput $result $evidence $name
        $acls = @([regex]::Matches($result.Error,'\[bridge\] clean=1 depth=\d+ default=([^\r\n]+)') |
            ForEach-Object { $_.Groups[1].Value })
        # A native entry records the runner policy before MSYS explicitly sets
        # its own ACL. Descendants retain that adapted request, not the runner snapshot.
        $descendantAcls = if ($case.Root -eq 'native') { @($acls | Select-Object -Skip 1) } else { $acls }
        $passed = $result.ExitCode -eq 37 -and $result.Output.Contains('CHAIN-WORKLOAD-PASS') -and
            $result.Output.Contains('fork from a secondary POSIX thread works') -and $result.Output -notmatch '(?m)^not ok' -and
            $acls.Count -eq $expectedBridges -and $descendantAcls.Count -gt 0 -and
            @($descendantAcls | Select-Object -Unique).Count -eq 1 -and
            $result.Error -notmatch 'fatal error|fork: retry|child_copy:|\[fatal\]'
        if ($restricted) { $passed = $passed -and $result.Output.Contains('RESTRICTED-TOKEN-AND-ACL-PASS') }
        if ($NativeRelay) {
            $passed=$passed -and [regex]::Matches($result.Error,'\[bridge-mode\] relay=1 hooks=1').Count -eq $expectedBridges
        }
        if ($case.Suspended) {
            $passed=$passed -and [regex]::Matches($result.Error,'suspended-preserved=1').Count -eq ($depth+1)
        }
        $results.Add([pscustomobject]@{Name=$name;Passed=$passed;ExitCode=$result.ExitCode;NativeBridges=$acls.Count})
        Write-Output "$name pass=$passed exit=$($result.ExitCode) bridges=$($acls.Count)"
    }
    if ($NativeRelay) {
        $arguments=$prefix+@($compat,'--trace','--native-relay','--runtime',$runtime,$bridge,'--relay',
            '--narrow-default',0,$bash,'--noprofile','--norc','-c','echo UNEXPECTED-EXECUTION')
        $result=Invoke-TestProcess (New-TestProcessInfo $launcher $arguments $state) 30000
        Save-TestOutput $result $evidence 'narrowed-policy'
        $passed=$result.ExitCode -eq 0 -and $result.Output.Contains('RELAY-NARROWED-POLICY-REJECTED') -and
            !$result.Output.Contains('UNEXPECTED-EXECUTION')
        $results.Add([pscustomobject]@{Name='narrowed-policy';Passed=$passed;ExitCode=$result.ExitCode;NativeBridges=1})
        Write-Output "narrowed-policy pass=$passed exit=$($result.ExitCode)"
    }
    if ($restricted -and $ordinary.HasExited) { throw 'Ordinary MSYS exited during the restricted workload' }
    $results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'results.json') -Encoding utf8NoBOM
    if (@($results | Where-Object {!$_.Passed}).Count) { throw 'Real MSYS process-chain workload failed' }
    Write-Output 'PROCESS-CHAIN-ALL-PASS'
} finally {
    if ($null -ne $ordinary) {
        if (!$ordinary.HasExited) {
            $ordinary.StandardInput.Close()
            if (!$ordinary.WaitForExit(3000)) { $ordinary.Kill($true); $ordinary.WaitForExit() }
        }
        [IO.File]::WriteAllText((Join-Path $evidence 'ordinary.stderr.txt'),$ordinaryError.GetAwaiter().GetResult())
        $ordinary.Dispose()
    }
}
