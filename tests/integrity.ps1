param(
    [string]$GitRoot='C:\Program Files\Git',
    [string]$Baseline=(Join-Path (Split-Path $PSScriptRoot -Parent) 'unused\evidence\git-before.json'),
    [string]$EvidenceDirectory='',
    [switch]$CaptureBaseline
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$Baseline=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Baseline)
$root=Split-Path $PSScriptRoot -Parent
$evidence=Join-Path $root 'unused\evidence\current\integrity'
if($EvidenceDirectory){$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)}
New-Item -ItemType Directory -Force $evidence | Out-Null
$gitDirectory=(Get-Item -LiteralPath $GitRoot).FullName.TrimEnd('\','/') + '\'
$after=@(Get-ChildItem -LiteralPath $gitDirectory -File -Recurse | ForEach-Object {
    [pscustomobject]@{Path=$_.FullName.Substring($gitDirectory.Length);Length=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
if($CaptureBaseline){
    New-Item -ItemType Directory -Force (Split-Path $Baseline -Parent) | Out-Null
    Write-TestJson $Baseline $after -Depth 3
    Write-Output "BASELINE-CAPTURED files=$($after.Count) path=$Baseline"
    return
}
if(!(Test-Path -LiteralPath $Baseline)){throw 'Capture a baseline before running compatibility tests: .\tests\integrity.ps1 -CaptureBaseline'}
$before=[IO.File]::ReadAllText($Baseline) | ConvertFrom-Json
$index=@{};foreach($item in $before){$index[$item.Path]=$item}
$differences=@(foreach($item in $after){
    $old=$index[$item.Path]
    if(!$old -or $old.Length -ne $item.Length -or $old.SHA256 -ne $item.SHA256){$item.Path}
    $index.Remove($item.Path)
};foreach($missing in $index.Keys){$missing})
Write-TestJson (Join-Path $evidence 'git-after.json') $after -Depth 3
$result=[pscustomobject]@{FilesBefore=$before.Count;FilesAfter=$after.Count;ChangedCount=$differences.Count;Differences=$differences}
Write-TestJson (Join-Path $evidence 'distribution-integrity.json') $result -Depth 3
if($differences.Count){throw "Distribution changed: $($differences.Count) files"}
Write-Output "INTEGRITY-PASS files=$($after.Count) changes=0"
