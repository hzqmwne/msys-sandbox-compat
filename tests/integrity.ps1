param(
    [string]$GitRoot='C:\Program Files\Git',
    [string]$Baseline=(Join-Path (Split-Path $PSScriptRoot -Parent) 'unused\evidence\git-before.json'),
    [string]$EvidenceDirectory='',
    [switch]$CaptureBaseline
)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$evidence=Join-Path $root 'unused\evidence\current\integrity'
if($EvidenceDirectory){$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)}
New-Item -ItemType Directory -Force $evidence | Out-Null
$after=@(Get-ChildItem -LiteralPath $GitRoot -File -Recurse | ForEach-Object {
    [pscustomobject]@{Path=[IO.Path]::GetRelativePath($GitRoot,$_.FullName);Length=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
if($CaptureBaseline){
    New-Item -ItemType Directory -Force (Split-Path ([IO.Path]::GetFullPath($Baseline)) -Parent) | Out-Null
    $after | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8NoBOM -LiteralPath $Baseline
    Write-Output "BASELINE-CAPTURED files=$($after.Count) path=$Baseline"
    return
}
if(!(Test-Path -LiteralPath $Baseline)){throw 'Capture a baseline before running compatibility tests: .\tests\integrity.ps1 -CaptureBaseline'}
$before=Get-Content -Raw -LiteralPath $Baseline | ConvertFrom-Json
$index=@{};foreach($item in $before){$index[$item.Path]=$item}
$differences=@(foreach($item in $after){
    $old=$index[$item.Path]
    if(!$old -or $old.Length -ne $item.Length -or $old.SHA256 -ne $item.SHA256){$item.Path}
    $index.Remove($item.Path)
};foreach($missing in $index.Keys){$missing})
$after | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8NoBOM -LiteralPath (Join-Path $evidence 'git-after.json')
$result=[pscustomobject]@{FilesBefore=$before.Count;FilesAfter=$after.Count;ChangedCount=$differences.Count;Differences=$differences}
$result | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8NoBOM -LiteralPath (Join-Path $evidence 'distribution-integrity.json')
if($differences.Count){throw "Distribution changed: $($differences.Count) files"}
Write-Output "INTEGRITY-PASS files=$($after.Count) changes=0"
