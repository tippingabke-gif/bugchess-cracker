param([string]$Payload, [string]$TargetRoot)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$work = Join-Path $repo ('build\longpath-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$longEntry = 'runtime/python/Lib/site-packages/' + ('x' * 70) + '/' + ('y' * 70) + '/payload.dat'
function Write-Fixture([string]$Path, [bool]$Traversal) {
    $file = [IO.File]::Create($Path)
    $zip = New-Object IO.Compression.ZipArchive($file, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $entries = @($longEntry, 'runtime/python/python.exe', 'runtime/lab/sample.py', 'BugChessNetwork.exe')
        if ($Traversal) { $entries += '../escape.txt' }
        foreach ($name in $entries) {
            $entry = $zip.CreateEntry($name)
            $writer = New-Object IO.StreamWriter($entry.Open())
            try { $writer.Write('fixture') } finally { $writer.Dispose() }
        }
    } finally { $zip.Dispose(); $file.Dispose() }
}
$valid = Join-Path $work 'valid.zip'
if ($Payload) { $valid = (Resolve-Path -LiteralPath $Payload).Path }
else { Write-Fixture $valid $false }
$invalid = Join-Path $work 'traversal.zip'
Write-Fixture $invalid $true
# Retain the production longPathAware declaration; only remove the elevation requirement.
$manifest = Join-Path $work 'test.manifest'
$manifestText = [IO.File]::ReadAllText((Join-Path $repo 'src\installer.manifest')).Replace('requireAdministrator', 'asInvoker')
[IO.File]::WriteAllText($manifest, $manifestText, (New-Object Text.UTF8Encoding($false)))
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
function Build-Harness([string]$Archive, [string]$Output) {
    & $compiler /nologo /platform:x64 /optimize+ /target:exe /r:System.IO.Compression.dll /r:System.Web.Extensions.dll `
        "/win32manifest:$manifest" "/resource:$Archive,BugChess.Payload" "/out:$Output" `
        "$repo\src\RuntimeCompatibility.cs" "$repo\src\PortableBundle.cs" "$repo\tools\LongPathRegression.cs"
    if ($LASTEXITCODE) { throw 'Regression harness compilation failed' }
}
$runner = Join-Path $work 'ExtractTest.exe'
Build-Harness $valid $runner
$fresh = Join-Path $work ('fresh\' + ('nested-' * 12))
if ($TargetRoot) { $fresh = [IO.Path]::GetFullPath($TargetRoot) }
& $runner $fresh success (Join-Path $work 'success.json')
if ($LASTEXITCODE) { throw 'Long-path extraction regression failed' }
& $runner (Join-Path $work 'preserve') preserve (Join-Path $work 'preserve.json')
if ($LASTEXITCODE) { throw 'Existing-directory protection regression failed' }
$rejectRunner = Join-Path $work 'RejectTest.exe'
Build-Harness $invalid $rejectRunner
& $rejectRunner (Join-Path $work 'reject') reject (Join-Path $work 'reject.json')
if ($LASTEXITCODE) { throw 'Traversal/partial-cleanup regression failed' }
Write-Output "Long-path checks passed. Evidence: $work"
