param([string]$Payload)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$out = Join-Path $repo 'build'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$refs = @('/nologo', '/platform:x64', '/optimize+', '/r:System.Windows.Forms.dll', '/r:System.Web.Extensions.dll', '/r:System.IO.Compression.dll', '/r:System.IO.Compression.FileSystem.dll')
& $compiler @refs /target:exe "/out:$out\BugChessHookPermanent.exe" "$repo\src\BugChessHook.cs"
if ($LASTEXITCODE) { throw 'Hook compilation failed' }
& $compiler @refs /target:exe "/out:$out\BugChessNetwork.exe" "$repo\src\BugChessNetwork.cs"
if ($LASTEXITCODE) { throw 'Network component compilation failed' }
& $compiler @refs /target:winexe "/win32manifest:$repo\src\installer.manifest" "/out:$out\启动鲨鱼.exe" "$repo\src\BundleLauncher.cs"
if ($LASTEXITCODE) { throw 'Bundle launcher compilation failed' }
$extra = @()
if ($Payload) {
    $resolvedPayload = (Resolve-Path -LiteralPath $Payload).Path
    $extra = @("/resource:$resolvedPayload,BugChess.Payload")
}
& $compiler @refs /target:exe "/win32manifest:$repo\src\installer.manifest" "/out:$out\BugChessCracker.exe" @extra "$repo\src\BugChessComponents.cs" "$repo\src\PortableBundle.cs"
if ($LASTEXITCODE) { throw 'Installer compilation failed' }
Write-Output 'C# compilation checks passed.'
