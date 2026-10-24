param([Parameter(Mandatory=$true)][string]$Installer, [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFile((Resolve-Path -LiteralPath $Installer).Path)
$stream = $assembly.GetManifestResourceStream('BugChess.Payload')
if (-not $stream) { throw 'Embedded payload is absent' }
$file = $null
try {
    $file = [IO.File]::Open($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output), [IO.FileMode]::CreateNew)
    $stream.CopyTo($file)
} finally { if ($file) { $file.Dispose() }; $stream.Dispose() }
