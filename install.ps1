$ErrorActionPreference = 'Stop'
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
$pythonArguments = @()
if (-not $pythonCommand) {
    $pythonCommand = Get-Command py -ErrorAction SilentlyContinue
    $pythonArguments = @('-3')
}
if (-not $pythonCommand) { throw 'Install Python 3.10+ and enable the PATH option.' }
& $pythonCommand.Source @pythonArguments -c 'import sys; sys.exit(sys.version_info < (3,10))'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ is required.' }
& $pythonCommand.Source @pythonArguments (Join-Path $PSScriptRoot 'domaininfo.py') --doctor
if ($LASTEXITCODE -ne 0) { throw 'The DomainInfo diagnostics failed.' }
Write-Host 'Done. From this folder: .\domaininfo.cmd example.com'
$script = Join-Path $PSScriptRoot 'domaininfo.py'
Write-Host 'TAB completion: add this line to your PowerShell profile (notepad $PROFILE):'
Write-Host "  python `"$script`" --completion powershell | Out-String | Invoke-Expression"
