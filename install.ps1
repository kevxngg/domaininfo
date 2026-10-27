$ErrorActionPreference = 'Stop'
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
$pythonArguments = @()
if (-not $pythonCommand) {
    $pythonCommand = Get-Command py -ErrorAction SilentlyContinue
    $pythonArguments = @('-3')
}
if (-not $pythonCommand) { throw 'Instala Python 3.10+ y activa la opción de PATH.' }
& $pythonCommand.Source @pythonArguments -c 'import sys; sys.exit(sys.version_info < (3,10))'
if ($LASTEXITCODE -ne 0) { throw 'Se requiere Python 3.10+.' }
& $pythonCommand.Source @pythonArguments (Join-Path $PSScriptRoot 'domaininfo.py') --doctor
if ($LASTEXITCODE -ne 0) { throw 'Falló el diagnóstico de DomainInfo.' }
Write-Host 'Listo. Desde esta carpeta: .\domaininfo.cmd example.com'
