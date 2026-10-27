# DomainInfo 4

Diagnóstico de dominios e IPs para **Termux, Kali/Linux, macOS y Windows**, por [@kevxngg](https://github.com/kevxngg).

El núcleo portable usa **Python 3.10+ y su biblioteca estándar**: no requiere pip, root, Bash, Nmap ni compiladores. Los módulos Bash de la versión 3 se conservan para auditorías avanzadas; sus requisitos y limitaciones son distintos.

## Instalación

### Termux

```bash
pkg update
pkg install git python
cd "$HOME"
git clone https://github.com/kevxngg/domaininfo.git
cd domaininfo
bash install.sh
domaininfo --doctor
domaininfo example.com
```

Trabaja dentro de `$HOME`, en vez del almacenamiento compartido de Android. El instalador utiliza `$PREFIX/bin`, no `/usr/bin`, no ejecuta sudo y no actualiza pip. Si falla `pkg`, revisa el error visible, la conexión y los repositorios con `termux-change-repo`. Consulta la [guía oficial de paquetes de Termux](https://github.com/termux/termux-packages/wiki/Package-Management).

### Kali y otras distribuciones Linux

```bash
git clone https://github.com/kevxngg/domaininfo.git
cd domaininfo
bash install.sh
python3 domaininfo.py --doctor
python3 domaininfo.py example.com
```

El instalador detecta apt, dnf o pacman si falta Python. El comando `domaininfo` se guarda en `~/.local/bin`; añade esa carpeta a PATH si hace falta. No ejecutes toda la aplicación con sudo.

### macOS

Instala Python 3.10+ (por ejemplo, `brew install python` si ya utilizas Homebrew), clona el repositorio y ejecuta:

```bash
bash install.sh
python3 domaininfo.py example.com
```

El núcleo portable no depende del Bash 3.2 del sistema ni de herramientas GNU.

### Windows (PowerShell o CMD)

Instala Python 3.10+ con su opción de PATH y Git. Abre una terminal nueva:

```powershell
git clone https://github.com/kevxngg/domaininfo.git
cd domaininfo
python domaininfo.py --doctor
.\domaininfo.cmd example.com
```

También puedes usar `py -3 domaininfo.py example.com`. El instalador opcional `install.ps1` solo verifica Python y el diagnóstico. Si PowerShell bloquea scripts, utiliza directamente `python domaininfo.py`; no necesitas cambiar la política del equipo.

## Funciones portables

| Modo | Funciones |
|---|---|
| `quick` (predeterminado) | Resolución IPv4/IPv6 y registro RDAP |
| `web` | DNS, HTTP, headers y certificado TLS verificado |
| `ports` | DNS y conexiones TCP concurrentes, sin sockets RAW |
| `full` | Todos los anteriores y traceroute del sistema, si está disponible |

Incluye dominios internacionales (IDNA), archivos batch UTF-8 con BOM/CRLF, eliminación de duplicados, errores por módulo, reportes JSON/TXT/HTML, escritura atómica y nombres únicos. El TXT contiene el mismo documento estructurado que el JSON. Los reportes HTML escapan el contenido remoto.

```bash
python3 domaininfo.py                          # Menú interactivo
python3 domaininfo.py example.com
python3 domaininfo.py -m web example.com
python3 domaininfo.py -m ports --ports 22,80,443 --timeout 2 -t 8 127.0.0.1
python3 domaininfo.py -m quick -s rdap ::1
python3 domaininfo.py -f targets.txt -m web -o logs --format all
python3 domaininfo.py -m full -s ports -s traceroute example.com
python3 domaininfo.py -q -s rdap localhost      # Solo JSON en stdout
python3 domaininfo.py --doctor                 # Diagnóstico local sin red
python3 domaininfo.py --help
```

En Windows sustituye `python3` por `python` o `py -3`.

`-t` limita conexiones TCP a 1–64 trabajadores. `--timeout` limita cada operación de conexión/lectura, entre 0.1 y 60 segundos; la resolución DNS del sistema y las redirecciones no tienen un límite global. `-s` puede repetirse. `--scheme http --web-port 8080` permite inspeccionar un servidor local. Una URL se normaliza a su host; configura protocolo y puerto con estas opciones, ya que la ruta y puerto de la URL no se conservan.

Los resultados salen como un documento JSON por objetivo. Código de salida: `0` sin errores, `1` si hay objetivos inválidos, módulos fallidos o error al guardar, `2` para argumentos inválidos y `130` al interrumpir. Un módulo omitido o traceroute no disponible no invalida los demás resultados.

### Límites de los resultados

- DNS portable consulta A/AAAA mediante el resolver del sistema. Los registros MX/TXT/NS y los módulos especializados siguen disponibles en Bash.
- RDAP envía el objetivo a `rdap.org` y al registro al que redirige. Requiere Internet y puede fallar por límites del servicio. Usa `-s rdap` para omitirlo.
- HTTP/TLS verifica certificados con el almacén de confianza de Python, siguiendo las [recomendaciones oficiales de Python](https://docs.python.org/3/library/ssl.html#ssl.create_default_context). No omite errores de confianza automáticamente.
- Un header ausente o un puerto abierto es una observación; no confirma por sí solo una vulnerabilidad ni un CVE.
- Traceroute usa `tracert` en Windows o `traceroute`/`tracepath` en Unix. Android puede limitarlo; se informa su ausencia y no se inventan saltos con conexiones TCP.

## Módulos Bash clásicos

```bash
bash install.sh --legacy
bash domaininfo.sh -m quick example.com
bash domaininfo.sh -m full -j -t 15 example.com
bash domaininfo.sh --portable --doctor
```

Para los módulos clásicos se necesita **Bash 4+**, curl, dig y las herramientas específicas de cada módulo (WHOIS, Nmap, OpenSSL, timeout/coreutils). En macOS ejecuta el Bash instalado por Homebrew; se reconoce `gtimeout`. Windows nativo usa el núcleo Python; los módulos clásicos requieren WSL/Linux y sus dependencias.

Se mantienen DNS extendido, geolocalización, WHOIS, subdominios, blacklists, stack web y los módulos de auditoría web/ISP/LAN. Son código heredado: algunos resultados son heurísticos y el acceso a interfaces, MAC/WiFi o sockets RAW depende del sistema y sus permisos. **No se garantiza paridad de auditorías WiFi entre Android, macOS y Windows.** La documentación histórica se conserva en [docs/LEGACY.md](docs/LEGACY.md); sus afirmaciones de cobertura de CVEs no equivalen a comprobaciones confirmadas.

## Pruebas y correcciones

```bash
python3 -m unittest discover -s tests -v
```

Las pruebas usan servicios locales y mocks para RDAP/TLS, sin auditar dominios ajenos. GitHub Actions ejecuta la suite con Python 3.10, 3.12 y 3.14 en Ubuntu, macOS y Windows. Termux requiere verificación manual en un dispositivo Android; los runners de GitHub no lo reproducen. Detalles de errores corregidos: [docs/FIXES.md](docs/FIXES.md).

Reportes en `logs/` (ignorados por Git). Utiliza los módulos activos solo sobre sistemas que tengas autorización para evaluar.

Licencia MIT. Autor: [@kevxngg](https://github.com/kevxngg).
