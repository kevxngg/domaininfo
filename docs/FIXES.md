# Correcciones de la versión 4

La versión 4.2 añade un menú guiado con navegación de regreso, validación que permite reintentar, progreso por módulo y visor de reportes. La entrada Bash sin argumentos abre este menú; el menú anterior sigue disponible con `--legacy`. Los comandos con objetivo conservan su salida JSON.

La versión 4.1 añade la auditoría portable de RouterOS por versión, con catálogo fechado y evidencias separadas de la aplicabilidad de un CVE. Ver [MIKROTIK.md](MIKROTIK.md).

No se encontraron logs de la sesión antigua de Termux. Estas correcciones provienen de la revisión del código y de pruebas reproducibles; no prueban cuál fue el error exacto de aquella sesión.

| Problema encontrado | Corrección |
|---|---|
| El instalador ocultaba stderr y el fallo de paquetes tras pipelines grep/head | Instalación con `set -euo pipefail`, salida visible y fallo inmediato |
| Un paquete opcional fallido impedía instalar el conjunto base | Python es el único requisito base; herramientas clásicas con `--legacy` |
| Alias sin comillas alrededor de rutas con espacios, symlink que alteraba SCRIPT_DIR | Launcher que conserva la ruta absoluta con comillas, sin modificar bashrc/zshrc |
| Uso de Bash asociativo en macOS con Bash 3.2 | Núcleo Python nativo y comprobación de Bash 4+ en la entrada clásica |
| `timeout` GNU no existe con ese nombre en macOS | Reconocimiento de `gtimeout` en la entrada clásica; Python no lo necesita |
| `date -Iseconds` y `date -d` no portables | Timestamp con formato explícito y fallback BSD para la fecha del certificado HTTP |
| Dependencias whois/host obligatorias para cualquier modo | Solo curl/dig comunes; WHOIS se omite con un mensaje si falta; núcleo Python independiente |
| Permisos RAW para Nmap en Termux | Escaneo clásico TCP con `-sT`; núcleo portable usa conexiones TCP sin root |
| RETURN traps podían persistir y borrar temporales de otras funciones | Limpieza explícita de temporales y registro para interrupción en la entrada clásica |
| Concurrencia cero o inválida y modos desconocidos aceptados | Validación de argumentos en ambas entradas |
| IPv4 con octetos 08/09 disparaba aritmética octal de Bash | Conversión explícita en base diez |
| Quiet seguía imprimiendo módulos y menú repetía al recibir EOF | Salida de escaneo silenciosa y salida del menú al cerrar stdin |
| LAN asumía `192.168.1.0/24` cuando no se podía detectar red | No iniciar descubrimiento sobre una red supuesta |
| Traceroute Python etiquetaba TCP como saltos sin medir TTL | Eliminar ese fallback y declarar la limitación de permisos |
| OpenSSL podía interpretar `Cipher: 0000` como TLS negociado | Rechazar cifrados NONE/0000, enviar SNI y no confundir un fallo local con protocolo deshabilitado |
| Reporte llamado completo truncaba el log a 200 líneas | HTML clásico incluye todas las líneas del archivo |

## Validación

La suite portable cubre entrada IPv4/IPv6/IDNA, argumentos inválidos, batch BOM/CRLF, puertos abiertos/cerrados locales, headers HTTP, respuestas HTTP 404, tamaño máximo de respuesta, errores TLS/RDAP, errores de traceroute, escape HTML, nombres únicos, modo quiet y fallo de escritura. TLS y RDAP se prueban con mocks; no son una validación contra todos los proveedores reales.

La compatibilidad declarada del núcleo corresponde a Python 3.10+ y APIs estándar. Las funciones de red dependen de conectividad y permisos del equipo. La suite de GitHub incluye Windows/Linux/macOS; no simula las restricciones de Android. Los módulos heredados requieren una revisión adicional para confirmar hallazgos y no constituyen un escáner de CVEs verificado.
