# DomainInfo 6.0 Security Suite — diseño y hoja de ruta

Estado: **Fase 1 implementada** en la rama `feature/v6-fase1-webapp`. Las fases 2–4 son plan, no código.

## 1. Punto de partida (DomainInfo 5.0)

- Núcleo Python solo con biblioteca estándar: `domaininfo.py` (CLI, `scan()`, `RUNNERS`, `MODES`),
  menú propio (`terminal_ui.py`), módulos por archivo (`dnsclient`, `mailsec`, `webtech`, `tlsdeep`,
  `recon`, `history`, `lookalike`, `netinfo`, `score`, `infra`, `render`, `routeros`).
- Módulos Bash clásicos en `modules/` (incluido `webapp.sh`), lanzados desde el menú (tecla `a`).
- 108 pruebas `unittest` sin red; CI en Windows/Linux/macOS × Python 3.10/3.12/3.14.

Deuda técnica detectada:

| Problema | Consecuencia | Fase 1 |
|---|---|---|
| `normalize_target()` reduce cualquier URL a su host | `/login` se audita como `/` | `safety.normalize_url()` conserva ruta y consulta |
| `urllib` sigue redirecciones sin control de destino | SSRF/redirecciones fuera de alcance | cliente HTTP propio con alcance y redirecciones manuales |
| Resolución DNS repetida en cada conexión | DNS rebinding entre peticiones | IP fijada por host durante toda la auditoría |
| `score.py` mezcla riesgo y falta de datos | Notas no comparables | `assessment` con Security / Coverage / Confidence |
| Hallazgos sin evidencia ni estado | Heurísticas parecen vulnerabilidades | modelo `evidence.Finding` con estado y confianza |
| Cabeceras evaluadas en dos sitios (`http_info`, `webtech`) | Duplicación | `webapp` reutiliza `webtech.grade_headers` y añade análisis profundo de CSP |

## 2. Arquitectura

```
domaininfo.py ── RUNNERS ──► dns, http, tls, tech, … (5.0, sin cambios)
                         └─► webapp ──► webapp.py ──► safety.py (URL, alcance, IP fijada, cliente HTTP)
                                                  └─► evidence.py (Finding, redacción, puntuaciones)
score.py ──► nota clásica (sin cambios de esquema) + hallazgos webapp confirmados/probables
evidence.assess() ──► report["assessment"] (campo nuevo)
tools.py ──► detección de herramientas externas (--doctor → "integrations")
```

Principios: núcleo stdlib; los adaptadores de herramientas externas solo detectan, comprueban
versión y se desactivan si faltan; los módulos activos se añadirán deshabilitados por defecto.

### Seguridad de la propia herramienta (Fase 1)

- **URL**: solo `http`/`https`, sin credenciales, sin caracteres de control, puerto 1–65535, sin fragmento.
- **Alcance**: el host de la URL y los de `--scope` (admite `*.dominio`). Una redirección fuera de alcance
  no se sigue: queda registrada como bloqueada.
- **SSRF / rebinding**: cada host se resuelve una vez y la conexión va a esa IP (Host y SNI con el nombre).
  Siempre se bloquean enlace local (incluido `169.254.169.254`), multicast, no especificadas y reservadas.
  Las direcciones no públicas (privadas, loopback, CGNAT…) solo se permiten si el objetivo inicial
  ya lo era (lo escribió el usuario) o con `--allow-private`.
- **Recursos**: tiempo por conexión, 5 redirecciones máximas, 1 MiB por respuesta, solo GET,
  sin cookies reenviadas, nunca se envía un formulario.
- **Secretos**: valores de cookies, tokens CSRF y fragmentos de claves se redactan antes de entrar
  en el reporte (`evidence.redact`); los parámetros sensibles de las URL (`code`, `token`, `sid`, `key`…)
  se ocultan (`evidence.redact_url`) y se eliminan los caracteres de control del contenido remoto.

### Revisión de seguridad independiente (Fase 1)

Una revisión sin acceso a las conclusiones del autor encontró, y se corrigieron con pruebas de regresión
(`tests/test_webapp.py::HostileServerTests`):

| Problema | Corrección |
|---|---|
| ReDoS en la firma de trazas de Node.js con 1 MB de saltos de línea | Patrón acotado y firmas limitadas a 256 KiB |
| Sin plazo total (servidor que envía byte a byte) | Plazo por auditoría y lectura por trozos |
| Parámetros secretos en URL, redirecciones y `action` sin ocultar; JSON con comillas | `redact_url`, nombres ampliados, comillas admitidas |
| `charset=undefined` y `max-age` gigante abortaban el módulo | Se capturan y se acota `max-age` |
| `shutil.which` en Windows (< 3.12) ejecutaría un binario plantado en la carpeta actual | Se ignoran rutas en la carpeta actual |
| Secuencias ANSI del objetivo en terminal/TXT | Se eliminan caracteres de control |
| NAT64 / 6to4 hacia `169.254.169.254` | Se clasifica la IPv4 incrustada |
| Origen con IP pública y privada habilitaba la red interna | Solo si todas sus IP son internas |
| Enlaces Markdown inyectados por títulos remotos | Escape de Markdown |

La verificación manual contra `python -m http.server` descubrió además que `http.client` suelta el socket
tras `getresponse()` cuando hay `Content-Length`; el servidor de pruebas ahora envía `Content-Length`.

## 3. Modelo de hallazgo

`id, target, path, category, title, severity, status, confidence, evidence, tool, impact,
verification, recommendation, references`.

Estados: `confirmado`, `probable`, `informativo`, `pendiente`, `no_aplicable`, `no_evaluado`, `error`.
Solo `confirmado` (evidencia directa en la respuesta) y `probable` restan en la Security Score;
`pendiente` significa “no hay evidencia en ningún sentido”, p. ej. un formulario sin token CSRF visible
y sin cookies SameSite: **no** se declara vulnerable.

Puntuaciones (`report["assessment"]`):
- **security**: 100 − penalizaciones (probable cuenta la mitad).
- **coverage**: comprobaciones ejecutadas / comprobaciones aplicables.
- **confidence**: comprobaciones con evidencia directa / comprobaciones ejecutadas.
- `evidence.comparable(a, b)`: dos auditorías solo se comparan si cubren las mismas comprobaciones y su
  cobertura difiere ≤ 10 puntos.

`report["score"]` (nota A–F de 5.0) se mantiene con el mismo esquema.

## 4. Hoja de ruta

| Fase | Contenido | Estado |
|---|---|---|
| 1 — Base sólida | URL completa, `webapp` pasivo, formularios/CSRF, cookies, CSP, CORS, errores, secretos expuestos, modelo de evidencias, nueva puntuación, política de alcance, detección de herramientas | **Hecha** |
| 2 — Seguridad avanzada | Sesiones con cuentas de prueba (fichero de autorización + límites), ZAP pasivo, Playwright opcional, análisis de OpenAPI, inventario de servicios | Plan |
| 3 — Integraciones | Ejecutores para Nmap, Nuclei, SSLyze, testssl.sh, Subfinder, httpx…; OSV/NVD/KEV con caché; correlación CVE por versión; historial y comparaciones | Plan |
| 4 — Security Center | FastAPI opcional en 127.0.0.1 con token, SQLite, dashboard React+TS, PDF/CSV, empaquetado | Plan |

### Decisiones para fases siguientes

- Las ejecuciones de herramientas externas usarán `subprocess.run([...], shell=False, timeout=…)`
  con argumentos construidos a partir de objetos validados (`safety.normalize_url`), nunca cadenas.
- La auditoría autenticada exigirá un archivo de autorización (`scope.toml`) con objetivos, cuentas
  de prueba por referencia a variables de entorno, ventana horaria y límite de peticiones.
- El dashboard escuchará solo en loopback y exigirá un token aleatorio por sesión.

## 5. Plan de implementación de la Fase 1 (TDD)

1. Pruebas de `safety`: URL con ruta/consulta/puerto, rechazo de credenciales y esquemas, alcance con comodín,
   clasificación de IP y rebinding con un resolvedor simulado.
2. Pruebas de `evidence`: redacción, estados válidos, ids estables, puntuaciones y comparabilidad.
3. Pruebas de `webapp` contra un servidor HTTP local (hilo): raíz frente a `/login`, formularios, CSRF directo /
   alternativo / pendiente, cookies, redirecciones dentro y fuera de alcance, errores técnicos, secretos, CORS.
4. Pruebas de CLI: `-m webapp --url …/login` conserva la ruta y el JSON público sigue igual.
5. Implementación mínima para pasar cada bloque; integración en menú, reportes y `--doctor`.
6. Revisión de seguridad, ruff/bandit/pyright y suite completa.
