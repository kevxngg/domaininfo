# Auditoría RouterOS 4.1

Autor: Kevin (@kevxngg). Revisión del catálogo: **2026-10-26**.

## Fuentes y alcance

Se contrastaron los rangos del [aviso de CERT Polska](https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/) con la [publicación de MikroTik actualizada en octubre](https://mikrotik.com/supportsec/september-2026-vulnerability/). El catálogo contiene estos seis avisos:

| Aviso | Componente |
|---|---|
| CVE-2026-67276 | Autenticación SSH |
| CVE-2026-67277 | Bandwidth-test |
| CVE-2026-67278 | Certificados y claves de host |
| CVE-2026-67279 | Canales SSH |
| CVE-2026-67281 | WebFig |
| CVE-2026-86060 | Usuarios SSH |

Los rangos exactos se conservan por aviso en `routeros.py` y se incluyen en cada reporte. Se usan los intervalos del investigador que publicó el aviso; no se extiende una afectación a toda una rama a partir de un resumen general. Por ejemplo, el aviso de WebFig comienza en 7.20 y el de validación de claves SSH en 7.9 según CERT Polska.

El parche completo de certificados está en **7.24.3** y **7.23.6**: **7.24.2**, **7.23.4** y **7.23.5** conservan un aviso potencial en este catálogo. RouterOS 6 queda fuera de ese aviso específico. Los demás límites se evalúan por separado.

La instantánea de versiones de referencia procede del [changelog oficial](https://mikrotik.com/download/changelogs): stable 7.25, long-term 7.23.8 y rama 6 en 6.49.23. Una versión anterior a stable no implica que deba cambiarse automáticamente desde long-term. Verifica arquitectura, canal, compatibilidad y política de actualización de tu equipo. Este catálogo no se actualiza solo y no cubre todos los CVEs históricos o futuros.

## Cómo se obtiene la evidencia

- Sin `--offline`, se prueban conexiones TCP a una lista limitada de servicios de gestión. `--ports` sustituye esa lista.
- Se lee el banner inicial SSH sin enviar credenciales y la página pública de inicio HTTP/HTTPS. No se sigue ninguna redirección. HTTPS conserva la verificación de certificados.
- Un número de protocolo SSH o una versión de otro servidor no se interpreta como RouterOS: se exige una marca RouterOS próxima a la versión.
- `--routeros-version` permite usar una versión de tu inventario; se registra como `user_supplied`. Una versión de banner se registra como `public_banner` y no es una identidad autenticada.
- Versiones contradictorias fuerzan revisión manual. Versiones desconocidas, beta/rc o ramas distintas de 6/7 no producen una conclusión de parche aplicado.
- `--web-port` y `--scheme` definen un puerto web personalizado; `--ssh-port` define el puerto del banner SSH. Incluye esos puertos en `--ports` si proporcionas una lista propia.

El modo `--offline` requiere una versión, no acepta objetivos ni batch y no resuelve DNS, escanea puertos o consulta servicios externos.

## Interpretación del reporte

| Estado del aviso | Significado |
|---|---|
| `potentially_affected` | La versión indicada está en un intervalo afectado del catálogo |
| `not_in_affected_range` | La versión queda fuera de los intervalos de ese aviso |
| `unknown_version` | Falta una versión para comparar |
| `manual_review` | Rama/beta/rc no evaluada o evidencia contradictoria |

`confirmed` permanece en `false`: no se intenta explotar el fallo. La exposición de puertos se informa por separado; un puerto cerrado o movido no elimina la aplicabilidad de un aviso por versión. Las comprobaciones no validan firewall, VLAN, permisos de usuarios, estado Flagged ni configuración interna; esas revisiones aparecen como recomendaciones para el administrador.

## Ejemplos

```bash
python3 domaininfo.py -m mikrotik --offline --routeros-version 7.24.2
python3 domaininfo.py -m mikrotik --offline --routeros-version 7.25
python3 domaininfo.py -m mikrotik --routeros-version 7.23.8 192.168.88.1
bash domaininfo.sh --mikrotik --offline --routeros-version 7.25
```

En Windows usa `python` o `py -3`. En Termux funciona con Python sin root. La validación automática usa un servidor local simulado y cubre límites de parches, versiones contradictorias, ausencia de versión, puertos personalizados y ausencia de conexiones en modo offline; no sustituye una prueba en hardware MikroTik real.
