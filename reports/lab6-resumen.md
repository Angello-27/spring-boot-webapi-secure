# Lab 6 — Policy as Code con Conftest

**Objetivo:** Bloquear con una política Rego una configuración Docker Compose que concede privilegios elevados.

## Hallazgos

| Política | Archivo | Riesgo | Corrección |
|---|---|---|---|
| deny: privileged == true | compose-lab.yaml, servicio app | Un contenedor privilegiado accede a todos los dispositivos y capacidades del host: si se compromete, el atacante puede escapar al host. | privileged: false. La política se evalúa antes del despliegue y bloquea el cambio. |

## Conclusión

Con privileged: true, Conftest devuelve FAIL (exit 1); con false, PASS (exit 0). Pasar esta regla no demuestra que la configuración sea segura: la política no revisa el usuario, los puertos, las capacidades (cap_add), los volúmenes del host ni la imagen. Cada uno de esos riesgos necesita su propia regla.
