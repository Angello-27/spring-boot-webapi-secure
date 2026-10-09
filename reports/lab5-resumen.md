# Lab 5 — Detección de secretos con Gitleaks (opcional)

**Objetivo:** Detectar una credencial expuesta en archivos y revisar el historial Git en busca de secretos.

## Hallazgos

| Regla / alcance | Ubicación | Riesgo | Mitigación |
|---|---|---|---|
| demo-token (regla didáctica) | secret-demo/demo.env:1 | Un token en texto plano dentro de un archivo versionable queda expuesto a cualquiera con acceso al repositorio. Se usó un valor ficticio de la guía, y el reporte lo muestra como REDACTED. | Reemplazado por REPLACE_AT_RUNTIME: el secreto se inyecta en tiempo de ejecución (variable de entorno o gestor de secretos). Segundo escaneo: no leaks found. |
| Historial Git (reglas por defecto) | 35 commits del repositorio | Borrar un secreto del archivo actual no lo elimina de los commits anteriores. | Sin hallazgos. Si apareciera una credencial real, primero se revoca o se rota y luego se limpia el historial. |

## Conclusión

Gitleaks detectó el token ficticio (exit 1) y dejó de detectarlo tras reemplazarlo (exit 0). El historial completo no tiene secretos con las reglas por defecto. Al terminar se retiraron secret-demo/ y .gitleaks-demo.toml.
