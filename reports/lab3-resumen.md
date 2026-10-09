# Lab 3 — Vulnerabilidades de imágenes con Trivy

**Objetivo:** Analizar una imagen antigua (nginx:1.24.0), aplicar un control HIGH/CRITICAL y compararla con una alternativa actual (nginx:stable).

## Hallazgos

| CVE | Paquete / versión instalada | Versión corregida | Riesgo |
|---|---|---|---|
| CVE-2024-45491 — CRITICAL | libexpat1 2.2.10-2+deb11u5 | 2.2.10-2+deb11u6 | Integer overflow en el parser XML Expat: puede corromper la memoria al procesar XML manipulado. |
| CVE-2024-45492 — CRITICAL | libexpat1 2.2.10-2+deb11u5 | 2.2.10-2+deb11u6 | Integer overflow en nextScaffoldPart de Expat: mismo vector de entrada XML. |

## Conclusión

El gate falla (exit 1) con 192 vulnerabilidades HIGH/CRITICAL en nginx:1.24.0 (Debian 11.9, digest sha256:f6daac2445b0…). Cambio propuesto: usar nginx:stable (Debian 13.7, digest sha256:9bf97bd7714f…). Las dos CVE elegidas desaparecen y los CRITICAL bajan de 17 a 1. stable no está libre de hallazgos: quedan CVE-2026-6653 en libxml2 (sin corrección publicada) y 67 HIGH. Hay que fijar la imagen por digest y volver a escanearla periódicamente.
