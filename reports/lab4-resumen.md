# Lab 4 — Inventario Maven (SBOM) y análisis SCA

**Objetivo:** Generar un SBOM CycloneDX del proyecto, analizarlo con Trivy y comprobar que actualizar una dependencia vulnerable elimina su CVE.

## Hallazgos

| CVE | Componente | Versión anterior → corregida | Riesgo / estado |
|---|---|---|---|
| CVE-2022-42889 «Text4Shell» — CRITICAL 9.8 | commons-text (directa) | 1.9 → 1.10.0 | La interpolación de StringSubstitutor (script:, dns:, url:) permite RCE si recibe datos del usuario. Corregido. |
| 6 CVE CRITICAL (p. ej. CVE-2026-41293) | tomcat-embed-core 10.1.54 (transitiva) | 10.1.58 | Es el servidor HTTP embebido. Pendiente: subir el parent de Spring Boot o fijar tomcat.version. |
| CVE HIGH (p. ej. CVE-2026-54512) | jackson-databind 2.21.2 (transitiva) | 2.21.7 | Deserializa todo el JSON de la API. Pendiente: jackson-bom.version o un Spring Boot más reciente. |

## Conclusión

El SBOM (commit base 00e5747) inventaría la aplicación y 53 componentes. La dependencia directa es commons-text y la transitiva, commons-lang3. Con 1.10.0, mvn clean verify sigue pasando (2 tests, BUILD SUCCESS) y el análisis baja de 53 a 52 vulnerabilidades: la única eliminada es CVE-2022-42889. Las demás vienen de Tomcat, Jackson y Spring, que administra el parent de Spring Boot. Los SBOM se guardan como reports/bom-before.json y bom-after.json.
