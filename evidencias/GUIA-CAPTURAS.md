# Guía de capturas — Laboratorio 3: CI Seguro con SAST y SCA

Guardar cada captura en `evidencias/capturas/` con **exactamente** el nombre indicado
(formato `.png`). Si un punto necesita más de una imagen, agregar un sufijo: `11-mvn-verify-2.png`, `11-mvn-verify-3.png`… El script `evidencias/generar_informe.py` las inserta en el PDF en este
orden y usa el nombre para el título. Si falta alguna, el PDF la marca como pendiente (las marcadas *Opcional* se omiten).
El script convierte las capturas a JPEG reducido para que el PDF quede por debajo de 20 MB.

En macOS: `Cmd + Shift + 4` y arrastrar para capturar un área; la imagen queda en el Escritorio.

## 1. Ejecución local

| Archivo | Qué capturar |
|---|---|
| `11-mvn-verify.png` | Terminal: `mvn -B clean verify` con `BUILD SUCCESS` y los tests ejecutados. |
| `12-semgrep-local.png` | Terminal: `docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep semgrep scan --config auto --config .semgrep.yml src/main/java` mostrando el *Scan Summary* (10 findings). |
| `13-dependency-check-local.png` | Navegador: reporte HTML de Dependency-Check (evidencias/local/dependency-check-report.html), parte superior con el resumen de dependencias vulnerables. |
| `14-dependency-check-commons-text.png` | Mismo reporte, sección de `commons-text-1.9.jar` con CVE-2022-42889 (CRITICAL, 9.8). Abrir con `open evidencias/local/dependency-check-report.html`, buscar `commons-text-1.9.jar` en la tabla resumen y hacer clic (salta al detalle). |
| `15-spotbugs-local.png` | Terminal: `mvn -B compile com.github.spotbugs:spotbugs-maven-plugin:spotbugs com.github.spotbugs:spotbugs-maven-plugin:gui` (primero analiza y luego abre la GUI con los 9 bugs; agrupar por *Bug Rank*). Alternativa en terminal: `mvn -B compile com.github.spotbugs:spotbugs-maven-plugin:check`. |
| `16-trivy-local.png` | Terminal: `docker run --rm -v "$PWD/target:/work" aquasec/trivy:0.74.0 sbom --scanners vuln --severity HIGH,CRITICAL /work/bom.json` (tabla con CVE-2022-42889 CRITICAL). Si no existe `target/bom.json`, generarlo antes con `mvn -B package -DskipTests`. |
| `17-quality-gate-local.png` | Terminal: `python3 .github/scripts/quality_gate.py --semgrep evidencias/local/semgrep-results.json --spotbugs evidencias/local/spotbugsXml.xml --trivy evidencias/local/sca-report.json` con **BLOQUEADO**. |

## 2. Pipeline en GitHub Actions

| Archivo | Qué capturar |
|---|---|
| `21-actions-lista-workflows.png` | Pestaña **Actions**: lista de workflows (CI, CI/CD, Nightly, SCA y SBOM, Semgrep) y sus ejecuciones. |
| `22-ci-feature-jobs.png` | Ejecución **CI - Spring Boot DevSecOps** de la rama `feature/lab3-ci-seguro`: grafo de jobs. |
| `23-quality-gate-resumen.png` | Esa ejecución → **Summary**: tabla del *Quality Gate de seguridad* (Semgrep, CodeQL, SpotBugs, Trivy) con **BLOQUEADO**. |
| `24-quality-gate-log.png` | Job **Security / Quality Gate** → paso *Evaluar reportes* con el detalle de hallazgos. |
| `25-sca-trivy-gate.png` | Job **SCA - SBOM y vulnerabilidades** → paso *Quality gate HIGH y CRITICAL* fallido. |
| `26-artifacts.png` | Parte inferior del Summary: lista de **Artifacts** (report-semgrep, report-codeql, report-spotbugs, sca-sbom-…, quality-gate-report). |
| `27-codeql-code-scanning.png` | Pestaña **Security → Code scanning**: alertas de CodeQL. |
| `28-nightly-dependency-check.png` | **Actions → CI - Nightly → Run workflow** (rama `feature/lab3-ci-seguro`): ejecución con el job *SCA - OWASP Dependency-Check*. |
| `30-cicd-main.png` | Ejecución **CI/CD - Spring Boot DevSecOps** en `main` o `develop` (cuando exista). Opcional. |

## 3. Protección de `main` y Dependabot

| Archivo | Qué capturar |
|---|---|
| `31-ruleset-main.png` | **Settings → Rules → Rulesets → proteger-main**: reglas activas y check requerido `Security / Quality Gate`. |
| `32-pr-merge-bloqueado.png` | PR #2: parte inferior con **"Merging is blocked"** y el check fallido. |
| `33-pr-checks.png` | PR #2 → pestaña **Checks**: lista de checks con el Quality Gate en rojo. |
| `34-dependabot-alerts.png` | **Security → Dependabot**: alertas (commons-text, spring, jackson…). |
| `35-dependabot-pr.png` | PR #1 de Dependabot: *Bump commons-text from 1.9 to 1.10.0*. |
| `36-advanced-security.png` | **Settings → Advanced Security**: Dependency graph, Dependabot alerts y security updates en *On*. |
| `37-secreto-nvd.png` | **Settings → Secrets and variables → Actions**: secreto `NVD_API_KEY` (solo el nombre, el valor no se ve). |
| `38-security-overview.png` | Pestaña **Security and quality → Overview**: Dependabot alerts y secret scanning habilitados. |

## 4. Generar el PDF

```bash
python3 evidencias/generar_informe.py
open evidencias/Laboratorio3-CI-Seguro.pdf
```

Se puede regenerar las veces que haga falta a medida que se agregan capturas.
