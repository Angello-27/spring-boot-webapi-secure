#!/usr/bin/env python3
"""Genera evidencias/Laboratorio3-CI-Seguro.pdf.

Combina:
  - tablas construidas a partir de los reportes locales (evidencias/local/)
  - las capturas de evidencias/capturas/, en el orden y con los títulos de GUIA-CAPTURAS.md
y lo imprime a PDF con Chrome en modo headless. Solo usa la biblioteca estándar.
"""
import base64
import collections
import datetime
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

BASE = os.path.dirname(os.path.abspath(__file__))
LOCAL = os.path.join(BASE, "local")
CAPTURAS = os.path.join(BASE, "capturas")
GUIA = os.path.join(BASE, "GUIA-CAPTURAS.md")
HTML_OUT = os.path.join(BASE, "Laboratorio3-CI-Seguro.html")
PDF_OUT = os.path.join(BASE, "Laboratorio3-CI-Seguro.pdf")

REPO = "https://github.com/Angello-27/spring-boot-webapi-secure"
PR = REPO + "/pull/2"
AUTOR = "Miguel Angel Escobar Lazcano"
CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
]
# Las capturas se convierten a JPEG (ancho máximo y calidad) para que el PDF pese poco.
JPEG_ANCHO = 1600
JPEG_CALIDAD = 55
TMP = tempfile.mkdtemp(prefix="informe-")
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 4}

e = html.escape


def path(name):
    return os.path.join(LOCAL, name)


def table(headers, rows):
    out = ["<table><thead><tr>"] + [f"<th>{e(h)}</th>" for h in headers] + ["</tr></thead><tbody>"]
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in row) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def badge(sev):
    sev = str(sev).upper()
    return f'<span class="sev sev-{e(sev.lower())}">{e(sev)}</span>'


def counts(counter):
    return " · ".join(f"{badge(k)} {v}" for k, v in sorted(counter.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9)))


# ---------------------------------------------------------------- reportes locales

def seccion_semgrep():
    f = path("semgrep-results.json")
    if not os.path.exists(f):
        return "<p class='pend'>Reporte de Semgrep no encontrado.</p>"
    res = json.load(open(f)).get("results", [])
    c = collections.Counter(r["extra"]["severity"] for r in res)
    rows = sorted(((r["extra"]["severity"], r["check_id"].split(".")[-1],
                    f"{r['path'].replace('src/main/java/bo/edu/devsecops/', '')}:{r['start']['line']}") for r in res),
                  key=lambda r: SEV_ORDER.get(r[0], 9))
    return (f"<p><b>{len(res)} hallazgos</b> — {counts(c)}</p>"
            + table(["Severidad", "Regla", "Ubicación"], rows))


def seccion_spotbugs():
    f = path("spotbugsXml.xml")
    if not os.path.exists(f):
        return "<p class='pend'>Reporte de SpotBugs no encontrado.</p>"
    bugs = list(ET.parse(f).getroot().iter("BugInstance"))
    rows = sorted(((b.get("rank"), b.get("category"), b.get("type"),
                    (b.find("Class").get("classname") if b.find("Class") is not None else "").split(".")[-1])
                   for b in bugs), key=lambda r: int(r[0]))
    return f"<p><b>{len(bugs)} hallazgos</b> (rank 1 = más grave)</p>" + table(["Rank", "Categoría", "Tipo", "Clase"], rows)


def seccion_trivy():
    f = path("sca-report.json")
    if not os.path.exists(f):
        return "<p class='pend'>Reporte de Trivy no encontrado.</p>"
    vulns = [v for r in json.load(open(f)).get("Results", []) for v in (r.get("Vulnerabilities") or [])]
    c = collections.Counter(v["Severity"] for v in vulns)
    graves = sorted((v for v in vulns if v["Severity"] in ("CRITICAL", "HIGH")), key=lambda v: SEV_ORDER[v["Severity"]])
    rows = [(v["Severity"], v["VulnerabilityID"], f"{v['PkgName']}@{v['InstalledVersion']}", v.get("FixedVersion") or "n/d")
            for v in graves]
    return (f"<p><b>{len(vulns)} vulnerabilidades</b> — {counts(c)}. Se listan las HIGH y CRITICAL.</p>"
            + table(["Severidad", "CVE", "Componente", "Versión corregida"], rows))


def seccion_dependency_check():
    f = path("dependency-check-report.json")
    if not os.path.exists(f):
        return "<p class='pend'>Reporte JSON de Dependency-Check pendiente (copiar target/dependency-check-report.json a evidencias/local/).</p>"
    deps = json.load(open(f)).get("dependencies", [])
    rows, c = [], collections.Counter()
    for d in deps:
        for v in d.get("vulnerabilities", []) or []:
            sev = str(v.get("severity", "")).upper()
            c[sev] += 1
            score = max(float(v.get(k, {}).get("baseScore", 0) or 0) for k in ("cvssv4", "cvssv3", "cvssv2"))
            rows.append((sev, v.get("name"), d.get("fileName"), score))
    rows.sort(key=lambda r: (SEV_ORDER.get(r[0], 9), -r[3]))
    graves = [r for r in rows if r[0] in ("CRITICAL", "HIGH")]
    return (f"<p><b>{len(rows)} vulnerabilidades</b> en {sum(1 for d in deps if d.get('vulnerabilities'))} dependencias — {counts(c)}. "
            "Se listan las HIGH y CRITICAL.</p>" + table(["Severidad", "CVE", "Dependencia", "CVSS"], graves))


def seccion_gate():
    f = path("quality-gate-report.md")
    if not os.path.exists(f):
        return ""
    filas = [l for l in open(f, encoding="utf-8") if l.startswith("| ") and "---" not in l]
    rows = [[c.strip() for c in l.strip().strip("|").split("|")] for l in filas[1:]]
    return table([c.strip() for c in filas[0].strip().strip("|").split("|")], rows)


# ---------------------------------------------------------------- capturas

def capturas():
    """Devuelve [(seccion, [(archivo, descripcion)])] según GUIA-CAPTURAS.md."""
    secciones, actual = [], None
    for line in open(GUIA, encoding="utf-8"):
        m = re.match(r"^## \d+\. (.+)", line)
        if m:
            actual = (m.group(1).strip(), [])
            secciones.append(actual)
            continue
        m = re.match(r"^\| `([\w-]+\.png)` \| (.+) \|$", line.strip())
        if m and actual:
            actual[1].append((m.group(1), re.sub(r"`([^`]+)`", r"\1", m.group(2))))
    return [s for s in secciones if s[1]]


def archivos(nombre):
    """La captura principal y sus variantes con sufijo (nombre-2.png, nombre-3.png...)."""
    stem = nombre[:-4]
    extra = sorted((f for f in os.listdir(CAPTURAS) if re.fullmatch(re.escape(stem) + r"-\d+\.png", f)),
                   key=lambda f: int(f[len(stem) + 1:-4]))
    return ([nombre] if os.path.exists(os.path.join(CAPTURAS, nombre)) else []) + extra


def jpeg(img):
    """Devuelve la captura como JPEG reducido (usa sips de macOS); si falla, el PNG original."""
    origen = os.path.join(CAPTURAS, img)
    destino = os.path.join(TMP, img[:-4] + ".jpg")
    r = subprocess.run(["sips", "-s", "format", "jpeg", "-s", "formatOptions", str(JPEG_CALIDAD),
                        "-Z", str(JPEG_ANCHO), origen, "--out", destino],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode == 0 and os.path.exists(destino):
        return "image/jpeg", open(destino, "rb").read()
    return "image/png", open(origen, "rb").read()


def figura(nombre, desc, n):
    titulo = f"Figura {n}. {nombre[3:-4].replace('-', ' ').capitalize()}"
    imgs = archivos(nombre)
    if not imgs and "opcional" in desc.lower():
        return ""
    if not imgs:
        return f'<div class="fig pend"><b>{e(titulo)}</b> — captura pendiente (<code>{e(nombre)}</code>)<br><small>{e(desc)}</small></div>'
    out = []
    for i, img in enumerate(imgs):
        mime, raw = jpeg(img)
        data = base64.b64encode(raw).decode()
        parte = f" ({i + 1}/{len(imgs)})" if len(imgs) > 1 else ""
        out.append(f'<figure class="fig"><img src="data:{mime};base64,{data}">'
                   f"<figcaption><b>{e(titulo)}{parte}.</b> {e(desc)}</figcaption></figure>")
    return "".join(out)


# ---------------------------------------------------------------- documento

CSS = """
@page { size: A4; margin: 16mm 14mm; }
body { font-family: -apple-system, 'Helvetica Neue', Arial, sans-serif; font-size: 10.5pt; color: #1b1f24; line-height: 1.45; }
h1 { font-size: 22pt; margin: 0 0 4px; } h2 { font-size: 15pt; border-bottom: 2px solid #1f6feb; padding-bottom: 3px; margin-top: 26px; page-break-after: avoid; }
h3 { font-size: 12pt; margin: 18px 0 6px; page-break-after: avoid; }
.portada { page-break-after: always; padding-top: 80px; } .portada p { margin: 4px 0; } .sub { color: #57606a; font-size: 13pt; }
table { border-collapse: collapse; width: 100%; font-size: 8.8pt; margin: 6px 0 12px; }
th, td { border: 1px solid #d0d7de; padding: 3px 6px; text-align: left; vertical-align: top; } th { background: #f0f3f6; }
tr { page-break-inside: avoid; }
.sev { font-weight: 700; font-size: 8pt; padding: 1px 5px; border-radius: 3px; color: #fff; }
.sev-critical { background: #a40e26; } .sev-high, .sev-error { background: #d1242f; } .sev-medium, .sev-warning { background: #bf8700; } .sev-low, .sev-info { background: #57606a; }
.fig { margin: 12px 0 18px; page-break-inside: avoid; } .fig img { max-width: 100%; max-height: 225mm; border: 1px solid #d0d7de; }
figcaption { font-size: 9pt; color: #57606a; margin-top: 4px; }
.pend { border: 1px dashed #bf8700; background: #fff8c5; padding: 8px; color: #6a4b00; }
code { font-family: Menlo, monospace; font-size: 8.8pt; background: #f0f3f6; padding: 0 3px; }
"""

WORKFLOWS = [
    ("ci-sec.yml", "CI", "push a feature/**, bugfix/**, hotfix/**; PR a main/develop", "Build & Test, CodeQL, Semgrep, SpotBugs, SBOM + Trivy, Quality Gate"),
    ("ci-cd-sec.yml", "CI/CD", "push a main y develop", "Pipeline de seguridad + Docker build → Trivy imagen → push GHCR (solo main, requiere gate aprobado)"),
    ("ci-sec-nightly.yml", "Nightly + SCA", "cron 20:55 America/La_Paz y manual", "Pipeline de seguridad + OWASP Dependency-Check (secreto NVD_API_KEY)"),
    ("security-pipeline.yml", "Reutilizable", "workflow_call", "Define los jobs y el Quality Gate que usan los tres anteriores"),
    ("sca-sbom.yml", "SCA y SBOM", "workflow_call y manual", "SBOM CycloneDX + Trivy sbom con gate HIGH/CRITICAL (guía 02)"),
    ("security-semgrep.yml", "Semgrep", "feature/** y PR a main/develop", "Workflow original de Semgrep (filtro de ramas corregido)"),
    ("dependabot.yml", "Dependabot", "semanal", "Actualizaciones de Maven y GitHub Actions"),
]

GATE = [
    ("Semgrep", "severidad ERROR / CRITICAL / HIGH"),
    ("CodeQL", "security-severity ≥ 7.0 (SARIF)"),
    ("SpotBugs + FindSecBugs", "categoría SECURITY con rank ≤ 12, o cualquier rank ≤ 4"),
    ("Trivy (SBOM)", "severidad HIGH / CRITICAL"),
    ("OWASP Dependency-Check", "CVSS ≥ 7.0 o severidad HIGH / CRITICAL (nightly)"),
    ("Cualquier herramienta", "reporte ausente o ilegible ⇒ falla (sin evidencia no se aprueba)"),
]


def main():
    hoy = datetime.date.today().strftime("%d/%m/%Y")
    partes = [f"<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Laboratorio 3 - CI Seguro</title><style>{CSS}</style></head><body>"]
    partes.append(f"""<div class="portada">
<h1>Laboratorio 3 — CI Seguro con SAST y SCA</h1>
<p class="sub">Módulo DevSecOps · Spring Boot + Maven</p><br>
<p><b>Estudiante:</b> {e(AUTOR)}</p>
<p><b>Repositorio:</b> {e(REPO)}</p>
<p><b>Pull request:</b> {e(PR)}</p>
<p><b>Rama:</b> feature/lab3-ci-seguro</p>
<p><b>Fecha:</b> {hoy}</p></div>""")

    partes.append("<h2>1. Implementación</h2><h3>Workflows</h3>"
                  + table(["Archivo", "Tipo", "Disparadores", "Contenido"], WORKFLOWS))
    partes.append("<h3>Quality Gate (.github/scripts/quality_gate.py)</h3>"
                  "<p>Lee los reportes de cada herramienta, publica un resumen en la ejecución (GITHUB_STEP_SUMMARY) "
                  "y termina con código 1 si encuentra hallazgos críticos. El check <code>Security / Quality Gate</code> "
                  "es obligatorio en el ruleset de <code>main</code>, por lo que un pipeline fallido bloquea el merge.</p>"
                  + table(["Herramienta", "Criterio de bloqueo"], GATE))
    partes.append("<h3>Otros cambios</h3><ul>"
                  "<li>Clave NVD retirada del <code>pom.xml</code>; Dependency-Check 13.0.0 la lee del secreto <code>NVD_API_KEY</code>.</li>"
                  "<li>SpotBugs con el plugin FindSecBugs; Dependency-Check genera HTML y JSON.</li>"
                  "<li>Java 21 en todos los workflows (igual que el <code>pom.xml</code>).</li>"
                  "<li>Dockerfile corregido (no existía Maven Wrapper; comandos de usuario válidos en Alpine).</li></ul>")

    partes.append("<h2>2. Reportes locales</h2>")
    partes.append("<h3>Quality Gate ejecutado localmente</h3>" + seccion_gate())
    partes.append("<h3>Semgrep (SAST)</h3>" + seccion_semgrep())
    partes.append("<h3>SpotBugs + FindSecBugs</h3>" + seccion_spotbugs())
    partes.append("<h3>OWASP Dependency-Check (SCA)</h3>" + seccion_dependency_check())
    partes.append("<h3>Trivy sobre SBOM CycloneDX (SCA)</h3>" + seccion_trivy())

    n = 0
    for i, (titulo, items) in enumerate(capturas(), start=3):
        partes.append(f"<h2>{i}. Capturas — {e(titulo)}</h2>")
        for nombre, desc in items:
            n += 1
            partes.append(figura(nombre, desc, n))

    partes.append("""<h2>Conclusiones</h2><ul>
<li>El pipeline ejecuta SAST (CodeQL, Semgrep, SpotBugs) y SCA (SBOM + Trivy, Dependency-Check) en cada rama de trabajo, en main/develop y cada noche.</li>
<li>El Quality Gate evalúa el contenido de los reportes y no solo el estado de los jobs; la aplicación, deliberadamente vulnerable, queda <b>BLOQUEADA</b>.</li>
<li>La regla de protección de <code>main</code> exige el check del Quality Gate: el merge del PR queda bloqueado mientras el pipeline falle.</li>
<li>Pendientes: corregir las vulnerabilidades de código (SQLi, XSS, secretos, CSRF) y actualizar dependencias (commons-text ≥ 1.10.0, Spring Boot 3.5.x más reciente).</li></ul>""")
    partes.append("</body></html>")

    with open(HTML_OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(partes))

    chrome = next((c for c in CHROME_CANDIDATES if os.path.exists(c)), None)
    if not chrome:
        print(f"HTML generado en {HTML_OUT}; no se encontró Chrome/Edge/Brave para el PDF.")
        return 1
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={PDF_OUT}", "file://" + HTML_OUT],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    faltan = [n for _, items in capturas() for n, d in items if not archivos(n) and "opcional" not in d.lower()]
    print(f"PDF generado: {PDF_OUT} ({os.path.getsize(PDF_OUT) / 1e6:.1f} MB)")
    print(f"Capturas pendientes ({len(faltan)}): {', '.join(faltan) if faltan else 'ninguna'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
