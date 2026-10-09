#!/usr/bin/env python3
"""Genera el informe de las guías DevSecOps locales (labs 1–7).

Toma los logs de reports/logs/ (escritos por run.sh: fecha, usuario, comando, salida y código
de salida reales), los reportes de reports/ y las capturas de evidencias/labs-local/capturas/.
Escribe reports/labN-resumen.md y evidencias/labs-local/DevSecOps-Labs-Locales.pdf (Chrome
headless). Solo usa la biblioteca estándar.
"""
import base64
import html
import json
import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(BASE))
REPORTS = os.path.join(ROOT, "reports")
LOGS = os.path.join(REPORTS, "logs")
CAPTURAS = os.path.join(BASE, "capturas")
HTML_OUT = os.path.join(BASE, "DevSecOps-Labs-Locales.html")
PDF_OUT = os.path.join(BASE, "DevSecOps-Labs-Locales.pdf")

AUTOR = "Miguel Angel Escobar Lazcano"
REPO = "https://github.com/Angello-27/spring-boot-webapi-secure"
RAMA = "feature/lab4-sbom-sca"
# Versión y digest de las imágenes ejecutadas (docker image inspect), como pide el README de las guías.
IMAGENES = [
    ("semgrep/semgrep:latest", "1.179.0", "sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b"),
    ("ghcr.io/zaproxy/zaproxy:stable", "2.17.0", "sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2"),
    ("bkimminich/juice-shop:latest", "latest", "sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"),
    ("aquasec/trivy:0.74.0", "0.74.0", "sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"),
    ("ghcr.io/gitleaks/gitleaks:latest", "8.30.1", "sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"),
    ("openpolicyagent/conftest:latest", "0.71.1", "sha256:0e77cdf7c1fcde035f3c579e4aaa6664ee2a8be5777eaa9af9f520cdd02280c0"),
]
GUIAS = "https://github.com/pablovillazon/devsecops-ddsv1e3/tree/main/guias-devsecops-local"
CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
]
ANSI = re.compile(r"\x1b\[[0-9;]*m")

e = html.escape


def load(name):
    with open(os.path.join(REPORTS, name), encoding="utf-8") as fh:
        return json.load(fh)


def terminal(log, drop=None, keep=None, head=None, tail=None, wide=False):
    """Bloque de terminal con la salida real del log; las líneas omitidas se indican."""
    lines = [ANSI.sub("", l) for l in open(os.path.join(LOGS, log + ".log"), encoding="utf-8").read().splitlines()]
    cabecera, cuerpo, fin = lines[0], lines[1:-1], lines[-1]
    cuerpo = [l for l in cuerpo if l.strip()]
    total = len(cuerpo)
    if drop:
        cuerpo = [l for l in cuerpo if not re.search(drop, l)]
    if keep:
        cuerpo = [l for l in cuerpo if re.search(keep, l)]
    if head and len(cuerpo) > head + (tail or 0):
        omit = len(cuerpo) - head - (tail or 0)
        cuerpo = cuerpo[:head] + [f"… ({omit} líneas omitidas) …"] + (cuerpo[-tail:] if tail else [])
    elif total != len(cuerpo):
        cuerpo.append(f"… ({total - len(cuerpo)} líneas omitidas) …")
    m = re.match(r"(\[[^\]]+\] \S+) \$ (.*)", cabecera)
    prompt, cmd = (m.group(1), m.group(2)) if m else (cabecera, "")
    clase = "term wide" if wide else "term"
    return (f'<div class="{clase}"><div class="prompt">{e(prompt)} $ <b>{e(cmd)}</b></div>'
            f'<pre>{e(chr(10).join(cuerpo))}</pre><div class="exit">{e(fin)}</div></div>')


def figura(nombre, desc):
    f = os.path.join(CAPTURAS, nombre)
    if not os.path.exists(f):
        return ""
    data = base64.b64encode(open(f, "rb").read()).decode()
    return f'<figure class="fig"><img src="data:image/png;base64,{data}"><figcaption>{e(desc)}</figcaption></figure>'


def table(headers, rows):
    out = ["<table><thead><tr>"] + [f"<th>{e(h)}</th>" for h in headers] + ["</tr></thead><tbody>"]
    out += ["<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows]
    return "".join(out + ["</tbody></table>"])


def md_table(headers, rows):
    limpio = lambda s: re.sub(r"<[^>]+>", "", str(s)).replace("|", "\\|")
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    return "\n".join(out + ["| " + " | ".join(limpio(c) for c in row) + " |" for row in rows])


# ---------------------------------------------------------------- datos por laboratorio

def lab1():
    antes, despues = load("semgrep-report.json")["results"], load("semgrep-after.json")["results"]
    hallazgos = [
        ["tainted-sql-string / spring-sqli (ERROR / WARNING)", "ProductController.java:24–25",
         "El parámetro <code>name</code> de <code>GET /api/products/search</code> se concatena en el SQL: "
         "permite inyección SQL y leer cualquier tabla de la base (por ejemplo, <code>users</code>). Aplica al endpoint real.",
         "<b>Corregido:</b> consulta parametrizada <code>LIKE ?</code> con <code>queryForList(sql, \"%\" + name + \"%\")</code>. "
         "<code>mvn test</code> pasa y las dos reglas desaparecen."],
        ["tainted-html-string (ERROR)", "CommentController.java:19",
         "<code>POST /api/comments/preview</code> devuelve el comentario sin escapar dentro de HTML "
         "(<code>text/html</code>): XSS reflejado.",
         "Pendiente: escapar con <code>HtmlUtils.htmlEscape(comment)</code> o usar una plantilla con escape automático; "
         "añadir una cabecera CSP."],
    ]
    return dict(
        num=1, titulo="SAST con Semgrep",
        objetivo="Revisar el código Java del proyecto Spring Boot con las reglas <code>p/java</code> y corregir un patrón inseguro confirmado.",
        evidencias=[terminal("01-02-semgrep-before"), terminal("01-03-semgrep-results"), terminal("01-04-fix-diff"),
                    terminal("01-05-mvn-test", keep=r"Tests run:|BUILD|Building spring"), terminal("01-06-semgrep-after"),
                    terminal("01-07-semgrep-compare")],
        headers=["Regla", "Ubicación", "Riesgo", "Mitigación"], hallazgos=hallazgos,
        conclusion=f"Semgrep encontró {len(antes)} hallazgos (0 errores de análisis). Tras parametrizar la consulta quedan "
                   f"{len(despues)}: el XSS de <code>CommentController</code>, que queda documentado como pendiente. "
                   "El análisis es estático y por patrones: no cubre la configuración ni las dependencias.")


def lab2():
    zap = load("zap-report.json")["site"][0]["alerts"]
    alerta = {a["name"]: a for a in zap}
    csp, cors, js = (alerta["Content Security Policy (CSP) Header Not Set"], alerta["Cross-Domain Misconfiguration"],
                     alerta["Dangerous JS Functions"])
    hallazgos = [
        ["Content Security Policy (CSP) Header Not Set — Medium (CWE-693)", e(csp["instances"][0]["uri"]),
         "Sin CSP, el navegador ejecuta cualquier script inyectado: un XSS no tiene una segunda barrera.",
         "Configuración: enviar <code>Content-Security-Policy: default-src 'self'; script-src 'self'</code> "
         "desde la aplicación o el proxy inverso."],
        ["Cross-Domain Misconfiguration — Medium (CWE-264)", e(cors["instances"][0]["uri"]) +
         f"<br>Evidencia: <code>{e(cors['instances'][0]['evidence'])}</code>",
         "<code>Access-Control-Allow-Origin: *</code> permite que cualquier sitio lea las respuestas no autenticadas de la API.",
         "Configuración: limitar CORS a una lista de orígenes de confianza."],
        ["Dangerous JS Functions — Low (CWE-749)", e(js["instances"][0]["uri"]) +
         f"<br>Evidencia: <code>{e(js['instances'][0]['evidence'])}</code>",
         "Código: <code>bypassSecurityTrustHtml</code> desactiva el saneamiento de Angular. Si recibe datos del usuario, "
         "se produce un XSS en el DOM.",
         "Eliminar el bypass o sanear el contenido con <code>DomSanitizer.sanitize</code> antes de insertarlo."],
    ]
    return dict(
        num=2, titulo="DAST baseline con OWASP ZAP sobre Juice Shop",
        objetivo="Explorar OWASP Juice Shop en ejecución con el escaneo pasivo <code>zap-baseline</code> y clasificar sus alertas.",
        nota="El puerto 3000 del equipo lo ocupa otro proyecto, así que Juice Shop se publicó en <code>127.0.0.1:3001</code>. "
             "ZAP no cambia: lo analiza en la red <code>devsecops-lab</code>, en <code>http://juice-shop:3000</code>, como indica la guía.",
        evidencias=[terminal("02-01-network"), terminal("02-02-juice-shop"), terminal("02-03-juice-check"),
                    figura("02-juice-shop.png", "Juice Shop en http://localhost:3001 (captura con Chrome headless)."),
                    terminal("02-04-zap", drop=r"^(PASS|IGNORE|INFO):", head=40),
                    figura("02-zap-report.png", "reports/zap-report.html: resumen y lista de alertas."),
                    terminal("02-05-cleanup")],
        headers=["Alerta", "URL / evidencia", "Riesgo", "Mitigación"], hallazgos=hallazgos,
        conclusion="ZAP terminó con código 2 (8 WARN, 0 FAIL y 59 reglas PASS). La araña recorrió 88 URL durante 1 minuto. "
                   "Las alertas de CSP, CORS y COEP/COOP son de <b>configuración</b>. La de <code>bypassSecurityTrustHtml</code> está en el "
                   "<b>código</b>. El baseline es pasivo y sin autenticación: no prueba la lógica de negocio (cupones, cesta, "
                   "roles), las rutas protegidas ni los POST de la API REST. Para eso hace falta un escaneo activo autenticado. "
                   "Juice Shop no se modificó.")


def lab3():
    a, d = load("trivy-before.json"), load("trivy-after.json")
    hallazgos = [
        ["CVE-2024-45491 — CRITICAL", "libexpat1 2.2.10-2+deb11u5", "2.2.10-2+deb11u6",
         "Integer overflow en el parser XML Expat: puede corromper la memoria al procesar XML manipulado."],
        ["CVE-2024-45492 — CRITICAL", "libexpat1 2.2.10-2+deb11u5", "2.2.10-2+deb11u6",
         "Integer overflow en <code>nextScaffoldPart</code> de Expat: mismo vector de entrada XML."],
    ]
    return dict(
        num=3, titulo="Vulnerabilidades de imágenes con Trivy",
        objetivo="Analizar una imagen antigua (<code>nginx:1.24.0</code>), aplicar un control HIGH/CRITICAL y compararla con una alternativa actual (<code>nginx:stable</code>).",
        evidencias=[terminal("03-01-trivy-volume"), terminal("03-02-trivy-pull", keep=r"Digest|Status|up to date"),
                    terminal("03-03-trivy-before"), terminal("03-04-trivy-gate"),
                    terminal("03-07-trivy-gate-table", wide=True), terminal("03-05-trivy-after"),
                    terminal("03-06-trivy-compare")],
        headers=["CVE", "Paquete / versión instalada", "Versión corregida", "Riesgo"], hallazgos=hallazgos,
        conclusion=f"El gate falla (exit 1) con 192 vulnerabilidades HIGH/CRITICAL en <code>{e(a['ArtifactName'])}</code> "
                   f"(Debian 11.9, digest <code>{e(a['Metadata']['RepoDigests'][0].split('@')[1][:19])}…</code>). "
                   f"Cambio propuesto: usar <code>{e(d['ArtifactName'])}</code> (Debian 13.7, digest "
                   f"<code>{e(d['Metadata']['RepoDigests'][0].split('@')[1][:19])}…</code>). Las dos CVE elegidas desaparecen y los CRITICAL "
                   "bajan de 17 a 1. <code>stable</code> no está libre de hallazgos: quedan CVE-2026-6653 en libxml2 (sin corrección "
                   "publicada) y 67 HIGH. Hay que fijar la imagen por digest y volver a escanearla periódicamente.")


def lab4():
    antes = [v for r in load("sca-before.json")["Results"] for v in r.get("Vulnerabilities") or []]
    despues = [v for r in load("sca-after.json")["Results"] for v in r.get("Vulnerabilities") or []]
    tomcat = len([v for v in despues if "tomcat" in v["PkgName"] and v["Severity"] == "CRITICAL"])
    hallazgos = [
        ["CVE-2022-42889 «Text4Shell» — CRITICAL 9.8", "commons-text (directa)", "1.9 → <b>1.10.0</b>",
         "La interpolación de <code>StringSubstitutor</code> (<code>script:</code>, <code>dns:</code>, <code>url:</code>) permite RCE "
         "si recibe datos del usuario. <b>Corregido.</b>"],
        [f"{tomcat} CVE CRITICAL (p. ej. CVE-2026-41293)", "tomcat-embed-core 10.1.54 (transitiva)", "10.1.58",
         "Es el servidor HTTP embebido. Pendiente: subir el parent de Spring Boot o fijar <code>tomcat.version</code>."],
        ["CVE HIGH (p. ej. CVE-2026-54512)", "jackson-databind 2.21.2 (transitiva)", "2.21.7",
         "Deserializa todo el JSON de la API. Pendiente: <code>jackson-bom.version</code> o un Spring Boot más reciente."],
    ]
    return dict(
        num=4, titulo="Inventario Maven (SBOM) y análisis SCA",
        objetivo="Generar un SBOM CycloneDX del proyecto, analizarlo con Trivy y comprobar que actualizar una dependencia vulnerable elimina su CVE.",
        evidencias=[terminal("04-01-dependency-tree", head=30, tail=0), terminal("04-02-verify-before", keep=r"Tests run:|BUILD|Building spring"),
                    terminal("04-03-sbom-before", keep=r"CycloneDX|BUILD|Writing"), terminal("04-04-bom-purl-before"),
                    terminal("04-05-sca-before", drop=r"Unsupported hash"), terminal("04-06-sca-before-cve", wide=True),
                    terminal("04-07-update-pom"), terminal("04-08-verify-after", keep=r"Tests run:|BUILD|Building spring"),
                    terminal("04-09-sbom-after", keep=r"CycloneDX|BUILD|Writing"), terminal("04-10-bom-purl-after"),
                    terminal("04-11-sca-after", drop=r"Unsupported hash"), terminal("04-12-sca-compare")],
        headers=["CVE", "Componente", "Versión anterior → corregida", "Riesgo / estado"], hallazgos=hallazgos,
        conclusion=f"El SBOM inicial (commit <code>00e5747</code>, commons-text 1.9) y el posterior (commit <code>90e490e</code>, "
                   f"commons-text 1.10.0) inventarían la aplicación y 53 componentes. La dependencia directa es "
                   f"<code>commons-text</code> y la transitiva, <code>commons-lang3</code>. Con 1.10.0, <code>mvn clean verify</code> "
                   f"sigue pasando (2 tests, BUILD SUCCESS) y el análisis baja de {len(antes)} a {len(despues)} vulnerabilidades: "
                   "la única eliminada es CVE-2022-42889. Las demás vienen de Tomcat, Jackson y Spring, que administra el parent "
                   "de Spring Boot. Los SBOM se guardan como <code>reports/bom-before.json</code> y <code>bom-after.json</code>.")


def lab5():
    hallazgos = [
        ["demo-token (regla didáctica)", "secret-demo/demo.env:1",
         "Un token en texto plano dentro de un archivo versionable queda expuesto a cualquiera con acceso al repositorio. "
         "Se usó un valor <b>ficticio</b> de la guía, y el reporte lo muestra como <code>REDACTED</code>.",
         "Reemplazado por <code>REPLACE_AT_RUNTIME</code>: el secreto se inyecta en tiempo de ejecución (variable de entorno o "
         "gestor de secretos). Segundo escaneo: <i>no leaks found</i>."],
        ["Historial Git (reglas por defecto)", "35 commits del repositorio",
         "Borrar un secreto del archivo actual no lo elimina de los commits anteriores.",
         "Sin hallazgos. Si apareciera una credencial real, primero se revoca o se rota y luego se limpia el historial."],
    ]
    return dict(
        num=5, titulo="Detección de secretos con Gitleaks (opcional)",
        objetivo="Detectar una credencial expuesta en archivos y revisar el historial Git en busca de secretos.",
        evidencias=[terminal("05-01-gitleaks-before", drop=r"^\s*[○│░╲]"), terminal("05-02-gitleaks-before-report"),
                    terminal("05-03-gitleaks-after", drop=r"^\s*[○│░╲]"), terminal("05-04-gitleaks-history", drop=r"^\s*[○│░╲]"),
                    terminal("05-06-limpieza")],
        headers=["Regla / alcance", "Ubicación", "Riesgo", "Mitigación"], hallazgos=hallazgos,
        conclusion="Gitleaks detectó el token ficticio (exit 1) y dejó de detectarlo tras reemplazarlo (exit 0). El historial "
                   "completo no tiene secretos con las reglas por defecto. Al terminar se retiraron <code>secret-demo/</code> y "
                   "<code>.gitleaks-demo.toml</code>.")


def lab6():
    hallazgos = [
        ["deny: <code>privileged == true</code>", "compose-lab.yaml, servicio <code>app</code>",
         "Un contenedor privilegiado accede a todos los dispositivos y capacidades del host: si se compromete, el atacante "
         "puede escapar al host.",
         "<code>privileged: false</code>. La política se evalúa antes del despliegue y bloquea el cambio."],
    ]
    return dict(
        num=6, titulo="Policy as Code con Conftest",
        objetivo="Bloquear con una política Rego una configuración Docker Compose que concede privilegios elevados.",
        evidencias=[terminal("06-01-archivos"), terminal("06-02-conftest-fail"), terminal("06-03-conftest-before-json"),
                    terminal("06-04-conftest-pass"), terminal("06-05-conftest-after-json")],
        headers=["Política", "Archivo", "Riesgo", "Corrección"], hallazgos=hallazgos,
        conclusion="Con <code>privileged: true</code>, Conftest devuelve FAIL (exit 1); con <code>false</code>, PASS (exit 0). "
                   "Pasar esta regla <b>no</b> demuestra que la configuración sea segura: la política no revisa el usuario, "
                   "los puertos, las capacidades (<code>cap_add</code>), los volúmenes del host ni la imagen. "
                   "Cada uno de esos riesgos necesita su propia regla.")


# ---------------------------------------------------------------- documento

CSS = """
@page { size: A4; margin: 15mm 13mm; }
body { font-family: -apple-system, 'Helvetica Neue', Arial, sans-serif; font-size: 10.3pt; color: #1b1f24; line-height: 1.45; }
h1 { font-size: 22pt; margin: 0 0 4px; } h2 { font-size: 15pt; border-bottom: 2px solid #1f6feb; padding-bottom: 3px; margin-top: 0; page-break-before: always; }
h3 { font-size: 11.5pt; margin: 16px 0 6px; page-break-after: avoid; }
.portada { padding-top: 70px; } .portada p { margin: 4px 0; } .sub { color: #57606a; font-size: 13pt; }
table { border-collapse: collapse; width: 100%; font-size: 8.8pt; margin: 6px 0 12px; }
th, td { border: 1px solid #d0d7de; padding: 3px 6px; text-align: left; vertical-align: top; } th { background: #f0f3f6; }
tr { page-break-inside: avoid; }
.term { background: #0d1117; color: #e6edf3; border-radius: 6px; padding: 7px 10px; margin: 7px 0 12px; page-break-inside: avoid; }
.term .prompt { color: #7ee787; font-family: Menlo, monospace; font-size: 7.6pt; word-break: break-all; }
.term .prompt b { color: #e6edf3; font-weight: 400; }
.term pre { margin: 5px 0 0; font-family: Menlo, monospace; font-size: 7.4pt; white-space: pre-wrap; color: #c9d1d9; }
.term.wide pre { font-size: 5.2pt; white-space: pre; overflow: hidden; }
.term .exit { font-family: Menlo, monospace; font-size: 7.4pt; color: #d2a8ff; margin-top: 3px; }
.fig { margin: 10px 0 16px; page-break-inside: avoid; } .fig img { max-width: 100%; max-height: 190mm; border: 1px solid #d0d7de; }
figcaption { font-size: 9pt; color: #57606a; margin-top: 4px; }
.nota { border-left: 4px solid #bf8700; background: #fff8c5; padding: 6px 10px; }
code { font-family: Menlo, monospace; font-size: 8.6pt; background: #f0f3f6; padding: 0 3px; }
"""


def main():
    labs = [lab1(), lab2(), lab3(), lab4(), lab5(), lab6()]
    p = [f"<!doctype html><html lang='es'><head><meta charset='utf-8'><title>DevSecOps - Laboratorios locales</title><style>{CSS}</style></head><body>"]
    p.append(f"""<div class="portada"><h1>Guías DevSecOps — ejecución local con Docker</h1>
<p class="sub">SAST · DAST · imágenes · SBOM/SCA · secretos · Policy as Code</p><br>
<p><b>Estudiante:</b> {e(AUTOR)}</p><p><b>Proyecto analizado:</b> {e(REPO)} (rama <code>{RAMA}</code>)</p>
<p><b>Guías:</b> {e(GUIAS)}</p><p><b>Equipo:</b> macOS (Darwin 25.6) · Docker 29.7.2 · Maven + Java 21</p><br>""")
    p.append(table(["Lab", "Herramienta", "Resultado"], [
        ["1", "Semgrep (SAST)", "3 hallazgos → 1 tras corregir la inyección SQL"],
        ["2", "OWASP ZAP baseline (DAST)", "8 alertas WARN, 0 FAIL (exit 2)"],
        ["3", "Trivy (imágenes)", "Gate HIGH/CRITICAL falla en nginx:1.24.0; CRITICAL de 17 a 1 con nginx:stable"],
        ["4", "CycloneDX + Trivy (SBOM/SCA)", "CVE-2022-42889 eliminada al pasar commons-text de 1.9 a 1.10.0"],
        ["5", "Gitleaks (opcional)", "Token ficticio detectado y corregido; historial sin secretos"],
        ["6", "Conftest (Policy as Code)", "FAIL con privileged: true → PASS con false"],
        ["7", "Snyk (opcional)", "No ejecutado: requiere cuenta y token de Snyk"],
    ]))
    p.append("<p style='font-size:9pt;color:#57606a'>Cada bloque de terminal reproduce la salida registrada de la ejecución: "
             "fecha y hora (UTC-4), usuario@equipo, comando, salida y código de salida. Las líneas de progreso o repetitivas se omiten y se indica cuántas. "
             "Los logs completos están en <code>reports/logs/</code>.</p>")
    p.append("<h3>Imágenes utilizadas</h3>" + table(["Imagen", "Versión", "Digest"], [
        [f"<code>{e(i)}</code>", e(v), f"<code>{e(d[:19])}…</code>"] for i, v, d in IMAGENES]) + "</div>")

    for lab in labs:
        p.append(f"<h2>Lab {lab['num']} — {e(lab['titulo'])}</h2><p><b>Objetivo:</b> {lab['objetivo']}</p>")
        if lab.get("nota"):
            p.append(f"<p class='nota'>{lab['nota']}</p>")
        p.append("<h3>Ejecución</h3>" + "".join(lab["evidencias"]))
        p.append("<h3>Hallazgos</h3>" + table(lab["headers"], lab["hallazgos"]))
        p.append(f"<h3>Conclusión</h3><p>{lab['conclusion']}</p>")
        with open(os.path.join(REPORTS, f"lab{lab['num']}-resumen.md"), "w", encoding="utf-8") as fh:
            limpio = lambda s: re.sub(r"<[^>]+>", "", s).replace("&#x27;", "'")
            fh.write(f"# Lab {lab['num']} — {lab['titulo']}\n\n**Objetivo:** {limpio(lab['objetivo'])}\n\n")
            if lab.get("nota"):
                fh.write(f"> {limpio(lab['nota'])}\n\n")
            fh.write(f"## Hallazgos\n\n{md_table(lab['headers'], lab['hallazgos'])}\n\n## Conclusión\n\n{limpio(lab['conclusion'])}\n")

    p.append("<h2>Lab 7 — SCA con Snyk (opcional)</h2><p>No se ejecutó. Es opcional y requiere una cuenta de Snyk y un "
             "token de autenticación. El análisis SCA del proyecto se cubre en el Lab 4 con CycloneDX y Trivy.</p>")
    p.append("</body></html>")

    with open(HTML_OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(p))
    chrome = next((c for c in CHROME_CANDIDATES if os.path.exists(c)), None)
    if not chrome:
        print(f"HTML generado en {HTML_OUT}; no se encontró Chrome/Edge/Brave para el PDF.")
        return 1
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={PDF_OUT}", "file://" + HTML_OUT],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"PDF generado: {PDF_OUT} ({os.path.getsize(PDF_OUT) / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
