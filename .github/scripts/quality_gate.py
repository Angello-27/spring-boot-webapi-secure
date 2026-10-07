#!/usr/bin/env python3
"""Quality gate de seguridad.

Lee los reportes de las herramientas del pipeline y falla (exit 1) si alguno
contiene hallazgos críticos según el umbral configurado. Un reporte indicado
pero inexistente o ilegible también hace fallar el gate: la ausencia de
evidencia no equivale a ausencia de vulnerabilidades.

Uso:
  python3 quality_gate.py \
    --semgrep reports/semgrep-results.json \
    --codeql reports/codeql \
    --spotbugs reports/spotbugsXml.xml \
    --trivy reports/sca-report.json \
    --dependency-check reports/dependency-check-report.json
"""
import argparse
import glob
import json
import os
import sys
import xml.etree.ElementTree as ET

SEVERE = {"CRITICAL", "HIGH"}


class Result:
    def __init__(self, tool, criterion):
        self.tool = tool
        self.criterion = criterion
        self.total = 0
        self.critical = []
        self.error = None

    @property
    def status(self):
        if self.error:
            return "ERROR"
        return "FALLA" if self.critical else "OK"


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def check_semgrep(path):
    r = Result("Semgrep (SAST)", "severidad ERROR / CRITICAL / HIGH")
    data = load_json(path)
    for item in data.get("results", []):
        r.total += 1
        sev = str(item.get("extra", {}).get("severity", "")).upper()
        if sev in {"ERROR"} | SEVERE:
            r.critical.append(f"[{sev}] {item.get('check_id')} "
                              f"{item.get('path')}:{item.get('start', {}).get('line')}")
    return r


def check_codeql(path, threshold):
    r = Result("CodeQL (SAST)", f"security-severity >= {threshold}")
    files = glob.glob(os.path.join(path, "**", "*.sarif"), recursive=True) if os.path.isdir(path) else [path]
    if not files:
        raise FileNotFoundError(f"no hay archivos .sarif en {path}")
    for sarif in files:
        data = load_json(sarif)
        for run in data.get("runs", []):
            rules = {}
            components = [run.get("tool", {}).get("driver", {})] + run.get("tool", {}).get("extensions", [])
            for comp in components:
                for rule in comp.get("rules", []):
                    rules[rule.get("id")] = rule
            for item in run.get("results", []):
                r.total += 1
                rule = rules.get(item.get("ruleId"), {})
                try:
                    score = float(rule.get("properties", {}).get("security-severity", 0))
                except ValueError:
                    score = 0.0
                if score >= threshold:
                    loc = item.get("locations", [{}])[0].get("physicalLocation", {})
                    r.critical.append(f"[{score}] {item.get('ruleId')} "
                                      f"{loc.get('artifactLocation', {}).get('uri')}:"
                                      f"{loc.get('region', {}).get('startLine')}")
    return r


def check_spotbugs(path, max_rank):
    r = Result("SpotBugs + FindSecBugs", f"categoría SECURITY con rank <= {max_rank}, o cualquier rank <= 4")
    root = ET.parse(path).getroot()
    for bug in root.iter("BugInstance"):
        r.total += 1
        rank = int(bug.get("rank", 20))
        category = bug.get("category", "")
        if (category == "SECURITY" and rank <= max_rank) or rank <= 4:
            cls = bug.find("Class")
            r.critical.append(f"[rank {rank}] {bug.get('type')} "
                              f"{cls.get('classname') if cls is not None else ''}")
    return r


def check_trivy(path):
    r = Result("Trivy (SCA sobre SBOM)", "severidad HIGH / CRITICAL")
    data = load_json(path)
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            r.total += 1
            if v.get("Severity") in SEVERE:
                r.critical.append(f"[{v.get('Severity')}] {v.get('VulnerabilityID')} "
                                  f"{v.get('PkgName')}@{v.get('InstalledVersion')} "
                                  f"(corregida: {v.get('FixedVersion') or 'n/d'})")
    r.critical.sort(key=lambda c: not c.startswith("[CRITICAL"))
    return r


def check_dependency_check(path, threshold):
    r = Result("OWASP Dependency-Check (SCA)", f"CVSS >= {threshold} o severidad HIGH / CRITICAL")
    data = load_json(path)
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            r.total += 1
            scores = [v.get(k, {}).get("baseScore", 0) for k in ("cvssv4", "cvssv3", "cvssv2")]
            score = max(float(s or 0) for s in scores)
            sev = str(v.get("severity", "")).upper()
            if score >= threshold or sev in SEVERE:
                r.critical.append(f"[{sev or score}] {v.get('name')} {dep.get('fileName')}")
    r.critical.sort(key=lambda c: not c.startswith("[CRITICAL"))
    return r


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--semgrep")
    p.add_argument("--codeql", help="archivo .sarif o directorio con archivos .sarif")
    p.add_argument("--spotbugs")
    p.add_argument("--trivy")
    p.add_argument("--dependency-check")
    p.add_argument("--cvss", type=float, default=7.0, help="umbral CVSS / security-severity (default 7.0)")
    p.add_argument("--spotbugs-max-rank", type=int, default=12)
    p.add_argument("--max-lines", type=int, default=15, help="hallazgos listados por herramienta")
    p.add_argument("--output", default="quality-gate-report.md")
    args = p.parse_args()

    checks = [
        (args.semgrep, "Semgrep (SAST)", check_semgrep, ()),
        (args.codeql, "CodeQL (SAST)", check_codeql, (args.cvss,)),
        (args.spotbugs, "SpotBugs + FindSecBugs", check_spotbugs, (args.spotbugs_max_rank,)),
        (args.trivy, "Trivy (SCA sobre SBOM)", check_trivy, ()),
        (args.dependency_check, "OWASP Dependency-Check (SCA)", check_dependency_check, (args.cvss,)),
    ]
    results = []
    for path, name, fn, extra in checks:
        if not path:
            continue
        try:
            if not os.path.exists(path):
                raise FileNotFoundError(f"reporte no encontrado: {path}")
            results.append(fn(path, *extra))
        except Exception as exc:  # reporte ausente o corrupto
            res = Result(name, "-")
            res.error = str(exc)
            results.append(res)

    if not results:
        print("::error::No se indicó ningún reporte para evaluar")
        return 1

    lines = ["## Quality Gate de seguridad", "",
             "| Herramienta | Criterio de bloqueo | Hallazgos totales | Críticos | Estado |",
             "|---|---|---:|---:|---|"]
    for r in results:
        icon = {"OK": "✅ OK", "FALLA": "❌ FALLA", "ERROR": "⚠️ ERROR"}[r.status]
        lines.append(f"| {r.tool} | {r.criterion} | {r.total} | {len(r.critical)} | {icon} |")
    for r in results:
        if r.error:
            lines += ["", f"### {r.tool}: sin evidencia", "", f"`{r.error}`"]
        elif r.critical:
            lines += ["", f"### {r.tool}: {len(r.critical)} hallazgos críticos", ""]
            lines += [f"- `{c}`" for c in r.critical[:args.max_lines]]
            if len(r.critical) > args.max_lines:
                lines.append(f"- ... y {len(r.critical) - args.max_lines} más (ver artifacts)")

    failed = [r for r in results if r.status != "OK"]
    lines += ["", f"**Resultado: {'BLOQUEADO' if failed else 'APROBADO'}**"]
    report = "\n".join(lines) + "\n"

    print(report)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report)

    for r in failed:
        msg = r.error or f"{len(r.critical)} hallazgos críticos"
        print(f"::error title=Quality Gate - {r.tool}::{msg}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
