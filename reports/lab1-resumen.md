# Lab 1 — SAST con Semgrep

**Objetivo:** Revisar el código Java del proyecto Spring Boot con las reglas p/java y corregir un patrón inseguro confirmado.

## Hallazgos

| Regla | Ubicación | Riesgo | Mitigación |
|---|---|---|---|
| tainted-sql-string / spring-sqli (ERROR / WARNING) | ProductController.java:24–25 | El parámetro name de GET /api/products/search se concatena en el SQL: permite inyección SQL y leer cualquier tabla de la base (por ejemplo, users). Aplica al endpoint real. | Corregido: consulta parametrizada LIKE ? con queryForList(sql, "%" + name + "%"). mvn test pasa y las dos reglas desaparecen. |
| tainted-html-string (ERROR) | CommentController.java:19 | POST /api/comments/preview devuelve el comentario sin escapar dentro de HTML (text/html): XSS reflejado. | Pendiente: escapar con HtmlUtils.htmlEscape(comment) o usar una plantilla con escape automático; añadir una cabecera CSP. |

## Conclusión

Semgrep encontró 3 hallazgos (0 errores de análisis). Tras parametrizar la consulta quedan 1: el XSS de CommentController, que queda documentado como pendiente. El análisis es estático y por patrones: no cubre la configuración ni las dependencias.
