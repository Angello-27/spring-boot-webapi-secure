# Lab 2 — DAST baseline con OWASP ZAP sobre Juice Shop

**Objetivo:** Explorar OWASP Juice Shop en ejecución con el escaneo pasivo zap-baseline y clasificar sus alertas.

> El puerto 3000 del equipo lo ocupa otro proyecto, así que Juice Shop se publicó en 127.0.0.1:3001. ZAP no cambia: lo analiza en la red devsecops-lab, en http://juice-shop:3000, como indica la guía.

## Hallazgos

| Alerta | URL / evidencia | Riesgo | Mitigación |
|---|---|---|---|
| Content Security Policy (CSP) Header Not Set — Medium (CWE-693) | http://juice-shop:3000 | Sin CSP, el navegador ejecuta cualquier script inyectado: un XSS no tiene una segunda barrera. | Configuración: enviar Content-Security-Policy: default-src 'self'; script-src 'self' desde la aplicación o el proxy inverso. |
| Cross-Domain Misconfiguration — Medium (CWE-264) | http://juice-shop:3000Evidencia: Access-Control-Allow-Origin: * | Access-Control-Allow-Origin: * permite que cualquier sitio lea las respuestas no autenticadas de la API. | Configuración: limitar CORS a una lista de orígenes de confianza. |
| Dangerous JS Functions — Low (CWE-749) | http://juice-shop:3000/main.jsEvidencia: bypassSecurityTrustHtml( | Código: bypassSecurityTrustHtml desactiva el saneamiento de Angular. Si recibe datos del usuario, se produce un XSS en el DOM. | Eliminar el bypass o sanear el contenido con DomSanitizer.sanitize antes de insertarlo. |

## Conclusión

ZAP terminó con código 2 (8 WARN, 0 FAIL y 59 reglas PASS). La araña recorrió 88 URL durante 1 minuto. Las alertas de CSP, CORS y COEP/COOP son de configuración. La de bypassSecurityTrustHtml está en el código. El baseline es pasivo y sin autenticación: no prueba la lógica de negocio (cupones, cesta, roles), las rutas protegidas ni los POST de la API REST. Para eso hace falta un escaneo activo autenticado. Juice Shop no se modificó.
