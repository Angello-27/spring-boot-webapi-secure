## Quality Gate de seguridad

| Herramienta | Criterio de bloqueo | Hallazgos totales | Críticos | Estado |
|---|---|---:|---:|---|
| Semgrep (SAST) | severidad ERROR / CRITICAL / HIGH | 10 | 7 | ❌ FALLA |
| SpotBugs + FindSecBugs | categoría SECURITY con rank <= 12, o cualquier rank <= 4 | 9 | 3 | ❌ FALLA |
| Trivy (SCA sobre SBOM) | severidad HIGH / CRITICAL | 52 | 24 | ❌ FALLA |

### Semgrep (SAST): 7 hallazgos críticos

- `[ERROR] lab-permit-all src/main/java/bo/edu/devsecops/config/SecurityConfig.java:16`
- `[ERROR] lab-hardcoded-secret src/main/java/bo/edu/devsecops/controller/AuthController.java:18`
- `[ERROR] lab-hardcoded-secret src/main/java/bo/edu/devsecops/controller/AuthController.java:19`
- `[ERROR] lab-html-without-output-encoding src/main/java/bo/edu/devsecops/controller/CommentController.java:19`
- `[ERROR] java.spring.security.injection.tainted-html-string.tainted-html-string src/main/java/bo/edu/devsecops/controller/CommentController.java:19`
- ... y 2 más (ver artifacts)

### SpotBugs + FindSecBugs: 3 hallazgos críticos

- `[rank 10] SPRING_CSRF_PROTECTION_DISABLED bo.edu.devsecops.config.SecurityConfig`
- `[rank 12] CRLF_INJECTION_LOGS bo.edu.devsecops.controller.AuthController`
- `[rank 12] SQL_INJECTION_SPRING_JDBC bo.edu.devsecops.controller.ProductController`

### Trivy (SCA sobre SBOM): 24 hallazgos críticos

- `[HIGH] CVE-2026-68494 com.fasterxml.jackson.core:jackson-core@2.21.2 (corregida: 2.18.8, 2.21.4)`
- `[HIGH] CVE-2026-89407 com.fasterxml.jackson.core:jackson-core@2.21.2 (corregida: 2.18.11, 2.21.7, 2.22.3)`
- `[HIGH] CVE-2026-89425 com.fasterxml.jackson.core:jackson-core@2.21.2 (corregida: 2.21.7, 2.22.3, 2.18.11)`
- `[HIGH] CVE-2026-54512 com.fasterxml.jackson.core:jackson-databind@2.21.2 (corregida: 2.18.8, 3.1.4, 2.21.4)`
- `[HIGH] CVE-2026-54513 com.fasterxml.jackson.core:jackson-databind@2.21.2 (corregida: 2.18.8, 2.21.4, 3.1.4)`
- ... y 19 más (ver artifacts)

**Resultado: BLOQUEADO**
