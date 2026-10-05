# SECUTOR

**Auditoría de seguridad web, pensada para ser entendida sin ser especialista.**

SECUTOR es un backend en NestJS que analiza un sitio web desde varios ángulos de seguridad —
cabeceras HTTP, cookies, certificado TLS, fugas de datos, configuración de email, dependencias
vulnerables y más— y consolida todo en un reporte en PDF con hallazgos claros y accionables.
La idea de fondo: acercar los principios de OWASP a cualquier persona que necesite evaluar la
seguridad de una web, sin tener que interpretar jerga de pentesting.

> Este repositorio se comparte con fines de revisión técnica y portafolio. Código disponible
> para revisión, todos los derechos reservados — no licenciado para uso o distribución. Ver
> [LICENSE](./LICENSE).

## Stack técnico

- **NestJS** + **TypeScript**
- **Playwright** (Chromium headless) para navegación, extracción de HTML/scripts y peticiones HTTP
- **Wapalyzer** para analizar las tecnologías del aplicativo web
- **jsPDF** + **jspdf-autotable** para la generación del reporte final
- **class-validator** / **class-transformer** para validación de entrada
- **@nestjs/throttler** para rate limiting, combinado con un fingerprint de sesión de navegador

## Módulos del backend

Cada módulo expone su propio endpoint y puede usarse de forma independiente; `secutor-report`
los consolida en un único PDF.

| Módulo | Qué analiza |
|---|---|
| **web-identifier** | Identifica el stack tecnológico del sitio (frameworks, lenguajes, CMS, servidor) y lo clasifica por categoría. |
| **header-identifier** | Evalúa las cabeceras de seguridad HTTP (obligatorias, recomendadas, perjudiciales y obsoletas), les da un puntaje de 0 a 100 y detecta si hay rate limiting expuesto. |
| **cookie-identifier** | Revisa cada cookie emitida por el sitio: flags `Secure`/`HttpOnly`, `SameSite`, alcance de dominio, cookies de terceros, prefijos `__Host-`/`__Secure-` y señales de exposición del valor (JWT, texto plano, etc.). |
| **content-identifier** | Analiza el DOM en busca de formularios inseguros, contenido mixto (HTTP sobre HTTPS) y vulnerabilidades de tabnabbing (`target="_blank"` sin `rel="noopener"`). |
| **data-identifier** | Busca fugas de datos: API keys y credenciales hardcodeadas en HTML/JS, rutas sensibles expuestas (`.git`, `.env`, `appsettings.json`, etc.), source maps públicos y falta de Subresource Integrity en scripts de terceros. |
| **security-identifier** | Revisa el certificado TLS (vencimiento, autofirmado, coincidencia de hostname, protocolo débil) y si el sitio redirige correctamente de HTTP a HTTPS. |
| **domain-identifier** | Verifica la configuración de seguridad de email del dominio: registros SPF, DKIM y DMARC. |
| **vulnerability-identifier** | Cruza las tecnologías y versiones detectadas contra bases de datos de vulnerabilidades conocidas (OSV) para señalar dependencias desactualizadas. |
| **secutor-report** | Combina los resultados de todos los módulos anteriores y genera un reporte PDF único, con portada ejecutiva (riesgo general por categoría) y detalle por sección. |

## Autor

**Nicolas Breña Muñoz**
LinkedIn: https://www.linkedin.com/in/nicolás-breña-muñoz-805668201
Contacto: nicolas_brena@hotmail.com
