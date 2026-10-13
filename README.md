# WebScout
### Herramienta de Auditoría OSINT y Seguridad Web en Java

---

## 🚀 ¿Qué es WebScout?

**WebScout** es una utilidad desarrollada en Java diseñada para realizar escaneos y auditorías rápidas sobre dominios web. Obtiene información crítica de seguridad, cabeceras HTTP, certificados SSL, registros DNS críticos (SPF, DMARC, DNSSEC) y metadatos de registro mediante consultas RDAP.

---

## 🛡️ Características Principales

* **Inspección de Protocolo y Cabeceras de Seguridad:**
  * Detección de redirecciones (HTTP / HTTPS).
  * Análisis de cabeceras defensivas clave: `Strict-Transport-Security (HSTS)`, `Content-Security-Policy (CSP)` y `X-Frame-Options` (incluyendo validación de `frame-ancestors`).
  * Identificación del servidor web subyacente.
* **Auditoría de Certificados SSL/TLS:**
  * Validación de la vigencia del certificado y cálculo de días restantes para su caducidad.
  * Identificación de la versión del protocolo TLS utilizada.
* **Análisis de Registros DNS y Correos:**
  * Verificación de registros **SPF** y **DMARC** utilizando consultas DNS directas.
  * Comprobación de **DNSSEC** a través de Cloudflare DoH (`DNS-over-HTTPS`).
* **Información RDAP / Whois:**
  * Consulta automatizada de fechas de registro y expiración del dominio.

---


## 🎯 Buenas Prácticas y Entorno de Pruebas Ético

El reconocimiento pasivo y las auditorías de configuración son técnicas muy potentes tanto para administradores de sistemas (*Blue Team*) como para investigadores. Para mantener un uso ético y legal de **WebScout**, ten en cuenta las siguientes directrices:

1. **Audita solo tus propios dominios:** Utiliza la herramienta en aplicaciones, servidores o dominios de tu propiedad o sobre los cuales poseas una **autorización explícita y por escrito** (como entornos de prácticas o laboratorios controlados).
2. **Entornos de prueba recomendados (Safe Harbors):** 
   * Dominios propios configurados localmente (ej. `localhost` o contenedores de prueba).
   * Sitios web diseñados específicamente para pruebas de seguridad legal o plataformas de laboratorios de ciberseguridad autorizados.
3. **Respeto a la infraestructura ajena:** Aunque se trate de consultas públicas, un uso masivo o automatizado e indiscriminado contra terceros puede ser interpretado erróneamente como un ataque de denegación de servicio (DoS) o escaneo malicioso por los sistemas de mitigación de los proveedores de hosting o WAFs.

---

## ⚖️ Aviso Legal / Disclaimer

Uso Exclusivo Educativo y de Investigación

El material contenido en este repositorio se proporciona únicamente con fines educativos, de aprendizaje y de concienciación en ciberseguridad.

Propósito: Comprender cómo funcionan los mecanismos de seguridad web, la exposición de cabeceras y la auditoría pasiva de dominios.

Responsabilidad: El autor no asume ninguna responsabilidad por el mal uso o las actividades ilegales que terceros puedan realizar con esta herramienta. La ciberseguridad debe ejercerse siempre bajo un marco ético, legal y respetando la privacidad ajena.
