package org.example.webscout.service;

import org.example.webscout.model.ReporteDominio;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Hashtable;

public class AuditorWeb {
    public ReporteDominio analizar(String dominio) throws Exception {
        String ip = InetAddress.getByName(dominio).getHostAddress();

        HttpClient cliente = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();

        HttpResponse<Void> respuesta = null;
        String protocoloUtilizado = "HTTPS";

        try {
            HttpRequest peticionHttps = HttpRequest.newBuilder()
                    .uri(URI.create("https://" + dominio))
                    .timeout(Duration.ofSeconds(3))
                    .header("User-Agent", "Mozilla/5.0")
                    .GET()
                    .build();
            respuesta = cliente.send(peticionHttps, HttpResponse.BodyHandlers.discarding());

        } catch (Exception e) {
            protocoloUtilizado = "HTTP";
            try {
                HttpRequest peticionHttp = HttpRequest.newBuilder()
                        .uri(URI.create("http://" + dominio))
                        .timeout(Duration.ofSeconds(3))
                        .header("User-Agent", "Mozilla/5.0")
                        .GET()
                        .build();
                respuesta = cliente.send(peticionHttp, HttpResponse.BodyHandlers.discarding());
            } catch (Exception exception) {
                // Previene caídas si el dominio no responde
            }
        }

        String servidor = "Oculto";
        String hstsEstado = "No";
        String cspEstado = "No";
        String xFrameEstado = "No";

        if (respuesta != null) {
            servidor = respuesta.headers().firstValue("Server").orElse("Oculto");
            hstsEstado = respuesta.headers().firstValue("Strict-Transport-Security").isPresent() ? "OK" : "No";

            boolean tieneCspCabecera = respuesta.headers().firstValue("Content-Security-Policy").isPresent();
            cspEstado = tieneCspCabecera ? "OK" : "No";

            String cspValor = respuesta.headers().firstValue("Content-Security-Policy").orElse("").toLowerCase();
            boolean tieneXFrame = respuesta.headers().firstValue("X-Frame-Options").isPresent();
            boolean protegeMarcosPorCsp = cspValor.contains("frame-ancestors");

            if (tieneXFrame || protegeMarcosPorCsp) {
                xFrameEstado = "OK";
            }
        }

        String sslEstado = "Inválido";
        String tlsVersion = "Ninguna";
        String sslDiasParaCaducar = "Caducado";

        if (protocoloUtilizado.equals("HTTPS")) {
            try {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                try (SSLSocket socket = (SSLSocket) factory.createSocket(dominio, 443)) {
                    socket.setSoTimeout(2500);
                    socket.startHandshake();

                    tlsVersion = socket.getSession().getProtocol();
                    X509Certificate cert = (X509Certificate) socket.getSession().getPeerCertificates()[0];

                    cert.checkValidity();
                    sslEstado = "Válido";

                    LocalDate fechaCaducidad = cert.getNotAfter()
                            .toInstant()
                            .atZone(ZoneId.systemDefault())
                            .toLocalDate();
                    long dias = ChronoUnit.DAYS.between(LocalDate.now(), fechaCaducidad);
                    sslDiasParaCaducar = dias + "días";
                }
            } catch (Exception exceptionE) {
                sslEstado = "Error";
                tlsVersion = "Error";
                sslDiasParaCaducar = "Error";
            }
        }


        String spfEstado = "No";
        String dmarcEstado = "No";
        String dnssecEstado = "No";

        InitialDirContext ictx = null;
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("java.naming.provider.url", "dns://8.8.8.8"); // Apunta directo al DNS global
            ictx = new InitialDirContext(env);
        } catch (Exception e) {
            System.err.println(e);
        }

        if (ictx != null) {
            // 1. Bloque SPF
            try {
                Attributes attrsTxt = ictx.getAttributes(dominio, new String[]{"TXT"});
                Attribute txtAttr = attrsTxt.get("TXT");
                if (txtAttr != null) {
                    for (int i = 0; i < txtAttr.size(); i++) {
                        String record = txtAttr.get(i).toString().toLowerCase();
                        if (record.contains("v=spf1")) {
                            spfEstado = "OK";
                            break; // Se detiene el bucle solo cuando encuentra "v=spf1"
                        }
                    }
                }
            } catch (Exception e) {
                spfEstado = "No";
            }

            // 2. Bloque DMARC
            try {
                dmarcEstado = "No";

                Attributes attrsDmarc = ictx.getAttributes("_dmarc." + dominio, new String[]{"TXT"});

                if (attrsDmarc != null){
                    Attribute dmarcAttr = attrsDmarc.get("TXT");

                        if (dmarcAttr != null && dmarcAttr.size() > 0) {


                            for (int i = 0; i < dmarcAttr.size(); i++) {
                                String record = dmarcAttr.get(i).toString().toLowerCase();
                                if (record.contains("v=dmarc1")) {
                                    dmarcEstado = "OK";
                                    break;
                                }
                            }
                        }
                }
            } catch (Exception e) {
                dmarcEstado = "No"; // Si el subdominio _dmarc no existe, se mostrará "No"
            }
        }

        // 3. Bloque DNSSEC vía Cloudflare
        try {
            java.net.URI uriDnssec = java.net.URI.create("https://cloudflare-dns.com/dns-query?name=" + dominio + "&type=RRSIG");

            java.net.http.HttpRequest peticionDnssec = java.net.http.HttpRequest.newBuilder()
                    .uri(uriDnssec)
                    .header("Accept", "application/dns-json")
                    .timeout(java.time.Duration.ofSeconds(2))
                    .GET().build();

            java.net.http.HttpResponse<String> respDnssec = cliente.send(peticionDnssec, java.net.http.HttpResponse.BodyHandlers.ofString());

            if (respDnssec.body() != null && respDnssec.body().contains("\"Answer\"") && respDnssec.body().contains("\"type\":46")){
                dnssecEstado = "OK";
            } else {
                dnssecEstado = "No";
            }
        } catch (Exception e) {
            dnssecEstado = "No";
        }

        String whoisRegistro = "Desconocido";
        String whoisExpira = "Desconocido";
        String whoisOrganizacion = dominio.contains(".")
                ? dominio.substring(0, dominio.indexOf(".")).toUpperCase()
                : "Desconocida";

        try{
            java.net.URI uriWhois = java.net.URI.create("https://rdap.org/domain/" + dominio);

            java.net.http.HttpRequest peticionWhois = java.net.http.HttpRequest.newBuilder()
                    .uri(uriWhois)
                    .header("Accept", "application/json")
                    .timeout(java.time.Duration.ofSeconds(3))
                    .GET().build();

            java.net.http.HttpResponse<String> respWhois = cliente.send(peticionWhois, java.net.http.HttpResponse.BodyHandlers.ofString());

            if (respWhois.body() != null && respWhois.statusCode() == 200){
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode root = objectMapper.readTree(respWhois.body());

                JsonNode events = root.path("events");

                if (events.isArray()){
                    for (JsonNode event : events){
                        String action = event.path("eventAction").asText();
                        String date = event.path("eventDate").asText();

                        if ("registration".equals(action) && date.length() >= 4){
                            whoisRegistro = date.substring(0, 4);
                        }
                        if ("expiration".equals(action) && date.length() >= 4){
                            whoisExpira = date.substring(0, 4);
                        }
                    }

                }
            }else {
                whoisRegistro = "Dato Protegido";
                whoisExpira = "Dato Protegido";
            }


        }catch (Exception e){
            System.err.println(e);
            whoisRegistro = "Error";
            whoisExpira = "Error";

        }

        return new ReporteDominio(
                ip, servidor, protocoloUtilizado,
                sslEstado, tlsVersion, sslDiasParaCaducar,
                spfEstado, dmarcEstado, dnssecEstado,
                hstsEstado, cspEstado, xFrameEstado,
                whoisRegistro, whoisExpira, whoisOrganizacion);
    }
}