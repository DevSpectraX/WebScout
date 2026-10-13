package org.example.webscout.model;

public record ReporteDominio (
        //Bloque basico
        String ip,
        String servidorWeb,
        String protocoloUtilizado,

        //Bloque ssl/tls
        String sslEstado,
        String tlsVersion,
        String sslDiasParaCaducar,

        //Bloque dns avanzado
        String spfEstado,
        String dmarcEstado,
        String dnssecEstado,

        //Bloque cabeceras
        String hstsEstado,
        String cspEstado,
        String xFrameEstado,

        //Bloque whois
        String whoisRegistro,
        String whoisExpira,
        String whoisOrganizacion
)
{}
