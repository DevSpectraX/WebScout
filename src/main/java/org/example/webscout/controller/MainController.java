package org.example.webscout.controller;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Insets;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import org.example.webscout.model.ReporteDominio;
import org.example.webscout.service.AuditorWeb;

import java.net.URL;
import java.util.ResourceBundle;

public class MainController implements Initializable {

    @FXML
    private Button btnAnalizar;

    @FXML
    private TextField inputUrl;

    @FXML
    private VBox vBoxCripto;

    @FXML
    private VBox vBoxResumen;

    @FXML
    private VBox vBoxSegurWeb;

    private AuditorWeb auditorWeb;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        instances();
        initGUI();
        actions();
    }

    private void instances(){
        this.auditorWeb = new AuditorWeb();
    }


    private void initGUI(){

        layoutTarjeta();
        vBoxResumen.getStyleClass().add("tarjeta-auditoria");
        vBoxSegurWeb.getStyleClass().add("tarjeta-auditoria");
        vBoxCripto.getStyleClass().add("tarjeta-auditoria");

    }

    private void actions(){
        btnAnalizar.setOnAction(event -> analizarUrl());
    }

    private void analizarUrl(){
        String urlOriginal = inputUrl.getText().trim();

        if(urlOriginal.isEmpty()){
            mostrarAlertaError("Campo obligatorio", "Por favor introduce un dominio válido");
            return;
        } buscarDominio(urlOriginal);

    }




    private void buscarDominio(String dominio){
        btnAnalizar.setDisable(true);

        try {

            vBoxResumen.getChildren().clear();
            vBoxCripto.getChildren().clear();
            vBoxSegurWeb.getChildren().clear();

            ReporteDominio reporteDominio = this.auditorWeb.analizar(dominio);

            agregarTituloSeccion(vBoxResumen, "INFRAESTRUCTURA");
            agregarDato(vBoxResumen, "IP Servidor", reporteDominio.ip());
            agregarDato(vBoxResumen, "Servidor Web", reporteDominio.servidorWeb());
            agregarDato(vBoxResumen, "Protocolo", reporteDominio.protocoloUtilizado());

            agregarTituloSeccion(vBoxResumen, "WHOIS");
            agregarDato(vBoxResumen, "Fecha de registro",reporteDominio.whoisRegistro());
            agregarDato(vBoxResumen, "Fecha de expiración",reporteDominio.whoisExpira());
            agregarDato(vBoxResumen, "Organización",reporteDominio.whoisOrganizacion());

            agregarTituloSeccion(vBoxCripto,"SSL / TLS");
            agregarDato(vBoxCripto, "Secure Sockets Layer (SSL)",reporteDominio.sslEstado());
            agregarDato(vBoxCripto, "Transport Layer Security (TLS)",reporteDominio.tlsVersion());
            agregarDato(vBoxCripto, "Dias para caducar",reporteDominio.sslDiasParaCaducar());

            agregarTituloSeccion(vBoxSegurWeb, "CABECERAS");
            agregarDato(vBoxSegurWeb, "HTTP Strict Transport Security",reporteDominio.hstsEstado());
            agregarDato(vBoxSegurWeb, "Content Security Policy",reporteDominio.cspEstado());
            agregarDato(vBoxSegurWeb, "X-FRAME-OPTIONS",reporteDominio.xFrameEstado());

            agregarTituloSeccion(vBoxSegurWeb, "DNS AVANZADO");
            agregarDato(vBoxSegurWeb,"Sender Policy Framework",reporteDominio.spfEstado());
            agregarDato(vBoxSegurWeb,"DMARC",reporteDominio.dmarcEstado());
            agregarDato(vBoxSegurWeb,"DNSSEC",reporteDominio.dnssecEstado());

        }catch (java.net.UnknownHostException e){
            mostrarAlertaError("Error de red", "No se ha podido encontrar el dominio: " + dominio);
        }catch (Exception e){
            mostrarAlertaError("Error inesperado", "Fallo en la petición: " + e.getMessage());

        }finally {
            btnAnalizar.setDisable(false);
            btnAnalizar.setText("Analizar");
        }
    }

    private void mostrarAlertaError(String titulo, String mensaje){

        Alert alertaError = new Alert(Alert.AlertType.ERROR);
        alertaError.setTitle("Error");
        alertaError.setHeaderText(titulo);
        alertaError.setContentText(mensaje);

        alertaError.showAndWait();
    }

    private void agregarDato(VBox contenedor, String clave, String valor){
        Label label  = new Label(clave + " -> " + valor);
        label.getStyleClass().add("dato-label");
        contenedor.getChildren().add(label);

    }

    private void agregarTituloSeccion(VBox contenedor, String titulo){
        Label labelTitulo = new Label(titulo.toUpperCase());
        labelTitulo.getStyleClass().add("titulo-seccion-label");
        contenedor.getChildren().add(labelTitulo);
    }



    private void layoutTarjeta(){

    Insets paddingTarjetas = new Insets(20, 20, 20, 20);
        vBoxCripto.setPadding(paddingTarjetas);
        vBoxResumen.setPadding(paddingTarjetas);
        vBoxSegurWeb.setPadding(paddingTarjetas);

        vBoxCripto.setPrefWidth(350);
        vBoxResumen.setPrefWidth(350);
        vBoxSegurWeb.setPrefWidth(350);

        vBoxCripto.setMinHeight(250);
        vBoxResumen.setMinHeight(250);
        vBoxSegurWeb.setMinHeight(250);

        vBoxCripto.setSpacing(15);
        vBoxResumen.setSpacing(15);
        vBoxSegurWeb.setSpacing(15);
    }
}
