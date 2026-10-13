module org.example.webscout {
    requires javafx.controls;
    requires javafx.fxml;
    requires tools.jackson.databind;
    requires java.net.http;
    requires java.naming;


    opens org.example.webscout to javafx.fxml;
    exports org.example.webscout;
    exports org.example.webscout.controller;
    opens org.example.webscout.controller to javafx.fxml;
}