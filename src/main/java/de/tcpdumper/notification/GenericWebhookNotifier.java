package de.tcpdumper.notification;

import com.google.gson.JsonObject;
import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

public class GenericWebhookNotifier implements Notifier {

    private static final Logger log = LoggerFactory.getLogger(GenericWebhookNotifier.class);

    private final String url;
    private final String method;
    private final Map<String, String> customHeaders;
    private final HttpClient http;

    public GenericWebhookNotifier(AppConfig config) {
        this.url = config.getGenericWebhookUrl();
        this.method = config.getGenericWebhookMethod().toUpperCase();
        this.customHeaders = config.getGenericWebhookHeaders();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Override
    public void send(NotificationType type, String title, String message) throws Exception {
        JsonObject payload = new JsonObject();
        payload.addProperty("source", "tcpdumper-pro");
        payload.addProperty("type", type.name().toLowerCase());
        payload.addProperty("title", title);
        payload.addProperty("message", message.replace("**", "").replace("`", ""));
        payload.addProperty("severity", type == NotificationType.ALERT ? "critical" : "info");
        payload.addProperty("timestamp", Instant.now().toString());

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(15));

        // Add custom headers
        for (Map.Entry<String, String> entry : customHeaders.entrySet()) {
            builder.header(entry.getKey(), entry.getValue());
        }

        builder.method(method, HttpRequest.BodyPublishers.ofString(payload.toString()));

        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            log.error("Generic webhook failed: {} — {}", response.statusCode(), response.body());
        }
    }
}
