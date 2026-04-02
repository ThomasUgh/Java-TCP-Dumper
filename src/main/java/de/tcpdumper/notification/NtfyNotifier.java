package de.tcpdumper.notification;

import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class NtfyNotifier implements Notifier {

    private static final Logger log = LoggerFactory.getLogger(NtfyNotifier.class);

    private final String baseUrl;
    private final String topic;
    private final String token;
    private final HttpClient http;

    public NtfyNotifier(AppConfig config) {
        this.baseUrl = config.getNtfyUrl().replaceAll("/$", "");
        this.topic = config.getNtfyTopic();
        this.token = config.getNtfyToken();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Override
    public void send(NotificationType type, String title, String message) throws Exception {
        String plainMessage = message.replace("**", "").replace("`", "");
        String priority = type == NotificationType.ALERT ? "urgent" : "default";

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/" + topic))
                .header("Title", title)
                .header("Priority", priority)
                .header("Tags", type == NotificationType.ALERT ? "rotating_light,warning" : "chart_with_upwards_trend")
                .POST(HttpRequest.BodyPublishers.ofString(plainMessage))
                .timeout(Duration.ofSeconds(15));

        if (!token.isEmpty()) {
            builder.header("Authorization", "Bearer " + token);
        }

        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            log.error("ntfy notification failed: {} — {}", response.statusCode(), response.body());
        }
    }
}
