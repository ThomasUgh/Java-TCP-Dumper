package de.tcpdumper.notification;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class SlackNotifier implements Notifier {

    private static final Logger log = LoggerFactory.getLogger(SlackNotifier.class);

    private final String webhookUrl;
    private final HttpClient http;

    public SlackNotifier(AppConfig config) {
        this.webhookUrl = config.getSlackWebhookUrl();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Override
    public void send(NotificationType type, String title, String message) throws Exception {
        // Convert markdown to Slack mrkdwn (** → *, ` stays)
        String slackMsg = message.replace("**", "*");

        JsonObject section = new JsonObject();
        section.addProperty("type", "section");
        JsonObject text = new JsonObject();
        text.addProperty("type", "mrkdwn");
        text.addProperty("text", type.getEmoji() + " *" + title + "*\n\n" + slackMsg);
        section.add("text", text);

        JsonArray blocks = new JsonArray();
        blocks.add(section);

        JsonObject payload = new JsonObject();
        payload.add("blocks", blocks);
        payload.addProperty("text", title); // Fallback for notifications

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(webhookUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            log.error("Slack webhook failed: {} — {}", response.statusCode(), response.body());
        }
    }
}
