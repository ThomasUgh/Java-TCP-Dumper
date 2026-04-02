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

public class DiscordNotifier implements Notifier {

    private static final Logger log = LoggerFactory.getLogger(DiscordNotifier.class);

    private final String webhookUrl;
    private final String username;
    private final String mention;
    private final HttpClient http;

    public DiscordNotifier(AppConfig config) {
        this.webhookUrl = config.getDiscordWebhookUrl();
        this.username = config.getDiscordUsername();
        this.mention = config.getDiscordMention();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Override
    public void send(NotificationType type, String title, String message) throws Exception {
        JsonObject embed = new JsonObject();
        embed.addProperty("title", type.getEmoji() + " " + title);
        embed.addProperty("description", message);
        embed.addProperty("color", type.getColor());
        embed.addProperty("timestamp", java.time.Instant.now().toString());

        JsonObject footer = new JsonObject();
        footer.addProperty("text", "TCPDumper Pro");
        embed.add("footer", footer);

        JsonArray embeds = new JsonArray();
        embeds.add(embed);

        JsonObject payload = new JsonObject();
        payload.addProperty("username", username);
        payload.add("embeds", embeds);

        if (type == NotificationType.ALERT && !mention.isEmpty()) {
            payload.addProperty("content", mention);
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(webhookUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 429) {
            // Rate limited — wait and retry once
            log.warn("Discord rate limited — waiting 2s and retrying");
            Thread.sleep(2000);
            http.send(request, HttpResponse.BodyHandlers.ofString());
        } else if (response.statusCode() >= 400) {
            log.error("Discord webhook failed: {} — {}", response.statusCode(), response.body());
        }
    }
}
