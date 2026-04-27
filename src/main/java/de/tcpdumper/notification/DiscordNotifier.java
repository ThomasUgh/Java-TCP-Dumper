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
    private static final int    RATE_LIMIT_RETRY_DELAY_MS = 2_000;

    private final String     webhookUrl;
    private final String     botUsername;
    private final String     mentionTarget;
    private final HttpClient httpClient;

    public DiscordNotifier(AppConfig config) {
        this.webhookUrl    = config.getDiscordWebhookUrl();
        this.botUsername   = config.getDiscordUsername();
        this.mentionTarget = config.getDiscordMention();
        this.httpClient    = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Override
    public void send(NotificationType type, String title, String message) throws Exception {
        JsonObject footer = new JsonObject();
        footer.addProperty("text", "TCP-Dumper");

        JsonObject embed = new JsonObject();
        embed.addProperty("title",       type.getEmoji() + " " + title);
        embed.addProperty("description", message);
        embed.addProperty("color",       type.getColor());
        embed.addProperty("timestamp",   java.time.Instant.now().toString());
        embed.add("footer", footer);

        JsonArray embeds = new JsonArray();
        embeds.add(embed);

        JsonObject payload = new JsonObject();
        payload.addProperty("username", botUsername);
        payload.add("embeds", embeds);

        if (type == NotificationType.ALERT && !mentionTarget.isEmpty()) {
            payload.addProperty("content", mentionTarget);
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(webhookUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 429) {
            log.warn("Discord rate limited — retrying after {}ms", RATE_LIMIT_RETRY_DELAY_MS);
            Thread.sleep(RATE_LIMIT_RETRY_DELAY_MS);
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } else if (response.statusCode() >= 400) {
            log.error("Discord webhook failed: {} — {}", response.statusCode(), response.body());
        }
    }
}
