package de.tcpdumper.notification;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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

    // ── Notifier interface ────────────────────────────────────────────────────

    @Override
    public void send(NotificationType type, String title, String message) throws Exception {
        postEmbed(buildEmbedPayload(type, title, message, false), false);
    }

    @Override
    public String sendAlert(AlertPayload payload) throws Exception {
        JsonObject embedPayload = buildEmbedPayload(
                NotificationType.ALERT,
                "Traffic Alert — " + payload.serverName(),
                payload.toAlertMessage(),
                true);

        if (!mentionTarget.isEmpty()) {
            embedPayload.addProperty("content", mentionTarget);
        }

        String responseBody = postEmbed(embedPayload, true);
        if (responseBody == null) return null;

        try {
            JsonObject responseJson = JsonParser.parseString(responseBody).getAsJsonObject();
            String messageId = responseJson.get("id").getAsString();
            log.info("Alert embed sent — Discord message ID: {}", messageId);
            return messageId;
        } catch (Exception parseException) {
            log.warn("Could not parse Discord message ID from response: {}", responseBody);
            return null;
        }
    }

    @Override
    public void editOrSendResolved(String messageId, ResolvedPayload payload) throws Exception {
        JsonObject embedPayload = buildEmbedPayload(
                NotificationType.SUCCESS,
                "Traffic Alert — " + payload.serverName() + " ✅ Beendet",
                payload.toResolvedMessage(),
                false);

        if (messageId != null) {
            patchEmbed(messageId, embedPayload);
        } else {
            log.debug("No Discord message ID — sending new resolved message.");
            postEmbed(embedPayload, false);
        }
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private String postEmbed(JsonObject payload, boolean waitForResponse) throws Exception {
        String url = waitForResponse ? webhookUrl + "?wait=true" : webhookUrl;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 429) {
            log.warn("Discord rate limited — retrying after {}ms", RATE_LIMIT_RETRY_DELAY_MS);
            Thread.sleep(RATE_LIMIT_RETRY_DELAY_MS);
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        }

        if (response.statusCode() >= 400) {
            log.error("Discord POST failed: {} — {}", response.statusCode(), response.body());
            return null;
        }

        return waitForResponse ? response.body() : null;
    }

    private void patchEmbed(String messageId, JsonObject payload) throws Exception {
        String patchUrl = webhookUrl + "/messages/" + messageId;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(patchUrl))
                .header("Content-Type", "application/json")
                .method("PATCH", HttpRequest.BodyPublishers.ofString(payload.toString()))
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 429) {
            log.warn("Discord rate limited on PATCH — retrying after {}ms", RATE_LIMIT_RETRY_DELAY_MS);
            Thread.sleep(RATE_LIMIT_RETRY_DELAY_MS);
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } else if (response.statusCode() >= 400) {
            log.error("Discord PATCH failed: {} — {} — falling back to new message",
                    response.statusCode(), response.body());
            postEmbed(payload, false);
        } else {
            log.info("Discord alert embed updated in-place (message ID: {})", messageId);
        }
    }

    // ── Embed builder ─────────────────────────────────────────────────────────

    private JsonObject buildEmbedPayload(NotificationType type, String title,
                                         String description, boolean isAlert) {
        JsonObject footer = new JsonObject();
        footer.addProperty("text", "TCP-Dumper");

        JsonObject embed = new JsonObject();
        embed.addProperty("title",       type.getEmoji() + " " + title);
        embed.addProperty("description", description);
        embed.addProperty("color",       type.getColor());
        embed.addProperty("timestamp",   java.time.Instant.now().toString());
        embed.add("footer", footer);

        JsonArray embeds = new JsonArray();
        embeds.add(embed);

        JsonObject payload = new JsonObject();
        payload.addProperty("username", botUsername);
        payload.add("embeds", embeds);

        return payload;
    }
}
