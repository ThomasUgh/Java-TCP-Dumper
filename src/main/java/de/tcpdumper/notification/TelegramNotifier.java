package de.tcpdumper.notification;

import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

public class TelegramNotifier implements Notifier {

    private static final Logger log = LoggerFactory.getLogger(TelegramNotifier.class);

    private final String botToken;
    private final String chatId;
    private final HttpClient http;

    public TelegramNotifier(AppConfig config) {
        this.botToken = config.getTelegramBotToken();
        this.chatId = config.getTelegramChatId();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Override
    public void send(NotificationType type, String title, String message) throws Exception {
        String htmlMessage = message
                .replace("**", "")  // strip markdown bold
                .replace("`", "<code>")
                .replace("</code>", "</code>"); // basic conversion


        String plainText = type.getEmoji() + " " + title + "\n\n" +
                message.replace("**", "").replace("`", "");

        String encodedText = URLEncoder.encode(plainText, StandardCharsets.UTF_8);
        String url = String.format(
                "https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=",
                botToken, chatId, encodedText
        );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            log.error("Telegram notification failed: {} — {}", response.statusCode(), response.body());
        }
    }
}
