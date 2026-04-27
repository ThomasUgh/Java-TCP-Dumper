package de.tcpdumper.notification;

import de.tcpdumper.analysis.TrafficAnalyzer;
import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NotificationManager {

    private static final Logger log = LoggerFactory.getLogger(NotificationManager.class);
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");

    private final List<Notifier> notifiers = new ArrayList<>();
    private final ExecutorService executor;
    private final String hostname;

    public NotificationManager(AppConfig config) {
        this.executor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "notifier");
            t.setDaemon(true);
            return t;
        });
        this.hostname = resolveHostname();

        if (config.isDiscordEnabled()) {
            notifiers.add(new DiscordNotifier(config));
            log.info("Discord notifications enabled");
        }
        if (config.isTelegramEnabled()) {
            notifiers.add(new TelegramNotifier(config));
            log.info("Telegram notifications enabled");
        }
        if (config.isSlackEnabled()) {
            notifiers.add(new SlackNotifier(config));
            log.info("Slack notifications enabled");
        }
        if (config.isGenericWebhookEnabled()) {
            notifiers.add(new GenericWebhookNotifier(config));
            log.info("Generic webhook notifications enabled");
        }
        if (config.isNtfyEnabled()) {
            notifiers.add(new NtfyNotifier(config));
            log.info("ntfy notifications enabled");
        }

        if (notifiers.isEmpty()) {
            log.warn("No notification channels configured!");
        }
    }

    public void sendStartup(String version, AppConfig config) {
        String message = String.format(
                "🟢 **TCP-Dumper v%s** started on `%s`\n" +
                "Interface: `%s` | Threshold IN: `%.0f Mbit/s` OUT: `%.0f Mbit/s`\n" +
                "Time: %s",
                version, hostname, config.getNetworkInterface(),
                config.getThresholdInMbits(), config.getThresholdOutMbits(),
                now()
        );
        broadcast(NotificationType.INFO, "TCP-Dumper Started", message);
    }

    public void sendShutdown() {
        String message = String.format(
                "🔴 **TCP-Dumper** stopped on `%s` at %s",
                serverName, currentTimestamp()
        );
        broadcast(NotificationType.WARNING, "TCP-Dumper Stopped", message);
    }

    /**
     * Sends a traffic alert notification.
     *
     * @param incomingMbits  current incoming rate in Mbit/s
     * @param outgoingMbits  current outgoing rate in Mbit/s
     * @param captureFile    rolling capture file (may be null)
     * @param dumpFile       alert dump file saved to dump_directory (may be null)
     * @param topTalkers     top-N source IPs by connection count
     */
    public void sendAlert(double incomingMbits, double outgoingMbits,
                          Path captureFile, Path dumpFile,
                          List<TrafficAnalyzer.TopTalker> topTalkers) {

        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append(String.format(
                "🚨 **TRAFFIC ALERT** on `%s`\n\n" +
                "📊 **Current Rates:**\n" +
                "↓ Incoming: `%.2f Mbit/s`\n" +
                "↑ Outgoing: `%.2f Mbit/s`\n\n" +
                "📁 Capture: `%s`\n" +
                "⏰ Time: %s",
                hostname, inMbits, outMbits,
                captureFile != null ? captureFile.getFileName() : "N/A",
                now()
        ));

        if (!topTalkers.isEmpty()) {
            sb.append("\n\n🔍 **Top Talkers:**\n");
            for (int i = 0; i < topTalkers.size(); i++) {
                TrafficAnalyzer.TopTalker t = topTalkers.get(i);
                sb.append(String.format("%d. `%s` — %d connections\n", i + 1, t.ip(), t.connections()));
            }
        }

        broadcast(NotificationType.ALERT, "Traffic Alert — " + hostname, sb.toString());
    }

    public void sendResolved(double inMbits, double outMbits, Path captureFile) {
        String msg = String.format(
                "✅ **Traffic Normalized** on `%s`\n\n" +
                "↓ Incoming: `%.2f Mbit/s`\n" +
                "↑ Outgoing: `%.2f Mbit/s`\n" +
                "📁 Capture saved: `%s`\n" +
                "⏰ Time: %s",
                hostname, inMbits, outMbits,
                captureFile != null ? captureFile.getFileName() : "N/A",
                now()
        );
        broadcast(NotificationType.SUCCESS, "Traffic Normalized — " + hostname, msg);
    }

    public void sendCaptureRotated(Path newFile) {
        String msg = String.format(
                "🔄 **Capture Rotated** on `%s`\nNew file: `%s`\n⏰ %s",
                hostname, newFile.getFileName(), now()
        );
        broadcast(NotificationType.INFO, "Capture Rotated", msg);
    }

    public void sendStats(TrafficAnalyzer.Stats stats) {
        String msg = String.format(
                "📈 **Traffic Report** — `%s`\n\n" +
                "Current: ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Average: ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Peak:    ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Alerts triggered: `%d`\n" +
                "⏰ %s",
                hostname,
                stats.currentInMbits(), stats.currentOutMbits(),
                stats.avgInMbits(), stats.avgOutMbits(),
                stats.peakInMbits(), stats.peakOutMbits(),
                stats.alertCount(),
                now()
        );
        broadcast(NotificationType.INFO, "Traffic Report — " + hostname, msg);
    }

    // ── Internal ──

    private void broadcast(NotificationType type, String title, String message) {
        for (Notifier n : notifiers) {
            executor.submit(() -> {
                try {
                    n.send(type, title, message);
                } catch (Exception e) {
                    log.error("Failed to send notification via {}", n.getClass().getSimpleName(), e);
                }
            });
        }
    }

    private String now() {
        return TIME_FMT.format(Instant.now().atZone(ZoneId.systemDefault()));
    }

    private String resolveHostname() {
        try {
            ProcessBuilder pb = new ProcessBuilder("hostname", "-f");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String result = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return result.isEmpty() ? "unknown" : result;
        } catch (Exception e) {
            return "unknown";
        }
    }
}
