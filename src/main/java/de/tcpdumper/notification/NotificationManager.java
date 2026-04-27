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

    private final List<Notifier>    notifiers;
    private final ExecutorService   dispatchExecutor;
    private final String            serverName;
    private final DateTimeFormatter timestampFormatter;

    public NotificationManager(AppConfig config) {
        this.serverName          = config.getServerName();
        this.timestampFormatter  = buildTimestampFormatter(config.getTimeFormat());
        this.notifiers           = new ArrayList<>();
        this.dispatchExecutor    = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "notifier");
            thread.setDaemon(true);
            return thread;
        });

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

    // ── Public API ────────────────────────────────────────────────────────────

    public void sendStartup(String version, AppConfig config) {
        String message = String.format(
                "🟢 **TCP-Dumper v%s** started on `%s`\n" +
                "Interface: `%s` | Threshold IN: `%.0f Mbit/s` OUT: `%.0f Mbit/s`\n" +
                "Alert delay: `%ds` | Time: %s",
                version, serverName,
                config.getNetworkInterface(),
                config.getThresholdInMbits(),
                config.getThresholdOutMbits(),
                config.getAlertDelaySeconds(),
                currentTimestamp()
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
                "💾 Dump: `%s`\n" +
                "⏰ Time: %s",
                serverName, incomingMbits, outgoingMbits,
                captureFile != null ? captureFile.getFileName() : "N/A",
                dumpFile    != null ? dumpFile.getFileName()    : "N/A",
                currentTimestamp()
        ));

        if (!topTalkers.isEmpty()) {
            messageBuilder.append("\n\n🔍 **Top Talkers:**\n");
            for (int rank = 0; rank < topTalkers.size(); rank++) {
                TrafficAnalyzer.TopTalker talker = topTalkers.get(rank);
                messageBuilder.append(String.format(
                        "%d. `%s` — %d connections\n",
                        rank + 1, talker.ip(), talker.connections()));
            }
        }

        broadcast(NotificationType.ALERT, "Traffic Alert — " + serverName, messageBuilder.toString());
    }

    public void sendResolved(double incomingMbits, double outgoingMbits, Path captureFile) {
        String message = String.format(
                "✅ **Traffic Normalized** on `%s`\n\n" +
                "↓ Incoming: `%.2f Mbit/s`\n" +
                "↑ Outgoing: `%.2f Mbit/s`\n" +
                "📁 Capture saved: `%s`\n" +
                "⏰ Time: %s",
                serverName, incomingMbits, outgoingMbits,
                captureFile != null ? captureFile.getFileName() : "N/A",
                currentTimestamp()
        );
        broadcast(NotificationType.SUCCESS, "Traffic Normalized — " + serverName, message);
    }

    public void sendCaptureRotated(Path newCaptureFile) {
        String message = String.format(
                "🔄 **Capture Rotated** on `%s`\nNew file: `%s`\n⏰ %s",
                serverName, newCaptureFile.getFileName(), currentTimestamp()
        );
        broadcast(NotificationType.INFO, "Capture Rotated", message);
    }

    public void sendStats(TrafficAnalyzer.Stats stats) {
        String message = String.format(
                "📈 **Traffic Report** — `%s`\n\n" +
                "Current: ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Average: ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Peak:    ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Alerts triggered: `%d`\n" +
                "⏰ %s",
                serverName,
                stats.currentInMbits(), stats.currentOutMbits(),
                stats.avgInMbits(),     stats.avgOutMbits(),
                stats.peakInMbits(),    stats.peakOutMbits(),
                stats.alertCount(),
                currentTimestamp()
        );
        broadcast(NotificationType.INFO, "Traffic Report — " + serverName, message);
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private void broadcast(NotificationType type, String title, String message) {
        for (Notifier notifier : notifiers) {
            dispatchExecutor.submit(() -> {
                try {
                    notifier.send(type, title, message);
                } catch (Exception exception) {
                    log.error("Failed to send notification via {}", notifier.getClass().getSimpleName(), exception);
                }
            });
        }
    }

    private String currentTimestamp() {
        return timestampFormatter.format(Instant.now().atZone(ZoneId.systemDefault()));
    }

    /**
     * Builds a timestamp formatter for the configured time format.
     *
     * @param timeFormat {@code "12h"} or {@code "24h"}
     */
    private static DateTimeFormatter buildTimestampFormatter(String timeFormat) {
        String pattern = "12h".equals(timeFormat)
                ? "yyyy-MM-dd hh:mm:ss a z"   // e.g. 2026-04-27 09:37:10 AM UTC
                : "yyyy-MM-dd HH:mm:ss z";     // e.g. 2026-04-27 09:37:10 UTC
        return DateTimeFormatter.ofPattern(pattern);
    }
}
