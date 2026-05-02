package de.tcpdumper.notification;

import de.tcpdumper.analysis.PcapAnalyzer;
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
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NotificationManager {

    private static final Logger log = LoggerFactory.getLogger(NotificationManager.class);

    private static final DateTimeFormatter TIMESTAMP_24H = DateTimeFormatter
            .ofPattern("dd. MMMM yyyy, HH:mm 'Uhr'", Locale.GERMAN);
    private static final DateTimeFormatter TIMESTAMP_12H = DateTimeFormatter
            .ofPattern("dd. MMMM yyyy, hh:mm a", Locale.GERMAN);

    private final List<Notifier>    notifiers;
    private final ExecutorService   dispatchExecutor;
    private final String            serverName;
    private final DateTimeFormatter timestampFormatter;

    /** Discord message IDs from the last sendAlert call, indexed parallel to {@code notifiers}. */
    private final List<String> lastAlertMessageIds = new ArrayList<>();

    public NotificationManager(AppConfig config) {
        this.serverName         = config.getServerName();
        this.timestampFormatter = "12h".equals(config.getTimeFormat()) ? TIMESTAMP_12H : TIMESTAMP_24H;
        this.notifiers          = new ArrayList<>();
        this.dispatchExecutor   = Executors.newFixedThreadPool(2, runnable -> {
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
                "🟢 **TCP-Dumper v%s** gestartet auf `%s`\n" +
                "Interface: `%s` | Schwelle ↓ `%.0f` ↑ `%.0f` Mbit/s\n" +
                "Alert-Verzögerung: `%ds` | Zeit: %s",
                version, serverName,
                config.getNetworkInterface(),
                config.getThresholdInMbits(),
                config.getThresholdOutMbits(),
                config.getAlertDelaySeconds(),
                now());
        broadcast(NotificationType.INFO, "TCP-Dumper gestartet", message);
    }

    public void sendShutdown() {
        String message = String.format(
                "🔴 **TCP-Dumper** gestoppt auf `%s` um %s",
                serverName, now());
        broadcast(NotificationType.WARNING, "TCP-Dumper gestoppt", message);
    }

    public void sendAlert(String alertId,
                          double incomingMbits,
                          double outgoingMbits,
                          Path captureFile,
                          List<TrafficAnalyzer.TopTalker> topTalkers) {

        Notifier.AlertPayload payload = new Notifier.AlertPayload(
                alertId, serverName,
                incomingMbits, outgoingMbits,
                captureFile, topTalkers,
                now());

        lastAlertMessageIds.clear();
        for (int i = 0; i < notifiers.size(); i++) lastAlertMessageIds.add(null);

        for (int index = 0; index < notifiers.size(); index++) {
            Notifier notifier = notifiers.get(index);
            try {
                String messageId = notifier.sendAlert(payload);
                lastAlertMessageIds.set(index, messageId);
            } catch (Exception exception) {
                log.error("Alert send failed via {}: {}",
                        notifier.getClass().getSimpleName(), exception.getMessage());
            }
        }
    }

    public void sendResolved(String alertId,
                             double maxIncomingMbits,
                             double maxOutgoingMbits,
                             double currentIncomingMbits,
                             double currentOutgoingMbits,
                             long   durationSeconds,
                             Path   captureFile,
                             Path   dumpFile) {

        // Analyse the completed dump for protocol breakdown
        Path analysisTarget = dumpFile != null ? dumpFile : captureFile;
        PcapAnalyzer.ProtocolStats stats = PcapAnalyzer.analyze(analysisTarget);
        String protocolStatsDisplay = stats.hasData() ? stats.toDisplayString() : "";

        Notifier.ResolvedPayload payload = new Notifier.ResolvedPayload(
                alertId, serverName,
                maxIncomingMbits, maxOutgoingMbits,
                currentIncomingMbits, currentOutgoingMbits,
                durationSeconds,
                captureFile, dumpFile,
                protocolStatsDisplay,
                now());

        for (int index = 0; index < notifiers.size(); index++) {
            Notifier notifier  = notifiers.get(index);
            String   messageId = index < lastAlertMessageIds.size()
                    ? lastAlertMessageIds.get(index) : null;
            try {
                notifier.editOrSendResolved(messageId, payload);
            } catch (Exception exception) {
                log.error("Resolved send failed via {}: {}",
                        notifier.getClass().getSimpleName(), exception.getMessage());
            }
        }
    }

    public void sendCaptureRotated(Path newCaptureFile) {
        String message = String.format(
                "🔄 **Capture rotiert** auf `%s`\nNeue Datei: `%s`\n⏰ %s",
                serverName, newCaptureFile.getFileName(), now());
        broadcast(NotificationType.INFO, "Capture rotiert", message);
    }

    public void sendStats(TrafficAnalyzer.Stats stats) {
        String message = String.format(
                "📈 **Traffic-Report** — `%s`\n\n" +
                "Aktuell:    ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Durchschn.: ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Spitze:     ↓ `%.2f` / ↑ `%.2f` Mbit/s\n" +
                "Alerts gesamt: `%d`\n" +
                "⏰ %s",
                serverName,
                stats.currentInMbits(),  stats.currentOutMbits(),
                stats.avgInMbits(),      stats.avgOutMbits(),
                stats.peakInMbits(),     stats.peakOutMbits(),
                stats.alertCount(),
                now());
        broadcast(NotificationType.INFO, "Traffic-Report — " + serverName, message);
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private void broadcast(NotificationType type, String title, String message) {
        for (Notifier notifier : notifiers) {
            dispatchExecutor.submit(() -> {
                try {
                    notifier.send(type, title, message);
                } catch (Exception exception) {
                    log.error("Notification failed via {}: {}",
                            notifier.getClass().getSimpleName(), exception.getMessage());
                }
            });
        }
    }

    private String now() {
        return timestampFormatter.format(Instant.now().atZone(ZoneId.systemDefault()));
    }
}
