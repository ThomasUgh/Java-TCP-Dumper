package de.tcpdumper.core;

import de.tcpdumper.config.AppConfig;
import de.tcpdumper.monitor.NloadMonitor;
import de.tcpdumper.monitor.TcpdumpCapture;
import de.tcpdumper.notification.NotificationManager;
import de.tcpdumper.analysis.TrafficAnalyzer;
import de.tcpdumper.util.SystemCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class TCPDumper {

    private static final Logger log = LoggerFactory.getLogger(TCPDumper.class);
    private static final String VERSION = "3.0.0";

    private final AppConfig               config;
    private final NotificationManager     notificationManager;
    private final NloadMonitor            nloadMonitor;
    private final TcpdumpCapture          tcpdumpCapture;
    private final TrafficAnalyzer         trafficAnalyzer;
    private final ScheduledExecutorService scheduler;

    private volatile AlertSession activeAlertSession;
    private volatile long thresholdFirstBreachedAtMs = 0;
    private final AtomicBoolean isCapturing = new AtomicBoolean(false);
    private volatile long captureStartedAtMs = 0;

    public TCPDumper(AppConfig config) {
        this.config = config;
        this.notificationManager = new NotificationManager(config);
        this.nloadMonitor = new NloadMonitor(config.getNetworkInterface());
        this.tcpdumpCapture = new TcpdumpCapture(config);
        this.trafficAnalyzer = new TrafficAnalyzer(config.getHistorySize());
        this.scheduler = Executors.newScheduledThreadPool(3, runnable -> {
            Thread thread = new Thread(runnable, "tcpdumper-scheduler");
            thread.setDaemon(true);
            return thread;
        });
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() {
        printBanner();

        if (!SystemCheck.verify(config)) {
            log.error("System check failed — aborting.");
            System.exit(1);
        }

        notificationManager.sendStartup(VERSION, config);
        log.info("Monitoring '{}' — threshold IN: {} Mbit/s, OUT: {} Mbit/s, alert delay: {}s",
                config.getNetworkInterface(),
                config.getThresholdInMbits(),
                config.getThresholdOutMbits(),
                config.getAlertDelaySeconds());

        scheduler.scheduleAtFixedRate(
                this::runMonitorCycle,
                0, config.getPollIntervalSeconds(), TimeUnit.SECONDS);

        if (config.getStatsIntervalMinutes() > 0) {
            scheduler.scheduleAtFixedRate(
                    this::reportPeriodicStats,
                    config.getStatsIntervalMinutes(), config.getStatsIntervalMinutes(), TimeUnit.MINUTES);
        }

        if (config.getMaxCaptureAgeDays() > 0) {
            scheduler.scheduleAtFixedRate(this::cleanupOldCaptures, 1, 60, TimeUnit.MINUTES);
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down TCP-Dumper...");
            scheduler.shutdownNow();
            if (isCapturing.get()) {
                tcpdumpCapture.stop();
            }
            notificationManager.sendShutdown();
        }));

        try {
            Thread.currentThread().join();
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    // ── Monitor cycle ─────────────────────────────────────────────────────────

    private void runMonitorCycle() {
        try {
            NloadMonitor.TrafficSnapshot snapshot = nloadMonitor.poll();
            if (snapshot == null) return;

            trafficAnalyzer.record(snapshot);

            double incomingMbits  = snapshot.incomingBitsPerSec() / 1_000_000.0;
            double outgoingMbits  = snapshot.outgoingBitsPerSec() / 1_000_000.0;
            boolean thresholdBreached =
                    incomingMbits >= config.getThresholdInMbits() ||
                    outgoingMbits >= config.getThresholdOutMbits();

            if (thresholdBreached) {
                handleThresholdBreached(incomingMbits, outgoingMbits);
            } else {
                handleTrafficNormal(incomingMbits, outgoingMbits);
            }

            if (config.isVerbose()) {
                log.debug("IN: {} | OUT: {} Mbit/s | alert: {} | capturing: {}",
                        String.format("%.2f", incomingMbits),
                        String.format("%.2f", outgoingMbits),
                        activeAlertSession != null,
                        isCapturing.get());
            }

        } catch (Exception exception) {
            log.error("Error in monitoring cycle", exception);
        }
    }

    private void handleThresholdBreached(double incomingMbits, double outgoingMbits) {
        // If already in alert state, just update peaks and check rotation
        if (activeAlertSession != null) {
            activeAlertSession.updatePeaks(incomingMbits, outgoingMbits);

            long captureElapsedMs = System.currentTimeMillis() - captureStartedAtMs;
            if (captureElapsedMs > config.getMaxCaptureDurationSeconds() * 1_000L) {
                log.info("[{}] Max capture duration — rotating.",
                        activeAlertSession.alertId);
                tcpdumpCapture.stop();
                Path newCaptureFile = tcpdumpCapture.start(activeAlertSession.alertId);
                captureStartedAtMs = System.currentTimeMillis();
                notificationManager.sendCaptureRotated(newCaptureFile);
            }
            return;
        }

        // Not yet in alert state — manage delay timer
        long nowMs = System.currentTimeMillis();
        if (thresholdFirstBreachedAtMs == 0) {
            thresholdFirstBreachedAtMs = nowMs;
            int delaySeconds = config.getAlertDelaySeconds();
            if (delaySeconds > 0) {
                log.debug("Threshold breached — waiting {}s before alerting.", delaySeconds);
            }
            return;
        }

        long millisSinceFirstBreach = nowMs - thresholdFirstBreachedAtMs;
        if (millisSinceFirstBreach < config.getAlertDelaySeconds() * 1_000L) {
            return; // Still within delay window
        }

        // Delay elapsed — fire the alert
        String alertId = generateAlertId();
        log.warn("[{}] Alert fired after {}s sustained breach — IN: {} Mbit/s, OUT: {} Mbit/s",
                alertId, config.getAlertDelaySeconds(),
                String.format("%.2f", incomingMbits),
                String.format("%.2f", outgoingMbits));

        activeAlertSession      = new AlertSession(alertId, System.currentTimeMillis(),
                incomingMbits, outgoingMbits);
        thresholdFirstBreachedAtMs = 0;
        isCapturing.set(true);
        captureStartedAtMs = System.currentTimeMillis();

        Path captureFile = tcpdumpCapture.start(alertId);

        notificationManager.sendAlert(
                alertId,
                incomingMbits, outgoingMbits,
                captureFile,
                trafficAnalyzer.getTopTalkers(5));

        trafficAnalyzer.incrementAlerts();
    }

    /**
     * Called every poll cycle while traffic is below threshold.
     *
     * <p>Resets the alert-delay timer if it was running.
     * Stops the capture once the cooldown window has elapsed.
     */
    private void handleTrafficNormal(double incomingMbits, double outgoingMbits) {
        if (thresholdFirstBreachedAtMs != 0) {
            log.debug("Traffic recovered before alert delay elapsed — resetting timer.");
            thresholdFirstBreachedAtMs = 0;
        }

        if (activeAlertSession == null || !isCapturing.get()) return;

        long captureElapsedMs = System.currentTimeMillis() - captureStartedAtMs;
        if (captureElapsedMs <= config.getCooldownSeconds() * 1_000L) {
            return; // Still within cooldown
        }

        // Cooldown elapsed — resolve the alert
        AlertSession resolvedSession = activeAlertSession;
        log.info("[{}] Traffic normalised — stopping capture and resolving alert.",
                resolvedSession.alertId);

        Path completedCapture = tcpdumpCapture.stop();
        isCapturing.set(false);

        // Copy completed capture → dump directory (after stop, so file is fully flushed)
        Path dumpFile = tcpdumpCapture.copyToDump(completedCapture, resolvedSession.alertId);

        activeAlertSession = null;

        notificationManager.sendResolved(
                resolvedSession.alertId,
                resolvedSession.peakIncomingMbits,
                resolvedSession.peakOutgoingMbits,
                incomingMbits,
                outgoingMbits,
                resolvedSession.durationSeconds(),
                completedCapture,
                dumpFile);
    }

    // ── Scheduled tasks ───────────────────────────────────────────────────────

    private void reportPeriodicStats() {
        try {
            TrafficAnalyzer.Stats stats = trafficAnalyzer.getStats();
            notificationManager.sendStats(stats);
            log.info("Stats — Ø IN: {} Mbit/s | Peak IN: {} Mbit/s | Alerts: {}",
                    String.format("%.2f", stats.avgInMbits()),
                    String.format("%.2f", stats.peakInMbits()),
                    stats.alertCount());
        } catch (Exception exception) {
            log.error("Error sending stats", exception);
        }
    }

    private void cleanupOldCaptures() {
        try {
            int deletedCount = tcpdumpCapture.cleanupOld(config.getMaxCaptureAgeDays());
            if (deletedCount > 0) {
                log.info("Deleted {} old capture file(s).", deletedCount);
            }
        } catch (Exception exception) {
            log.error("Error cleaning up captures", exception);
        }
    }

    // ── CLI ───────────────────────────────────────────────────────────────────
    private static String generateAlertId() {
        return UUID.randomUUID().toString()
                .replace("-", "")
                .substring(0, 8)
                .toUpperCase();
    }

    private void printBanner() {
        System.out.println("""
                ╔══════════════════════════════════════╗
                ║         TCP-Dumper  v%s           ║
                ║  Advanced Network Traffic Monitor    ║
                ╚══════════════════════════════════════╝
                """.formatted(VERSION));
    }

    public static void main(String[] args) {
        String configPath = "config.yml";

        for (int index = 0; index < args.length; index++) {
            if (("--config".equals(args[index]) || "-c".equals(args[index])) && index + 1 < args.length) {
                configPath = args[++index];
            }
            if ("--version".equals(args[index]) || "-v".equals(args[index])) {
                System.out.println("TCP-Dumper v" + VERSION);
                return;
            }
            if ("--help".equals(args[index]) || "-h".equals(args[index])) {
                printHelp();
                return;
            }
        }

        try {
            AppConfig config = AppConfig.load(Path.of(configPath));
            new TCPDumper(config).start();
        } catch (Exception exception) {
            LoggerFactory.getLogger(TCPDumper.class).error("Failed to start TCP-Dumper", exception);
            System.exit(1);
        }
    }

    private static void printHelp() {
        System.out.println("""
                Usage: java -jar tcp-dumper.jar [options]

                Options:
                  -c, --config <path>   Path to config.yml (default: ./config.yml)
                  -v, --version         Print version and exit
                  -h, --help            Show this help message
                """);
    }
}
