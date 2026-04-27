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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main application class for TCP-Dumper.
 *
 * <p>Orchestrates the monitoring loop, capture lifecycle, and notification dispatch.
 * The alert-delay feature prevents false positives: an alert is only triggered after
 * the threshold has been continuously breached for {@code alert_delay_seconds}.
 */
public class TCPDumper {

    private static final Logger log = LoggerFactory.getLogger(TCPDumper.class);
    private static final String VERSION = "3.0.0";

    private final AppConfig config;
    private final NotificationManager notificationManager;
    private final NloadMonitor nloadMonitor;
    private final TcpdumpCapture tcpdumpCapture;
    private final TrafficAnalyzer trafficAnalyzer;
    private final ScheduledExecutorService scheduler;

    /** True while a capture (and alert state) is active. */
    private final AtomicBoolean isCapturing = new AtomicBoolean(false);

    /** Epoch-ms when the current capture was started. */
    private volatile long captureStartedAtMs = 0;

    /**
     * Epoch-ms when the threshold was first exceeded in the current breach window.
     * Reset to 0 when traffic drops back below threshold.
     */
    private volatile long thresholdFirstBreachedAtMs = 0;

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
        log.info("Monitoring interface '{}' — threshold IN: {} Mbit/s, OUT: {} Mbit/s, alert delay: {}s",
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
        } catch (InterruptedException e) {
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
                log.debug("IN: {} Mbit/s | OUT: {} Mbit/s | capturing: {}",
                        String.format("%.2f", incomingMbits),
                        String.format("%.2f", outgoingMbits),
                        isCapturing.get());
            }

        } catch (Exception exception) {
            log.error("Error in monitoring cycle", exception);
        }
    }

    /**
     * Called every poll cycle while the threshold is breached.
     *
     * <p>If not yet in alert state, starts the alert-delay timer on first breach.
     * The alert (and capture start) fires only after the delay window has elapsed.
     * If already capturing, checks for max-duration rotation.
     */
    private void handleThresholdBreached(double incomingMbits, double outgoingMbits) {
        if (!isCapturing.get()) {
            long nowMs = System.currentTimeMillis();

            if (thresholdFirstBreachedAtMs == 0) {
                // First poll in this breach window — start the delay timer
                thresholdFirstBreachedAtMs = nowMs;
                int delaySeconds = config.getAlertDelaySeconds();
                if (delaySeconds > 0) {
                    log.debug("Threshold breached — waiting {}s before alerting (IN: {} Mbit/s, OUT: {} Mbit/s)",
                            delaySeconds,
                            String.format("%.2f", incomingMbits),
                            String.format("%.2f", outgoingMbits));
                }
                return;
            }

            long millisSinceFirstBreach = nowMs - thresholdFirstBreachedAtMs;
            long alertDelayMs = config.getAlertDelaySeconds() * 1000L;

            if (millisSinceFirstBreach < alertDelayMs) {
                // Still within the delay window — wait
                return;
            }

            // Delay elapsed — fire the alert
            log.warn("⚠ Alert triggered after {}s sustained breach — IN: {} Mbit/s, OUT: {} Mbit/s",
                    config.getAlertDelaySeconds(),
                    String.format("%.2f", incomingMbits),
                    String.format("%.2f", outgoingMbits));

            isCapturing.set(true);
            captureStartedAtMs = System.currentTimeMillis();
            thresholdFirstBreachedAtMs = 0;

            Path captureFile = tcpdumpCapture.start();
            Path dumpFile    = tcpdumpCapture.writeDump();

            notificationManager.sendAlert(incomingMbits, outgoingMbits, captureFile, dumpFile,
                    trafficAnalyzer.getTopTalkers(5));

        } else {
            // Already in alert/capture state — check for max-duration rotation
            long elapsedMs = System.currentTimeMillis() - captureStartedAtMs;
            if (elapsedMs > config.getMaxCaptureDurationSeconds() * 1000L) {
                log.info("Max capture duration reached ({} s) — rotating capture.",
                        config.getMaxCaptureDurationSeconds());
                tcpdumpCapture.stop();
                Path newCaptureFile = tcpdumpCapture.start();
                captureStartedAtMs = System.currentTimeMillis();
                notificationManager.sendCaptureRotated(newCaptureFile);
            }
        }
    }

    /**
     * Called every poll cycle while traffic is below threshold.
     *
     * <p>Resets the alert-delay timer if it was running.
     * Stops the capture once the cooldown window has elapsed.
     */
    private void handleTrafficNormal(double incomingMbits, double outgoingMbits) {
        // Reset breach timer — traffic recovered before the delay elapsed
        if (thresholdFirstBreachedAtMs != 0) {
            log.debug("Traffic dropped below threshold before alert delay elapsed — resetting timer.");
            thresholdFirstBreachedAtMs = 0;
        }

        if (isCapturing.get()) {
            long elapsedMs = System.currentTimeMillis() - captureStartedAtMs;
            if (elapsedMs > config.getCooldownSeconds() * 1000L) {
                log.info("Traffic back to normal — stopping capture.");
                Path stoppedFile = tcpdumpCapture.stop();
                isCapturing.set(false);
                notificationManager.sendResolved(incomingMbits, outgoingMbits, stoppedFile);
            }
        }
    }

    // ── Scheduled tasks ───────────────────────────────────────────────────────

    private void reportPeriodicStats() {
        try {
            TrafficAnalyzer.Stats stats = trafficAnalyzer.getStats();
            notificationManager.sendStats(stats);
            log.info("Stats — Avg IN: {} Mbit/s, Peak IN: {} Mbit/s, Alerts: {}",
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
                log.info("Cleaned up {} old capture file(s).", deletedCount);
            }
        } catch (Exception exception) {
            log.error("Error cleaning up captures", exception);
        }
    }

    // ── CLI ───────────────────────────────────────────────────────────────────

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
