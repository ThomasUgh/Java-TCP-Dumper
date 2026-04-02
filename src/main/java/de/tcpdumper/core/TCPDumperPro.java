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

public class TCPDumperPro {

    private static final Logger log = LoggerFactory.getLogger(TCPDumperPro.class);
    private static final String VERSION = "2.0.0";

    private final AppConfig config;
    private final NotificationManager notifications;
    private final NloadMonitor nloadMonitor;
    private final TcpdumpCapture tcpdumpCapture;
    private final TrafficAnalyzer analyzer;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean capturing = new AtomicBoolean(false);
    private volatile long captureStartedAt = 0;

    public TCPDumperPro(AppConfig config) {
        this.config = config;
        this.notifications = new NotificationManager(config);
        this.nloadMonitor = new NloadMonitor(config.getNetworkInterface());
        this.tcpdumpCapture = new TcpdumpCapture(config);
        this.analyzer = new TrafficAnalyzer(config.getHistorySize());
        this.scheduler = Executors.newScheduledThreadPool(3, r -> {
            Thread t = new Thread(r, "tcpdumper-scheduler");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() {
        printBanner();

        if (!SystemCheck.verify(config)) {
            log.error("System check failed — aborting.");
            System.exit(1);
        }

        notifications.sendStartup(VERSION, config);
        log.info("Monitoring interface '{}' — threshold IN: {} Mbit/s, OUT: {} Mbit/s",
                config.getNetworkInterface(),
                config.getThresholdInMbits(),
                config.getThresholdOutMbits());

        scheduler.scheduleAtFixedRate(this::monitorCycle,
                0, config.getPollIntervalSeconds(), TimeUnit.SECONDS);

        if (config.getStatsIntervalMinutes() > 0) {
            scheduler.scheduleAtFixedRate(this::reportStats,
                    config.getStatsIntervalMinutes(), config.getStatsIntervalMinutes(), TimeUnit.MINUTES);
        }

        if (config.getMaxCaptureAgeDays() > 0) {
            scheduler.scheduleAtFixedRate(this::cleanupOldCaptures,
                    1, 60, TimeUnit.MINUTES);
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down TCPDumper Pro...");
            scheduler.shutdownNow();
            if (capturing.get()) {
                tcpdumpCapture.stop();
            }
            notifications.sendShutdown();
        }));

        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void monitorCycle() {
        try {
            NloadMonitor.TrafficSnapshot snapshot = nloadMonitor.poll();
            if (snapshot == null) {
                return;
            }

            analyzer.record(snapshot);

            double inMbits = snapshot.incomingBitsPerSec() / 1_000_000.0;
            double outMbits = snapshot.outgoingBitsPerSec() / 1_000_000.0;

            boolean thresholdBreached =
                    inMbits >= config.getThresholdInMbits() ||
                    outMbits >= config.getThresholdOutMbits();

            if (thresholdBreached && !capturing.get()) {
                log.warn("⚠ Threshold breached! IN: {} Mbit/s, OUT: {} Mbit/s — starting capture",
                        String.format("%.2f", inMbits), String.format("%.2f", outMbits));
                capturing.set(true);
                captureStartedAt = System.currentTimeMillis();

                Path captureFile = tcpdumpCapture.start();
                notifications.sendAlert(inMbits, outMbits, captureFile, analyzer.getTopTalkers(5));

            } else if (thresholdBreached && capturing.get()) {
                // Already capturing — check max capture duration
                long elapsed = System.currentTimeMillis() - captureStartedAt;
                if (elapsed > config.getMaxCaptureDurationSeconds() * 1000L) {
                    log.info("Max capture duration reached ({} s) — rotating capture.",
                            config.getMaxCaptureDurationSeconds());
                    tcpdumpCapture.stop();
                    Path captureFile = tcpdumpCapture.start();
                    captureStartedAt = System.currentTimeMillis();
                    notifications.sendCaptureRotated(captureFile);
                }

            } else if (!thresholdBreached && capturing.get()) {
                long elapsed = System.currentTimeMillis() - captureStartedAt;
                if (elapsed > config.getCooldownSeconds() * 1000L) {
                    log.info("Traffic back to normal — stopping capture.");
                    Path stoppedFile = tcpdumpCapture.stop();
                    capturing.set(false);
                    notifications.sendResolved(inMbits, outMbits, stoppedFile);
                }
            }

            if (config.isVerbose()) {
                log.debug("IN: {} Mbit/s | OUT: {} Mbit/s | Capturing: {}",
                        String.format("%.2f", inMbits), String.format("%.2f", outMbits), capturing.get());
            }

        } catch (Exception e) {
            log.error("Error in monitoring cycle", e);
        }
    }

    private void reportStats() {
        try {
            TrafficAnalyzer.Stats stats = analyzer.getStats();
            notifications.sendStats(stats);
            log.info("Stats — Avg IN: {} Mbit/s, Peak IN: {} Mbit/s, Alerts: {}",
                    String.format("%.2f", stats.avgInMbits()), String.format("%.2f", stats.peakInMbits()), stats.alertCount());
        } catch (Exception e) {
            log.error("Error sending stats", e);
        }
    }

    private void cleanupOldCaptures() {
        try {
            int deleted = tcpdumpCapture.cleanupOld(config.getMaxCaptureAgeDays());
            if (deleted > 0) {
                log.info("Cleaned up {} old capture files.", deleted);
            }
        } catch (Exception e) {
            log.error("Error cleaning up captures", e);
        }
    }

    private void printBanner() {
        System.out.println("""
                ╔══════════════════════════════════════╗
                ║       TCPDumper Pro v%s          ║
                ║  Advanced Network Traffic Monitor    ║
                ╚══════════════════════════════════════╝
                """.formatted(VERSION));
    }


    public static void main(String[] args) {
        String configPath = "config.yml";

        for (int i = 0; i < args.length; i++) {
            if (("--config".equals(args[i]) || "-c".equals(args[i])) && i + 1 < args.length) {
                configPath = args[++i];
            }
            if ("--version".equals(args[i]) || "-v".equals(args[i])) {
                System.out.println("TCPDumper Pro v" + VERSION);
                return;
            }
            if ("--help".equals(args[i]) || "-h".equals(args[i])) {
                printHelp();
                return;
            }
        }

        try {
            AppConfig config = AppConfig.load(Path.of(configPath));
            new TCPDumperPro(config).start();
        } catch (Exception e) {
            log.error("Failed to start TCPDumper Pro", e);
            System.exit(1);
        }
    }

    private static void printHelp() {
        System.out.println("""
                Usage: java -jar tcpdumper-pro.jar [options]
                
                Options:
                  -c, --config <path>   Path to config.yml (default: ./config.yml)
                  -v, --version         Print version and exit
                  -h, --help            Show this help message
                """);
    }
}
