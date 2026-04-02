package de.tcpdumper.monitor;

import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

public class TcpdumpCapture {

    private static final Logger log = LoggerFactory.getLogger(TcpdumpCapture.class);
    private static final DateTimeFormatter FILE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");

    private final AppConfig config;
    private final Path captureDir;
    private Process currentProcess;
    private Path currentFile;

    public TcpdumpCapture(AppConfig config) {
        this.config = config;
        this.captureDir = Path.of(config.getCaptureDir());
        ensureCaptureDir();
    }

    private void ensureCaptureDir() {
        try {
            Files.createDirectories(captureDir);
        } catch (IOException e) {
            log.error("Cannot create capture directory: {}", captureDir, e);
        }
    }

    public synchronized Path start() {
        if (currentProcess != null && currentProcess.isAlive()) {
            log.warn("Capture already running — stopping first.");
            stop();
        }

        String timestamp = LocalDateTime.now().format(FILE_FMT);
        currentFile = captureDir.resolve("capture_" + timestamp + ".pcap");

        try {
            ProcessBuilder pb = new ProcessBuilder();

            pb.command(
                    "tcpdump",
                    "-n", "-nn",
                    "-i", config.getNetworkInterface(),
                    "-s", String.valueOf(config.getSnapLen()),
                    "-C", String.valueOf(config.getMaxCaptureSizeMB()),
                    "-w", currentFile.toAbsolutePath().toString(),
                    config.getCaptureFilter()
            );

            pb.redirectErrorStream(true);
            pb.directory(captureDir.toFile());

            currentProcess = pb.start();

            // Drain stdout/stderr in background to prevent buffer blocking
            Thread drainer = new Thread(() -> {
                try (var is = currentProcess.getInputStream()) {
                    is.transferTo(java.io.OutputStream.nullOutputStream());
                } catch (IOException ignored) {}
            }, "tcpdump-drainer");
            drainer.setDaemon(true);
            drainer.start();

            log.info("tcpdump started → {}", currentFile);
            return currentFile;

        } catch (IOException e) {
            log.error("Failed to start tcpdump", e);
            return currentFile;
        }
    }

    public synchronized Path stop() {
        if (currentProcess == null) return null;

        Path file = currentFile;
        try {
            // Send SIGTERM for graceful shutdown (flushes buffers)
            currentProcess.destroy();
            boolean exited = currentProcess.waitFor(10, TimeUnit.SECONDS);
            if (!exited) {
                log.warn("tcpdump did not exit in time — forcing.");
                currentProcess.destroyForcibly();
            }
            log.info("tcpdump stopped → {} ({})",
                    file, humanSize(file.toFile().length()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            currentProcess.destroyForcibly();
        } finally {
            currentProcess = null;
            currentFile = null;
        }
        return file;
    }

    public int cleanupOld(int maxAgeDays) {
        int deleted = 0;
        Instant cutoff = Instant.now().minus(maxAgeDays, ChronoUnit.DAYS);

        File[] files = captureDir.toFile().listFiles((dir, name) -> name.endsWith(".pcap"));
        if (files == null) return 0;

        for (File f : files) {
            Instant lastMod = Instant.ofEpochMilli(f.lastModified());
            if (lastMod.isBefore(cutoff)) {
                if (f.delete()) {
                    deleted++;
                    log.debug("Deleted old capture: {}", f.getName());
                }
            }
        }
        return deleted;
    }

    public boolean isRunning() {
        return currentProcess != null && currentProcess.isAlive();
    }

    private String humanSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }
}
