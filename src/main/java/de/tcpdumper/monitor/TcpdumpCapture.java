package de.tcpdumper.monitor;

import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

public class TcpdumpCapture {

    private static final Logger log = LoggerFactory.getLogger(TcpdumpCapture.class);
    private static final DateTimeFormatter FILE_TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");

    private final AppConfig config;
    private final Path captureDirectory;
    private final Path dumpDirectory;

    private Process activeProcess;
    private Path   activeFile;

    public TcpdumpCapture(AppConfig config) {
        this.config           = config;
        this.captureDirectory = Path.of(config.getCaptureDirectory());
        this.dumpDirectory    = Path.of(config.getDumpDirectory());
        ensureDirectoriesExist();
    }

    private void ensureDirectoriesExist() {
        try {
            Files.createDirectories(captureDirectory);
            Files.createDirectories(dumpDirectory);
            log.info("Capture dir : {}", captureDirectory.toAbsolutePath());
            log.info("Dump dir    : {}", dumpDirectory.toAbsolutePath());
        } catch (IOException ioException) {
            log.error("Cannot create capture/dump directories", ioException);
        }
    }

    // ── Capture control ───────────────────────────────────────────────────────

    public synchronized Path start(String alertId) {
        if (activeProcess != null && activeProcess.isAlive()) {
            log.warn("Capture already running — stopping first.");
            stop();
        }

        String timestamp = LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT);
        activeFile = captureDirectory.resolve(
                String.format("capture_%s_%s.pcap", alertId, timestamp));

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(
                    "tcpdump",
                    "-n", "-nn",
                    "-i", config.getNetworkInterface(),
                    "-s", String.valueOf(config.getSnapLen()),
                    "-w", activeFile.toAbsolutePath().toString(),
                    config.getCaptureFilter()
            );
            // Redirect stderr to stdout so we can log tcpdump errors
            processBuilder.redirectErrorStream(true);
            processBuilder.directory(captureDirectory.toFile());

            activeProcess = processBuilder.start();
            forwardProcessOutputToLog(activeProcess, alertId);

            log.info("[{}] tcpdump started → {}", alertId, activeFile);

        } catch (IOException ioException) {
            log.error("[{}] Failed to start tcpdump: {}", alertId, ioException.getMessage());
        }

        return activeFile;
    }

    /** Stops the active tcpdump capture. Returns the path of the stopped file. */
    public synchronized Path stop() {
        if (activeProcess == null) return null;

        Path completedFile = activeFile;
        try {
            activeProcess.destroy(); // SIGTERM — tcpdump flushes buffers on SIGTERM
            boolean exitedCleanly = activeProcess.waitFor(10, TimeUnit.SECONDS);
            if (!exitedCleanly) {
                log.warn("tcpdump did not exit within 10s — forcing termination.");
                activeProcess.destroyForcibly();
            }
            log.info("tcpdump stopped → {} ({})",
                    completedFile, formatFileSize(completedFile));
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            activeProcess.destroyForcibly();
        } finally {
            activeProcess = null;
            activeFile    = null;
        }
        return completedFile;
    }

    public Path copyToDump(Path completedCapture, String alertId) {
        if (completedCapture == null || !Files.exists(completedCapture)) {
            log.warn("[{}] copyToDump: source file not found — {}", alertId, completedCapture);
            return null;
        }

        String timestamp = LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT);
        Path   dumpTarget = dumpDirectory.resolve(
                String.format("dump_%s_%s.pcap", alertId, timestamp));

        try {
            Files.copy(completedCapture, dumpTarget, StandardCopyOption.REPLACE_EXISTING);
            log.info("[{}] Alert dump saved → {} ({})",
                    alertId, dumpTarget, formatFileSize(dumpTarget));
            return dumpTarget;
        } catch (IOException ioException) {
            log.error("[{}] Failed to write dump to {}: {}", alertId, dumpTarget, ioException.getMessage());
            return null;
        }
    }

    // ── Housekeeping ──────────────────────────────────────────────────────────

    /** Deletes capture files older than {@code maxAgeDays}. Returns number deleted. */
    public int cleanupOld(int maxAgeDays) {
        int deletedCount = 0;
        Instant cutoff   = Instant.now().minus(maxAgeDays, ChronoUnit.DAYS);

        File[] files = captureDirectory.toFile()
                .listFiles((dir, name) -> name.endsWith(".pcap"));
        if (files == null) return 0;

        for (File file : files) {
            if (Instant.ofEpochMilli(file.lastModified()).isBefore(cutoff)) {
                if (file.delete()) {
                    deletedCount++;
                    log.debug("Deleted old capture: {}", file.getName());
                }
            }
        }
        return deletedCount;
    }

    public boolean isRunning() {
        return activeProcess != null && activeProcess.isAlive();
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private void forwardProcessOutputToLog(Process process, String alertId) {
        Thread logThread = new Thread(() -> {
            try (var reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) {
                        log.warn("[{}] tcpdump: {}", alertId, trimmed);
                    }
                }
            } catch (IOException ignored) {}
        }, "tcpdump-logger-" + alertId);
        logThread.setDaemon(true);
        logThread.start();
    }

    private String formatFileSize(Path file) {
        if (file == null || !file.toFile().exists()) return "? B";
        return formatFileSize(file.toFile().length());
    }

    private String formatFileSize(long bytes) {
        if (bytes < 1_024)              return bytes + " B";
        if (bytes < 1_048_576)          return String.format("%.1f KB", bytes / 1_024.0);
        if (bytes < 1_073_741_824)      return String.format("%.1f MB", bytes / 1_048_576.0);
        return                                 String.format("%.2f GB", bytes / 1_073_741_824.0);
    }
}
