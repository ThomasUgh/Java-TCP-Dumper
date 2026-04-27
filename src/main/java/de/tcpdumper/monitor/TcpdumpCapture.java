package de.tcpdumper.monitor;

import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
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
        } catch (IOException ioException) {
            log.error("Cannot create capture/dump directories", ioException);
        }
    }

    // ── Capture control ───────────────────────────────────────────────────────

    /** Starts a new tcpdump capture. Returns the path to the capture file. */
    public synchronized Path start() {
        if (activeProcess != null && activeProcess.isAlive()) {
            log.warn("Capture already running — stopping first.");
            stop();
        }

        String timestamp = LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT);
        activeFile = captureDirectory.resolve("capture_" + timestamp + ".pcap");

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(
                    "tcpdump",
                    "-n", "-nn",
                    "-i", config.getNetworkInterface(),
                    "-s", String.valueOf(config.getSnapLen()),
                    "-C", String.valueOf(config.getMaxCaptureSizeMb()),
                    "-w", activeFile.toAbsolutePath().toString(),
                    config.getCaptureFilter()
            );
            processBuilder.redirectErrorStream(true);
            processBuilder.directory(captureDirectory.toFile());

            activeProcess = processBuilder.start();
            drainProcessOutput(activeProcess);

            log.info("tcpdump started → {}", activeFile);

        } catch (IOException ioException) {
            log.error("Failed to start tcpdump", ioException);
        }

        return activeFile;
    }

    /** Stops the active tcpdump capture. Returns the path of the stopped file. */
    public synchronized Path stop() {
        if (activeProcess == null) return null;

        Path stoppedFile = activeFile;
        try {
            activeProcess.destroy();
            boolean exitedCleanly = activeProcess.waitFor(10, TimeUnit.SECONDS);
            if (!exitedCleanly) {
                log.warn("tcpdump did not exit within 10s — forcing termination.");
                activeProcess.destroyForcibly();
            }
            log.info("tcpdump stopped → {} ({})",
                    stoppedFile, formatFileSize(stoppedFile.toFile().length()));
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            activeProcess.destroyForcibly();
        } finally {
            activeProcess = null;
            activeFile    = null;
        }
        return stoppedFile;
    }

    public synchronized Path writeDump() {
        if (activeFile == null || !Files.exists(activeFile)) {
            log.warn("writeDump() called but no active capture file exists.");
            return null;
        }

        String timestamp  = LocalDateTime.now().format(FILE_TIMESTAMP_FORMAT);
        Path   dumpTarget = dumpDirectory.resolve("dump_" + timestamp + ".pcap");

        try {
            Files.copy(activeFile, dumpTarget, StandardCopyOption.REPLACE_EXISTING);
            log.info("Alert dump written → {} ({})",
                    dumpTarget, formatFileSize(dumpTarget.toFile().length()));
            return dumpTarget;
        } catch (IOException ioException) {
            log.error("Failed to write alert dump to {}", dumpTarget, ioException);
            return null;
        }
    }

    // ── Housekeeping ──────────────────────────────────────────────────────────

    /** Deletes capture files older than {@code maxAgeDays} days. Returns count deleted. */
    public int cleanupOld(int maxAgeDays) {
        int deletedCount = 0;
        Instant cutoffInstant = Instant.now().minus(maxAgeDays, ChronoUnit.DAYS);

        File[] captureFiles = captureDirectory.toFile()
                .listFiles((dir, name) -> name.endsWith(".pcap"));
        if (captureFiles == null) return 0;

        for (File captureFile : captureFiles) {
            Instant lastModifiedInstant = Instant.ofEpochMilli(captureFile.lastModified());
            if (lastModifiedInstant.isBefore(cutoffInstant)) {
                if (captureFile.delete()) {
                    deletedCount++;
                    log.debug("Deleted old capture: {}", captureFile.getName());
                }
            }
        }
        return deletedCount;
    }

    public boolean isRunning() {
        return activeProcess != null && activeProcess.isAlive();
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    /** Drains tcpdump stdout/stderr in a background thread to prevent buffer blocking. */
    private void drainProcessOutput(Process process) {
        Thread drainerThread = new Thread(() -> {
            try (var inputStream = process.getInputStream()) {
                inputStream.transferTo(OutputStream.nullOutputStream());
            } catch (IOException ignored) {}
        }, "tcpdump-drainer");
        drainerThread.setDaemon(true);
        drainerThread.start();
    }

    private String formatFileSize(long bytes) {
        if (bytes < 1_024)              return bytes + " B";
        if (bytes < 1_048_576)          return String.format("%.1f KB", bytes / 1_024.0);
        if (bytes < 1_073_741_824)      return String.format("%.1f MB", bytes / 1_048_576.0);
        return                                 String.format("%.2f GB", bytes / 1_073_741_824.0);
    }
}
