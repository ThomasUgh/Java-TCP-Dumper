package de.tcpdumper.util;

import de.tcpdumper.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;

public final class SystemCheck {

    private static final Logger log = LoggerFactory.getLogger(SystemCheck.class);

    private SystemCheck() {}

    public static boolean verify(AppConfig config) {
        boolean ok = true;

        // Check tcpdump
        if (!isCommandAvailable("tcpdump")) {
            log.error("✗ tcpdump is not installed. Install with: apt install tcpdump");
            ok = false;
        } else {
            log.info("✓ tcpdump found");
        }

        // Check network interface exists
        if (!interfaceExists(config.getNetworkInterface())) {
            log.error("✗ Network interface '{}' not found. Available: {}",
                    config.getNetworkInterface(), listInterfaces());
            ok = false;
        } else {
            log.info("✓ Interface '{}' found", config.getNetworkInterface());
        }

        // Check /proc/net/dev readable
        if (Files.isReadable(Path.of("/proc/net/dev"))) {
            log.info("✓ /proc/net/dev readable (primary monitoring)");
        } else {
            log.warn("⚠ /proc/net/dev not readable — will try nload fallback");
            if (!isCommandAvailable("nload")) {
                log.error("✗ nload is also not installed. Install with: apt install nload");
                ok = false;
            } else {
                log.info("✓ nload found (fallback)");
            }
        }

        // Check capture directory writable
        Path captureDir = Path.of(config.getCaptureDirectory());
        try {
            Files.createDirectories(captureDir);
            Path testFile = captureDir.resolve(".write-test");
            Files.writeString(testFile, "test");
            Files.delete(testFile);
            log.info("✓ Capture directory writable: {}", captureDir.toAbsolutePath());
        } catch (Exception e) {
            log.error("✗ Capture directory not writable: {}", captureDir.toAbsolutePath());
            ok = false;
        }

        if (!canCapture()) {
            log.warn("⚠ Not running as root. tcpdump may fail without CAP_NET_RAW.");
            log.warn("  Fix: run as root, or: setcap cap_net_raw+eip $(which tcpdump)");
        } else {
            log.info("✓ Capture permissions OK");
        }

        return ok;
    }

    private static boolean isCommandAvailable(String cmd) {
        try {
            Process p = new ProcessBuilder("which", cmd)
                    .redirectErrorStream(true)
                    .start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean interfaceExists(String iface) {
        return Files.exists(Path.of("/sys/class/net/" + iface));
    }

    private static String listInterfaces() {
        try {
            Process p = new ProcessBuilder("ls", "/sys/class/net/")
                    .redirectErrorStream(true)
                    .start();
            return new String(p.getInputStream().readAllBytes()).trim().replace("\n", ", ");
        } catch (Exception e) {
            return "(unknown)";
        }
    }

    private static boolean canCapture() {
        // Quick check: are we root or can tcpdump capture?
        try {
            String uid = new String(
                    new ProcessBuilder("id", "-u").start().getInputStream().readAllBytes()
            ).trim();
            if ("0".equals(uid)) return true;

            // Check if tcpdump has CAP_NET_RAW
            Process p = new ProcessBuilder("bash", "-c",
                    "getcap $(which tcpdump) 2>/dev/null | grep -q cap_net_raw")
                    .start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
