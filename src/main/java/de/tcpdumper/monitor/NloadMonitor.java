package de.tcpdumper.monitor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NloadMonitor {

    private static final Logger log = LoggerFactory.getLogger(NloadMonitor.class);

    private final String networkInterface;
    private long lastRxBytes = -1;
    private long lastTxBytes = -1;
    private long lastTimestamp = -1;

    public NloadMonitor(String networkInterface) {
        this.networkInterface = networkInterface;
    }

    public TrafficSnapshot poll() {
        try {
            long[] counters = readProcNetDev();
            if (counters == null) {
                return pollViaNload();
            }

            long rxBytes = counters[0];
            long txBytes = counters[1];
            long now = System.nanoTime();

            if (lastRxBytes < 0) {
                lastRxBytes = rxBytes;
                lastTxBytes = txBytes;
                lastTimestamp = now;
                return null; // Need two data points
            }

            double elapsed = (now - lastTimestamp) / 1_000_000_000.0;
            if (elapsed <= 0) return null;

            double rxBitsPerSec = ((rxBytes - lastRxBytes) * 8.0) / elapsed;
            double txBitsPerSec = ((txBytes - lastTxBytes) * 8.0) / elapsed;

            lastRxBytes = rxBytes;
            lastTxBytes = txBytes;
            lastTimestamp = now;

            if (rxBitsPerSec < 0) rxBitsPerSec = 0;
            if (txBitsPerSec < 0) txBitsPerSec = 0;

            return new TrafficSnapshot(
                    Instant.now(),
                    networkInterface,
                    rxBitsPerSec,
                    txBitsPerSec,
                    rxBytes,
                    txBytes
            );

        } catch (Exception e) {
            log.error("Failed to poll traffic data", e);
            return null;
        }
    }

    private long[] readProcNetDev() {
        try {
            ProcessBuilder pb = new ProcessBuilder("cat", "/proc/net/dev");
            pb.redirectErrorStream(true);
            Process p = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith(networkInterface + ":")) {
                        String[] parts = line.split("[:\\s]+");
                        // Format: iface rx_bytes rx_packets ... tx_bytes tx_packets ...
                        if (parts.length >= 11) {
                            long rxBytes = Long.parseLong(parts[1]);
                            long txBytes = Long.parseLong(parts[9]);
                            return new long[]{rxBytes, txBytes};
                        }
                    }
                }
            }
            p.waitFor();
        } catch (Exception e) {
            log.debug("Could not read /proc/net/dev, falling back to nload", e);
        }
        return null;
    }

    private TrafficSnapshot pollViaNload() {
        try {
            // Use nload -t 1000 -i 1 to get a single snapshot
            ProcessBuilder pb = new ProcessBuilder(
                    "bash", "-c",
                    "nload -t 500 -i 500 " + networkInterface + " 2>/dev/null | head -n 30"
            );
            pb.redirectErrorStream(true);
            Process p = pb.start();

            double inRate = 0;
            double outRate = 0;

            Pattern ratePattern = Pattern.compile("Curr:\\s+([\\d.]+)\\s+(Bit|kBit|MBit|GBit)/s");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                boolean inIncoming = false;
                boolean inOutgoing = false;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("Incoming")) inIncoming = true;
                    if (line.contains("Outgoing")) { inIncoming = false; inOutgoing = true; }

                    Matcher m = ratePattern.matcher(line);
                    if (m.find()) {
                        double val = Double.parseDouble(m.group(1));
                        String unit = m.group(2);
                        double bitsPerSec = toBitsPerSec(val, unit);
                        if (inIncoming && inRate == 0) inRate = bitsPerSec;
                        if (inOutgoing && outRate == 0) outRate = bitsPerSec;
                    }
                }
            }

            p.destroyForcibly();

            return new TrafficSnapshot(
                    Instant.now(), networkInterface,
                    inRate, outRate, 0, 0
            );

        } catch (Exception e) {
            log.error("Failed to poll via nload", e);
            return null;
        }
    }

    private double toBitsPerSec(double value, String unit) {
        return switch (unit) {
            case "Bit" -> value;
            case "kBit" -> value * 1_000;
            case "MBit" -> value * 1_000_000;
            case "GBit" -> value * 1_000_000_000;
            default -> value;
        };
    }


    public record TrafficSnapshot(
            Instant timestamp,
            String iface,
            double incomingBitsPerSec,
            double outgoingBitsPerSec,
            long totalRxBytes,
            long totalTxBytes
    ) {}
}
