package de.tcpdumper.analysis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;

public class PcapAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(PcapAnalyzer.class);

    private PcapAnalyzer() {}

    public static ProtocolStats analyze(Path pcapFile) {
        if (pcapFile == null || !pcapFile.toFile().exists()) {
            log.warn("PcapAnalyzer: file not found — {}", pcapFile);
            return ProtocolStats.EMPTY;
        }

        long tcpPackets  = countPackets(pcapFile, "tcp");
        long udpPackets  = countPackets(pcapFile, "udp");
        long icmpPackets = countPackets(pcapFile, "icmp");

        long totalPackets = countPackets(pcapFile, "");
        long otherPackets = Math.max(0, totalPackets - tcpPackets - udpPackets - icmpPackets);

        log.debug("Pcap analysis — TCP: {}, UDP: {}, ICMP: {}, other: {} (total: {})",
                tcpPackets, udpPackets, icmpPackets, otherPackets, totalPackets);

        return new ProtocolStats(tcpPackets, udpPackets, icmpPackets, otherPackets);
    }

    private static long countPackets(Path pcapFile, String filter) {
        try {
            String command = filter.isEmpty()
                    ? String.format("tcpdump -r %s -nn -q 2>/dev/null | wc -l",
                            pcapFile.toAbsolutePath())
                    : String.format("tcpdump -r %s -nn -q '%s' 2>/dev/null | wc -l",
                            pcapFile.toAbsolutePath(), filter);

            ProcessBuilder processBuilder = new ProcessBuilder("bash", "-c", command);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line = reader.readLine();
                process.waitFor();
                if (line != null) {
                    return Long.parseLong(line.trim());
                }
            }
        } catch (Exception exception) {
            log.debug("Failed to count '{}' packets in {}: {}", filter, pcapFile, exception.getMessage());
        }
        return 0;
    }

    // ── Data types ────────────────────────────────────────────────────────────

    public record ProtocolStats(long tcp, long udp, long icmp, long other) {

        public static final ProtocolStats EMPTY = new ProtocolStats(0, 0, 0, 0);

        public long total() {
            return tcp + udp + icmp + other;
        }

        /** Returns true if at least one packet was counted. */
        public boolean hasData() {
            return total() > 0;
        }

        /** Formats as a compact string, e.g. {@code TCP: 1.234 | UDP: 56 | ICMP: 3 | Sonstige: 2} */
        public String toDisplayString() {
            return String.format("TCP: %s | UDP: %s | ICMP: %s | Sonstige: %s",
                    formatCount(tcp), formatCount(udp), formatCount(icmp), formatCount(other));
        }

        private static String formatCount(long count) {
            if (count >= 1_000_000) return String.format("%.1fM", count / 1_000_000.0);
            if (count >= 1_000)     return String.format("%.1fK", count / 1_000.0);
            return String.valueOf(count);
        }
    }
}
