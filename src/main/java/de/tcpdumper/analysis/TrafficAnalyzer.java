package de.tcpdumper.analysis;

import de.tcpdumper.monitor.NloadMonitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class TrafficAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(TrafficAnalyzer.class);

    private final int maxHistory;
    private final Deque<NloadMonitor.TrafficSnapshot> history;
    private final AtomicInteger alertCount = new AtomicInteger(0);
    private double peakIn = 0;
    private double peakOut = 0;

    public TrafficAnalyzer(int maxHistory) {
        this.maxHistory = maxHistory;
        this.history = new ConcurrentLinkedDeque<>();
    }

    public void record(NloadMonitor.TrafficSnapshot snapshot) {
        history.addLast(snapshot);
        while (history.size() > maxHistory) {
            history.pollFirst();
        }

        double inMbits = snapshot.incomingBitsPerSec() / 1_000_000.0;
        double outMbits = snapshot.outgoingBitsPerSec() / 1_000_000.0;
        if (inMbits > peakIn) peakIn = inMbits;
        if (outMbits > peakOut) peakOut = outMbits;
    }

    public void incrementAlerts() {
        alertCount.incrementAndGet();
    }

    public Stats getStats() {
        if (history.isEmpty()) {
            return new Stats(0, 0, 0, 0, peakIn, peakOut, alertCount.get(), Instant.now());
        }

        double sumIn = 0, sumOut = 0;
        for (NloadMonitor.TrafficSnapshot s : history) {
            sumIn += s.incomingBitsPerSec() / 1_000_000.0;
            sumOut += s.outgoingBitsPerSec() / 1_000_000.0;
        }

        int size = history.size();
        NloadMonitor.TrafficSnapshot latest = history.peekLast();

        return new Stats(
                sumIn / size,
                sumOut / size,
                latest != null ? latest.incomingBitsPerSec() / 1_000_000.0 : 0,
                latest != null ? latest.outgoingBitsPerSec() / 1_000_000.0 : 0,
                peakIn,
                peakOut,
                alertCount.get(),
                Instant.now()
        );
    }

    public List<TopTalker> getTopTalkers(int limit) {
        List<TopTalker> talkers = getTopTalkersViaSs();
        if (talkers.isEmpty()) {
            talkers = getTopTalkersViaNetstat();
        }
        return talkers.stream()
                .sorted(Comparator.comparingInt(TopTalker::connections).reversed())
                .limit(limit)
                .toList();
    }

    private List<TopTalker> getTopTalkersViaSs() {
        try {
            ProcessBuilder pb = new ProcessBuilder("bash", "-c",
                    "ss -tn state established 2>/dev/null | awk '{print $5}' | " +
                    "grep -oP '^[\\d.]+' | sort | uniq -c | sort -rn | head -20");
            pb.redirectErrorStream(true);
            Process p = pb.start();

            List<TopTalker> result = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    String[] parts = line.split("\\s+", 2);
                    if (parts.length == 2) {
                        try {
                            int count = Integer.parseInt(parts[0]);
                            result.add(new TopTalker(parts[1], count));
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }

            p.waitFor();
            return result;

        } catch (Exception e) {
            log.debug("ss not available, trying netstat", e);
            return Collections.emptyList();
        }
    }

    private List<TopTalker> getTopTalkersViaNetstat() {
        try {
            ProcessBuilder pb = new ProcessBuilder("bash", "-c",
                    "netstat -tn 2>/dev/null | awk '/ESTABLISHED/{print $5}' | " +
                    "grep -oP '^[\\d.]+' | sort | uniq -c | sort -rn | head -20");
            pb.redirectErrorStream(true);
            Process p = pb.start();

            List<TopTalker> result = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    String[] parts = line.split("\\s+", 2);
                    if (parts.length == 2) {
                        try {
                            int count = Integer.parseInt(parts[0]);
                            result.add(new TopTalker(parts[1], count));
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }

            p.waitFor();
            return result;

        } catch (Exception e) {
            log.debug("netstat also unavailable", e);
            return Collections.emptyList();
        }
    }

    public record Stats(
            double avgInMbits,
            double avgOutMbits,
            double currentInMbits,
            double currentOutMbits,
            double peakInMbits,
            double peakOutMbits,
            int alertCount,
            Instant timestamp
    ) {}

    public record TopTalker(String ip, int connections) {}
}
