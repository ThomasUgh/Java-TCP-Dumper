package de.tcpdumper.core;

import java.nio.file.Path;

public final class AlertSession {

    public final String alertId;
    public final long startedAtMs;

    public double peakIncomingMbits;
    public double peakOutgoingMbits;
    public String discordMessageId;

    public AlertSession(String alertId, long startedAtMs,
                        double initialIncomingMbits, double initialOutgoingMbits) {
        this.alertId             = alertId;
        this.startedAtMs         = startedAtMs;
        this.peakIncomingMbits   = initialIncomingMbits;
        this.peakOutgoingMbits   = initialOutgoingMbits;
        this.discordMessageId    = null;
    }

    public void updatePeaks(double incomingMbits, double outgoingMbits) {
        if (incomingMbits > peakIncomingMbits) peakIncomingMbits = incomingMbits;
        if (outgoingMbits > peakOutgoingMbits) peakOutgoingMbits = outgoingMbits;
    }

    public long durationSeconds() {
        return (System.currentTimeMillis() - startedAtMs) / 1_000L;
    }
}
