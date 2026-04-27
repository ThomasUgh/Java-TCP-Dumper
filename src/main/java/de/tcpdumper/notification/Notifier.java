package de.tcpdumper.notification;

import de.tcpdumper.analysis.PcapAnalyzer;
import de.tcpdumper.analysis.TrafficAnalyzer;

import java.nio.file.Path;
import java.util.List;

public interface Notifier {

    void send(NotificationType type, String title, String message) throws Exception;

    default String sendAlert(AlertPayload payload) throws Exception {
        send(NotificationType.ALERT,
                "Traffic Alert — " + payload.serverName(),
                payload.toAlertMessage());
        return null; // no message ID — will send a new message on resolve
    }

    default void editOrSendResolved(String messageId, ResolvedPayload payload) throws Exception {
        send(NotificationType.SUCCESS,
                "Traffic Normalized — " + payload.serverName(),
                payload.toResolvedMessage());
    }

    record AlertPayload(
            String alertId,
            String serverName,
            double incomingMbits,
            double outgoingMbits,
            Path   captureFile,
            List<TrafficAnalyzer.TopTalker> topTalkers,
            String timestamp
    ) {
        public String toAlertMessage() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format(
                    "🚨 **TRAFFIC ALERT** auf `%s`\n" +
                    "🔑 AlertID: `%s`\n\n" +
                    "📊 **Aktuelle Werte:**\n" +
                    "↓ Eingehend: `%.2f Mbit/s`\n" +
                    "↑ Ausgehend: `%.2f Mbit/s`\n\n" +
                    "📁 Capture: `%s`\n" +
                    "⏰ Zeit: %s",
                    serverName, alertId,
                    incomingMbits, outgoingMbits,
                    captureFile != null ? captureFile.getFileName() : "N/A",
                    timestamp));
            if (!topTalkers.isEmpty()) {
                sb.append("\n\n🔍 **Top Talker:**\n");
                for (int i = 0; i < topTalkers.size(); i++) {
                    sb.append(String.format("%d. `%s` — %d Verbindungen\n",
                            i + 1, topTalkers.get(i).ip(), topTalkers.get(i).connections()));
                }
            }
            return sb.toString();
        }
    }

    record ResolvedPayload(
            String alertId,
            String serverName,
            double maxIncomingMbits,
            double maxOutgoingMbits,
            double currentIncomingMbits,
            double currentOutgoingMbits,
            long   durationSeconds,
            Path   captureFile,
            Path   dumpFile,
            PcapAnalyzer.ProtocolStats protocolStats,
            String timestamp
    ) {
        public String toResolvedMessage() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format(
                    "✅ **Traffic normalisiert** auf `%s`\n" +
                    "🔑 AlertID: `%s`\n\n" +
                    "📊 **Spitzenwerte während des Alerts:**\n" +
                    "↓ Max. Eingehend: `%.2f Mbit/s`\n" +
                    "↑ Max. Ausgehend: `%.2f Mbit/s`\n\n" +
                    "📊 **Aktuelle Werte:**\n" +
                    "↓ Eingehend: `%.2f Mbit/s`\n" +
                    "↑ Ausgehend: `%.2f Mbit/s`\n\n" +
                    "⏱ Dauer: `%ds`\n",
                    serverName, alertId,
                    maxIncomingMbits, maxOutgoingMbits,
                    currentIncomingMbits, currentOutgoingMbits,
                    durationSeconds));

            if (protocolStats != null && protocolStats.hasData()) {
                sb.append(String.format(
                        "🔬 **Protokolle:** %s\n\n",
                        protocolStats.toDisplayString()));
            }

            sb.append(String.format(
                    "📁 Capture: `%s`\n" +
                    "💾 Dump: `%s`\n" +
                    "⏰ Zeit: %s",
                    captureFile != null ? captureFile.getFileName() : "N/A",
                    dumpFile    != null ? dumpFile.getFileName()    : "N/A",
                    timestamp));

            return sb.toString();
        }
    }
}
