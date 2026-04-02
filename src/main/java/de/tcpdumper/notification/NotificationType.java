package de.tcpdumper.notification;

public enum NotificationType {
    INFO(0x3498DB),       // Blue
    SUCCESS(0x2ECC71),    // Green
    WARNING(0xF39C12),    // Orange
    ALERT(0xE74C3C);      // Red

    private final int color;

    NotificationType(int color) {
        this.color = color;
    }

    public int getColor() {
        return color;
    }

    public String getEmoji() {
        return switch (this) {
            case INFO -> "ℹ️";
            case SUCCESS -> "✅";
            case WARNING -> "⚠️";
            case ALERT -> "🚨";
        };
    }
}
