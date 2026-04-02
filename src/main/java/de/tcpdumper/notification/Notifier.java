package de.tcpdumper.notification;

public interface Notifier {
    void send(NotificationType type, String title, String message) throws Exception;
}
