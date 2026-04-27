package de.tcpdumper.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AppConfig {

    private static final Logger log = LoggerFactory.getLogger(AppConfig.class);

    private final Map<String, Object> rawConfig;

    private AppConfig(Map<String, Object> rawConfig) {
        this.rawConfig = rawConfig;
    }

    // ── Factory ───────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static AppConfig load(Path configPath) throws IOException {
        if (!Files.exists(configPath)) {
            throw new IOException("Config file not found: " + configPath.toAbsolutePath());
        }
        log.info("Loading configuration from {}", configPath.toAbsolutePath());
        try (InputStream inputStream = Files.newInputStream(configPath)) {
            Yaml yaml = new Yaml();
            Map<String, Object> parsedData = yaml.load(inputStream);
            if (parsedData == null) {
                throw new IOException("Config file is empty or invalid");
            }
            return new AppConfig(parsedData);
        }
    }

    // ── Raw map helpers ───────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private Map<String, Object> section(String sectionKey) {
        Object value = rawConfig.get(sectionKey);
        return value instanceof Map ? (Map<String, Object>) value : Collections.emptyMap();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> nestedSection(String parentKey, String childKey) {
        Map<String, Object> parent = section(parentKey);
        Object value = parent.get(childKey);
        return value instanceof Map ? (Map<String, Object>) value : Collections.emptyMap();
    }

    private String getString(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    private int getInt(Map<String, Object> map, String key, int defaultValue) {
        Object value = map.get(key);
        if (value instanceof Number number) return number.intValue();
        if (value instanceof String string) {
            try { return Integer.parseInt(string); } catch (NumberFormatException ignored) { return defaultValue; }
        }
        return defaultValue;
    }

    private double getDouble(Map<String, Object> map, String key, double defaultValue) {
        Object value = map.get(key);
        if (value instanceof Number number) return number.doubleValue();
        if (value instanceof String string) {
            try { return Double.parseDouble(string); } catch (NumberFormatException ignored) { return defaultValue; }
        }
        return defaultValue;
    }

    private boolean getBoolean(Map<String, Object> map, String key, boolean defaultValue) {
        Object value = map.get(key);
        if (value instanceof Boolean bool) return bool;
        if (value instanceof String string) return Boolean.parseBoolean(string);
        return defaultValue;
    }

    // ── General ───────────────────────────────────────────────────────────────

    /** Custom display name used in all notifications (replaces system hostname). */
    public String getServerName() {
        return getString(section("general"), "server_name", "unknown");
    }

    /**
     * Time format for notification timestamps.
     * @return {@code "12h"} or {@code "24h"}
     */
    public String getTimeFormat() {
        String format = getString(section("general"), "time_format", "24h");
        return format.equalsIgnoreCase("12h") ? "12h" : "24h";
    }

    // ── Monitor ───────────────────────────────────────────────────────────────

    public String getNetworkInterface() {
        return getString(section("monitor"), "interface", "eth0");
    }

    public double getThresholdInMbits() {
        return getDouble(section("monitor"), "threshold_in_mbits", 500.0);
    }

    public double getThresholdOutMbits() {
        return getDouble(section("monitor"), "threshold_out_mbits", 500.0);
    }

    /**
     * Seconds the threshold must be continuously exceeded before an alert fires.
     * Set to 0 to alert immediately on first breach.
     */
    public int getAlertDelaySeconds() {
        return getInt(section("monitor"), "alert_delay_seconds", 0);
    }

    public int getPollIntervalSeconds() {
        return getInt(section("monitor"), "poll_interval_seconds", 2);
    }

    public int getCooldownSeconds() {
        return getInt(section("monitor"), "cooldown_seconds", 30);
    }

    public int getHistorySize() {
        return getInt(section("monitor"), "history_size", 300);
    }

    public boolean isVerbose() {
        return getBoolean(section("monitor"), "verbose", false);
    }

    public int getStatsIntervalMinutes() {
        return getInt(section("monitor"), "stats_interval_minutes", 30);
    }

    // ── Capture ───────────────────────────────────────────────────────────────

    public String getCaptureDirectory() {
        return getString(section("capture"), "directory", "./captures");
    }

    /** Central directory where dumps triggered by alerts are saved. */
    public String getDumpDirectory() {
        return getString(section("capture"), "dump_directory", "./dumps");
    }

    public int getMaxCaptureDurationSeconds() {
        return getInt(section("capture"), "max_duration_seconds", 120);
    }

    public int getMaxCaptureAgeDays() {
        return getInt(section("capture"), "max_age_days", 7);
    }

    public int getMaxCaptureSizeMb() {
        return getInt(section("capture"), "max_size_mb", 100);
    }

    public String getCaptureFilter() {
        return getString(section("capture"), "filter", "tcp");
    }

    public int getSnapLen() {
        return getInt(section("capture"), "snaplen", 0);
    }

    // ── Notifications — Discord ───────────────────────────────────────────────

    public boolean isDiscordEnabled() {
        return getBoolean(nestedSection("notifications", "discord"), "enabled", false);
    }

    public String getDiscordWebhookUrl() {
        return getString(nestedSection("notifications", "discord"), "webhook_url", "");
    }

    public String getDiscordUsername() {
        return getString(nestedSection("notifications", "discord"), "username", "TCP-Dumper");
    }

    public String getDiscordMention() {
        return getString(nestedSection("notifications", "discord"), "mention", "");
    }

    // ── Notifications — Telegram ──────────────────────────────────────────────

    public boolean isTelegramEnabled() {
        return getBoolean(nestedSection("notifications", "telegram"), "enabled", false);
    }

    public String getTelegramBotToken() {
        return getString(nestedSection("notifications", "telegram"), "bot_token", "");
    }

    public String getTelegramChatId() {
        return getString(nestedSection("notifications", "telegram"), "chat_id", "");
    }

    // ── Notifications — Slack ─────────────────────────────────────────────────

    public boolean isSlackEnabled() {
        return getBoolean(nestedSection("notifications", "slack"), "enabled", false);
    }

    public String getSlackWebhookUrl() {
        return getString(nestedSection("notifications", "slack"), "webhook_url", "");
    }

    // ── Notifications — Generic Webhook ──────────────────────────────────────

    public boolean isGenericWebhookEnabled() {
        return getBoolean(nestedSection("notifications", "webhook"), "enabled", false);
    }

    public String getGenericWebhookUrl() {
        return getString(nestedSection("notifications", "webhook"), "url", "");
    }

    public String getGenericWebhookMethod() {
        return getString(nestedSection("notifications", "webhook"), "method", "POST");
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> getGenericWebhookHeaders() {
        Object value = nestedSection("notifications", "webhook").get("headers");
        if (value instanceof Map) return (Map<String, String>) value;
        return Collections.emptyMap();
    }

    // ── Notifications — ntfy ──────────────────────────────────────────────────

    public boolean isNtfyEnabled() {
        return getBoolean(nestedSection("notifications", "ntfy"), "enabled", false);
    }

    public String getNtfyUrl() {
        return getString(nestedSection("notifications", "ntfy"), "url", "https://ntfy.sh");
    }

    public String getNtfyTopic() {
        return getString(nestedSection("notifications", "ntfy"), "topic", "");
    }

    public String getNtfyToken() {
        return getString(nestedSection("notifications", "ntfy"), "token", "");
    }
}
