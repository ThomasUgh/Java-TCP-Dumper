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

    private final Map<String, Object> raw;

    private AppConfig(Map<String, Object> raw) {
        this.raw = raw;
    }

    @SuppressWarnings("unchecked")
    public static AppConfig load(Path path) throws IOException {
        if (!Files.exists(path)) {
            throw new IOException("Config file not found: " + path.toAbsolutePath());
        }
        log.info("Loading configuration from {}", path.toAbsolutePath());
        try (InputStream in = Files.newInputStream(path)) {
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(in);
            if (data == null) {
                throw new IOException("Config file is empty or invalid");
            }
            return new AppConfig(data);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> section(String key) {
        Object val = raw.get(key);
        return val instanceof Map ? (Map<String, Object>) val : Collections.emptyMap();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> nestedSection(String parent, String child) {
        Map<String, Object> p = section(parent);
        Object val = p.get(child);
        return val instanceof Map ? (Map<String, Object>) val : Collections.emptyMap();
    }

    private String getString(Map<String, Object> map, String key, String def) {
        Object val = map.get(key);
        return val != null ? val.toString() : def;
    }

    private int getInt(Map<String, Object> map, String key, int def) {
        Object val = map.get(key);
        if (val instanceof Number n) return n.intValue();
        if (val instanceof String s) {
            try { return Integer.parseInt(s); } catch (NumberFormatException e) { return def; }
        }
        return def;
    }

    private double getDouble(Map<String, Object> map, String key, double def) {
        Object val = map.get(key);
        if (val instanceof Number n) return n.doubleValue();
        if (val instanceof String s) {
            try { return Double.parseDouble(s); } catch (NumberFormatException e) { return def; }
        }
        return def;
    }

    private boolean getBool(Map<String, Object> map, String key, boolean def) {
        Object val = map.get(key);
        if (val instanceof Boolean b) return b;
        if (val instanceof String s) return Boolean.parseBoolean(s);
        return def;
    }


    public String getNetworkInterface() {
        return getString(section("monitor"), "interface", "eth0");
    }
    public double getThresholdInMbits() {
        return getDouble(section("monitor"), "threshold_in_mbits", 500.0);
    }
    public double getThresholdOutMbits() {
        return getDouble(section("monitor"), "threshold_out_mbits", 500.0);
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
        return getBool(section("monitor"), "verbose", false);
    }
    public int getStatsIntervalMinutes() {
        return getInt(section("monitor"), "stats_interval_minutes", 30);
    }


    public String getCaptureDir() {
        return getString(section("capture"), "directory", "./captures");
    }
    public int getMaxCaptureDurationSeconds() {
        return getInt(section("capture"), "max_duration_seconds", 120);
    }
    public int getMaxCaptureAgeDays() {
        return getInt(section("capture"), "max_age_days", 7);
    }
    public int getMaxCaptureSizeMB() {
        return getInt(section("capture"), "max_size_mb", 100);
    }
    public String getCaptureFilter() {
        return getString(section("capture"), "filter", "tcp");
    }
    public int getSnapLen() {
        return getInt(section("capture"), "snaplen", 0);
    }


    public boolean isDiscordEnabled() {
        return getBool(nestedSection("notifications", "discord"), "enabled", false);
    }

    public String getDiscordWebhookUrl() {
        return getString(nestedSection("notifications", "discord"), "webhook_url", "");
    }

    public String getDiscordUsername() {
        return getString(nestedSection("notifications", "discord"), "username", "TCPDumper Pro");
    }

    public String getDiscordMention() {
        return getString(nestedSection("notifications", "discord"), "mention", "");
    }


    public boolean isTelegramEnabled() {
        return getBool(nestedSection("notifications", "telegram"), "enabled", false);
    }
    public String getTelegramBotToken() {
        return getString(nestedSection("notifications", "telegram"), "bot_token", "");
    }

    public String getTelegramChatId() {
        return getString(nestedSection("notifications", "telegram"), "chat_id", "");
    }


    public boolean isSlackEnabled() {
        return getBool(nestedSection("notifications", "slack"), "enabled", false);
    }

    public String getSlackWebhookUrl() {
        return getString(nestedSection("notifications", "slack"), "webhook_url", "");
    }


    public boolean isGenericWebhookEnabled() {
        return getBool(nestedSection("notifications", "webhook"), "enabled", false);
    }

    public String getGenericWebhookUrl() {
        return getString(nestedSection("notifications", "webhook"), "url", "");
    }

    public String getGenericWebhookMethod() {
        return getString(nestedSection("notifications", "webhook"), "method", "POST");
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> getGenericWebhookHeaders() {
        Object val = nestedSection("notifications", "webhook").get("headers");
        if (val instanceof Map) return (Map<String, String>) val;
        return Collections.emptyMap();
    }



    public boolean isNtfyEnabled() {
        return getBool(nestedSection("notifications", "ntfy"), "enabled", false);
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
