# Java-TCPDumper

Überwacht den Netzwerktraffic auf einem Linux-Server in Echtzeit. Sobald ein konfigurierbarer Schwellenwert (Mbit/s) überschritten wird, startet automatisch ein `tcpdump`-Capture und Alerts werden über Discord, Telegram, Slack, ntfy oder einen generischen HTTP-Webhook verschickt.

## Features

- **Traffic-Monitoring** via `/proc/net/dev` (primär) mit nload-Fallback
- **Automatischer tcpdump-Start** bei Schwellenwertüberschreitung
- **5 Notification-Kanäle:** Discord Webhook, Telegram Bot, Slack, ntfy.sh, Generic HTTP
- **Top-Talker-Analyse** — zeigt die IPs mit den meisten Verbindungen im Alert
- **Capture-Rotation** — automatisches Rotieren bei max. Dauer/Größe
- **Auto-Cleanup** — alte Captures werden nach X Tagen gelöscht
- **Periodische Stats-Reports** mit Durchschnitt, Peak und Alert-Count
- **Systemd-Service** mit Hardening und Auto-Restart
- **YAML-Config** — eine Datei für alle Einstellungen

## Voraussetzungen

- Java 17+
- `tcpdump` (`apt install tcpdump`)
- `nload` (optional, `apt install nload`)
- Root-Rechte oder `CAP_NET_RAW` auf tcpdump

## Quick-Start (Clone & Run)

```bash
# 1. Clonen
git clone https://github.com/ThomasUgh/Java-TCP-Dumper.git
cd Java-TCP-Dumper

# 2. Bauen (Maven Wrapper inkludiert — kein mvn nötig)
chmod +x build.sh start.sh mvnw
./build.sh

# 3. Config anpassen
nano config.yml

# 4. Starten
sudo ./start.sh
```

Das war's. Kein Maven, kein manuelles Kopieren — clonen, bauen, config anpassen, starten.

## Installation als Systemd-Service

```bash
# Automatisch (setzt auch Dependencies auf):
sudo bash scripts/install.sh

# Danach:
sudo systemctl enable --now tcpdumper-pro
sudo journalctl -u tcpdumper-pro -f
```

## Config (`config.yml`)

### Monitor

| Key | Default | Beschreibung |
|-----|---------|-------------|
| `interface` | `eth0` | Netzwerk-Interface (`ip link show` zum Prüfen) |
| `threshold_in_mbits` | `500` | Schwellenwert Incoming (Mbit/s) |
| `threshold_out_mbits` | `500` | Schwellenwert Outgoing (Mbit/s) |
| `poll_interval_seconds` | `2` | Abtast-Intervall |
| `cooldown_seconds` | `30` | Wartezeit nach Normalisierung bevor Capture stoppt |
| `stats_interval_minutes` | `30` | Periodischer Report (0 = aus) |
| `verbose` | `false` | Jeden Poll auf die Konsole ausgeben |

### Capture

| Key | Default | Beschreibung |
|-----|---------|-------------|
| `directory` | `./captures` | Speicherort für .pcap-Dateien |
| `max_duration_seconds` | `120` | Max. Capture-Dauer, dann Rotation |
| `max_age_days` | `7` | Auto-Löschung alter Captures |
| `max_size_mb` | `100` | Max. Dateigröße pro Capture |
| `filter` | `tcp` | BPF-Filter für tcpdump |
| `snaplen` | `0` | Snap-Length (0 = volles Paket, 96 = nur Header) |

### Notifications

Jeder Kanal hat `enabled: true/false`. Mehrere Kanäle gleichzeitig möglich.

**Discord:**
```yaml
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/ID/TOKEN"
    username: "TCPDumper Pro"
    mention: "<@&ROLE_ID>"   # Optional: Rolle/User pingen bei Alert
```

**Telegram:**
```yaml
  telegram:
    enabled: true
    bot_token: "123456:ABC-DEF"
    chat_id: "-100123456789"
```

**Slack:**
```yaml
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/T.../B.../xxx"
```

**ntfy.sh (Mobile Push):**
```yaml
  ntfy:
    enabled: true
    url: "https://ntfy.sh"       # Oder self-hosted
    topic: "tcpdumper-alerts"
    token: ""                    # Optional: Access Token
```

**Generischer HTTP-Webhook (Grafana, PagerDuty, etc.):**
```yaml
  webhook:
    enabled: true
    url: "https://your-api.example.com/alerts"
    method: "POST"
    headers:
      Authorization: "Bearer TOKEN"
```

## CLI

```
java -jar tcpdumper-pro.jar [Optionen]

  -c, --config <Pfad>   Pfad zur config.yml (default: ./config.yml)
  -v, --version          Version anzeigen
  -h, --help             Hilfe anzeigen
```


## Lizenz

MIT
