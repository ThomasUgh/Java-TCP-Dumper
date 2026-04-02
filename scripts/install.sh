#!/bin/bash
# ──────────────────────────────────────────────
# TCPDumper Pro — Install Script
# Run as root on Ubuntu/Debian
# ──────────────────────────────────────────────
set -e

INSTALL_DIR="/opt/tcpdumper-pro"
JAR_NAME="tcpdumper-pro.jar"
SERVICE_NAME="tcpdumper-pro"

echo "╔══════════════════════════════════════╗"
echo "║   TCPDumper Pro — Installer          ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (sudo bash install.sh)"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
apt-get update -qq
apt-get install -y -qq tcpdump nload iproute2 > /dev/null 2>&1
echo "✓ tcpdump, nload, iproute2 installed"

# Check Java
if ! command -v java &> /dev/null; then
    echo "📦 Installing Java 17..."
    apt-get install -y -qq openjdk-17-jre-headless > /dev/null 2>&1
    echo "✓ Java 17 installed"
else
    JAVA_VER=$(java -version 2>&1 | head -1)
    echo "✓ Java found: $JAVA_VER"
fi

# Create install directory
echo "📁 Setting up $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR/captures"
mkdir -p "$INSTALL_DIR/logs"

# Copy files
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

if [ -f "$PARENT_DIR/target/$JAR_NAME" ]; then
    cp "$PARENT_DIR/target/$JAR_NAME" "$INSTALL_DIR/"
    echo "✓ JAR copied"
elif [ -f "$PARENT_DIR/$JAR_NAME" ]; then
    cp "$PARENT_DIR/$JAR_NAME" "$INSTALL_DIR/"
    echo "✓ JAR copied"
else
    echo "⚠ JAR not found — build first with: mvn clean package"
    echo "  Then copy target/tcpdumper-pro-2.0.0-shaded.jar to $INSTALL_DIR/$JAR_NAME"
fi

# Config
if [ ! -f "$INSTALL_DIR/config.yml" ]; then
    cp "$PARENT_DIR/config.yml" "$INSTALL_DIR/"
    echo "✓ Default config.yml created — EDIT THIS!"
else
    echo "✓ config.yml already exists — keeping current"
fi

# Systemd service
cp "$SCRIPT_DIR/tcpdumper-pro.service" /etc/systemd/system/
systemctl daemon-reload
echo "✓ Systemd service installed"

echo ""
echo "══════════════════════════════════════════"
echo "  Installation complete!"
echo ""
echo "  Next steps:"
echo "  1. Edit config:    nano $INSTALL_DIR/config.yml"
echo "  2. Start service:  systemctl start $SERVICE_NAME"
echo "  3. Enable on boot: systemctl enable $SERVICE_NAME"
echo "  4. Check logs:     journalctl -u $SERVICE_NAME -f"
echo "══════════════════════════════════════════"
