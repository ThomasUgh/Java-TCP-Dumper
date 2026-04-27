#!/bin/bash
# ──────────────────────────────────────────────
# TCP-Dumper — Start Script
# Runs the application with sensible JVM defaults.
# ──────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

JAR="tcp-dumper.jar"
CONFIG="config.yml"

# Check if JAR exists
if [ ! -f "$JAR" ]; then
    # Try target/ directory
    SHADED_JAR=$(find target/ -name "tcp-dumper-*.jar" ! -name "*original*" 2>/dev/null | head -1)
    if [ -n "$SHADED_JAR" ]; then
        JAR="$SHADED_JAR"
    else
        echo "❌ $JAR not found. Run ./build.sh first."
        exit 1
    fi
fi

# Check if config exists, create default if not
if [ ! -f "$CONFIG" ]; then
    echo "⚠ config.yml not found — creating default config."
    echo "  → Edit config.yml before restarting!"
    cp config.yml.example "$CONFIG" 2>/dev/null || true
fi

# Ensure directories exist
mkdir -p captures logs

echo "╔══════════════════════════════════════╗"
echo "║   TCP-Dumper — Starting...           ║"
echo "╚══════════════════════════════════════╝"
echo ""

# JVM arguments
JVM_ARGS="-Xms64m -Xmx256m"
JVM_ARGS="$JVM_ARGS -XX:+UseG1GC"
JVM_ARGS="$JVM_ARGS -XX:+HeapDumpOnOutOfMemoryError"
JVM_ARGS="$JVM_ARGS -Djava.net.preferIPv4Stack=true"

# Pass through any additional args (like --config /other/path.yml)
exec java $JVM_ARGS -jar "$JAR" --config "$CONFIG" "$@"
