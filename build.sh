#!/bin/bash
# ──────────────────────────────────────────────
# TCPDumper Pro — Build Script
# Builds the fat JAR, ready to run.
# ──────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔══════════════════════════════════════╗"
echo "║   TCPDumper Pro — Build              ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check Java
if ! command -v java &> /dev/null; then
    echo "❌ Java not found. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq openjdk-17-jdk-headless
    else
        echo "Please install Java 17+ manually."
        exit 1
    fi
fi

JAVA_VER=$(java -version 2>&1 | head -1)
echo "✓ Java: $JAVA_VER"

# Build
echo ""
echo "🔨 Building..."
./mvnw clean package -q

# Find the shaded JAR
SHADED_JAR=$(find target/ -name "tcpdumper-pro-*.jar" ! -name "*original*" 2>/dev/null | head -1)

if [ -z "$SHADED_JAR" ]; then
    echo "❌ Build failed — no JAR found in target/"
    exit 1
fi

# Copy to project root for convenience
cp "$SHADED_JAR" tcpdumper-pro.jar

echo ""
echo "✅ Build successful!"
echo "   JAR: $(pwd)/tcpdumper-pro.jar"
echo ""
echo "   Starten mit:  ./start.sh"
echo "   Oder direkt:  java -jar tcpdumper-pro.jar"
