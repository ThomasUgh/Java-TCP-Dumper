#!/bin/sh
# Maven Wrapper — downloads Maven automatically if not installed
# Usage: ./mvnw clean package

set -e

MAVEN_VERSION="3.9.8"
MAVEN_HOME="$HOME/.m2/wrapper/apache-maven-$MAVEN_VERSION"
MAVEN_URL="https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/$MAVEN_VERSION/apache-maven-$MAVEN_VERSION-bin.tar.gz"

# If Maven is already installed system-wide, use it
if command -v mvn > /dev/null 2>&1; then
    exec mvn "$@"
fi

# Otherwise download and cache Maven
if [ ! -f "$MAVEN_HOME/bin/mvn" ]; then
    echo "Maven not found — downloading Maven $MAVEN_VERSION..."
    mkdir -p "$MAVEN_HOME"
    TMPFILE=$(mktemp /tmp/maven-XXXXXX.tar.gz)
    
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$MAVEN_URL" -o "$TMPFILE"
    elif command -v wget > /dev/null 2>&1; then
        wget -q "$MAVEN_URL" -O "$TMPFILE"
    else
        echo "ERROR: Neither curl nor wget found. Install Maven manually:"
        echo "  apt install maven"
        exit 1
    fi
    
    tar xzf "$TMPFILE" -C "$(dirname "$MAVEN_HOME")"
    rm -f "$TMPFILE"
    echo "Maven $MAVEN_VERSION installed to $MAVEN_HOME"
fi

exec "$MAVEN_HOME/bin/mvn" "$@"
