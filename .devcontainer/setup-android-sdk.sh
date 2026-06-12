#!/usr/bin/env bash
set -euo pipefail

CMDLINE_TOOLS_VERSION="11076708"
ANDROID_SDK_ROOT="${ANDROID_HOME:-$HOME/android-sdk}"

if [ -d "$ANDROID_SDK_ROOT/cmdline-tools/latest" ]; then
  echo "Android SDK already installed at $ANDROID_SDK_ROOT"
  exit 0
fi

echo "Installing Android SDK command-line tools..."
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"

wget -q -O /tmp/cmdline-tools.zip \
  "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip"

unzip -q /tmp/cmdline-tools.zip -d "$ANDROID_SDK_ROOT/cmdline-tools"
mv "$ANDROID_SDK_ROOT/cmdline-tools/cmdline-tools" "$ANDROID_SDK_ROOT/cmdline-tools/latest"
rm /tmp/cmdline-tools.zip

export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH"

echo "Accepting Android SDK licenses..."
yes | sdkmanager --licenses > /dev/null 2>&1 || true

echo "Installing required SDK packages..."
sdkmanager --install \
  "platform-tools" \
  "platforms;android-36" \
  "build-tools;36.0.0"

echo "Android SDK setup complete at $ANDROID_SDK_ROOT"
