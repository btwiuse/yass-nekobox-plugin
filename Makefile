# yass-nekobox-plugin build automation
#
# Usage:
#   make all                           # full build (download + go wrapper + apk)
#   make download-yass                 # download yass CLI binary
#   make go-wrapper                    # cross-compile Go wrapper for Android arm64
#   make apk                           # build the Android APK (requires signing)
#   make clean                         # remove build artifacts
#
# Configuration (override via environment or command line):
#   YASS_VERSION       - yass CLI release version   (default: 1.22.1)
#   PLUGIN_VERSION     - plugin / APK version name  (default: 1.22.1-1)
#   APK_ABI            - target ABI                 (default: arm64-v8a)
#   KEYSTORE_PASS      - keystore password          (required for signed APK)

YASS_VERSION   ?= 1.22.1
PLUGIN_VERSION ?= 1.22.1-1
APK_ABI        ?= arm64-v8a

YASS_DOWNLOAD_URL = https://github.com/hukeyue/yass/releases/download/$(YASS_VERSION)/yass_cli-android-release-arm64-$(YASS_VERSION).tgz
LIBS_DIR          = app/libs/$(APK_ABI)

.PHONY: all download-yass go-wrapper apk clean

all: download-yass go-wrapper apk

# ---------- Download yass CLI binary ----------
download-yass:
	mkdir -p $(LIBS_DIR)
	wget -O /tmp/yass_cli.tar.gz "$(YASS_DOWNLOAD_URL)"
	tar -xf /tmp/yass_cli.tar.gz -C /tmp
	cp /tmp/yass-cli-android-release-arm64-$(YASS_VERSION)/yass_cli $(LIBS_DIR)/libyass_cli.so
	chmod +x $(LIBS_DIR)/libyass_cli.so
	rm -rf /tmp/yass_cli.tar.gz /tmp/yass-cli-android-release-arm64-$(YASS_VERSION)

# ---------- Build Go wrapper ----------
go-wrapper:
	mkdir -p $(LIBS_DIR)
	GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
		go build -ldflags="-s -w" -trimpath -o $(LIBS_DIR)/libnaive.so main.go

# ---------- Build APK ----------
apk:
	chmod +x gradlew
	APK_VERSION_NAME=$(PLUGIN_VERSION) APK_ABI=$(APK_ABI) ./gradlew assembleRelease

# ---------- Clean ----------
clean:
	rm -rf $(LIBS_DIR)
	./gradlew clean 2>/dev/null || true
