# Yass Plugin for NekoBox (NaiveProxy Wrapper)

This is a standalone Android plugin for [NekoBoxForAndroid](https://github.com/MatsuriDayo/NekoBoxForAndroid) that allows running the `yass_cli` core by masquerading as a NaiveProxy plugin.

## Project Structure

- `main.go`: The Go wrapper source code. It translates NaiveProxy JSON config to Yass format and prevents routing loops.
- `app/`: The Android project for the plugin APK.
- `integration_guide.md`: Detailed technical explanation of the implementation.

## How to Build

### 1. Build the Go Wrapper
You need the Go SDK installed.
```bash
export GOOS=android
export GOARCH=arm64
export CGO_ENABLED=0
go build -ldflags="-s -w" -trimpath -o app/libs/arm64-v8a/libnaive.so main.go
```

### 2. Add yass_cli
Place your compiled `yass_cli` binary (Android arm64) into `app/libs/arm64-v8a/` and rename it to `libyass_cli.so`.

### 3. Build the APK
```bash
export APK_VERSION_NAME="v1.0.0-1"
export APK_ABI="arm64-v8a"
export KEYSTORE_PASS="your_password"
./gradlew assembleRelease
```

## CI/CD Setup

The GitHub Actions workflow requires two repository secrets: `KEYSTORE_BASE64` and `KEYSTORE_PASS`.

### 1. Choose a keystore password

Pick a strong password. This will be your `KEYSTORE_PASS`.

### 2. Generate a release keystore

```bash
keytool -genkey -v \
  -keystore release.keystore \
  -alias release \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -storepass YOUR_PASSWORD \
  -keypass YOUR_PASSWORD
```

Replace `YOUR_PASSWORD` with the password you chose. When prompted for name, organization, etc., you can fill in any values or press Enter to skip.

### 3. Base64-encode the keystore

```bash
# Linux
base64 -w 0 release.keystore

# macOS
base64 -i release.keystore
```

Copy the output — this is your `KEYSTORE_BASE64`.

### 4. Add the secrets to GitHub

1. Go to your repository on GitHub → **Settings** → **Secrets and variables** → **Actions**.
2. Click **New repository secret** and add:
   - **Name:** `KEYSTORE_PASS` — **Value:** the password you chose in step 1.
   - **Name:** `KEYSTORE_BASE64` — **Value:** the base64 output from step 3.

## Thanks to
- [hukeyue/yass](https://github.com/hukeyue/yass/issues)
- [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy)
- [MatsuriDayo/NekoBoxForAndroid](https://github.com/MatsuriDayo/NekoBoxForAndroid)
