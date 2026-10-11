#!/bin/zsh
# 릴리스 빌드 후 .app 번들을 만들고 ad-hoc 서명한다.
set -e
cd "$(dirname "$0")"
swift build -c release
APP="build/IPLeakLogger.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp .build/release/IPLeakLogger "$APP/Contents/MacOS/IPLeakLogger"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.local.ip-leak-logger</string>
<key>CFBundleName</key><string>IPLeakLogger</string>
<key>CFBundleExecutable</key><string>IPLeakLogger</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$APP"
echo "빌드 완료: $APP"
