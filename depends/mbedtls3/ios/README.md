# mbedtls iOS Framework & Demo

本目录包含 mbedtls 的 iOS Framework 工程及示例 App。

## 编译方式

### 推荐：使用 Workspace

**请始终打开 `mbedtls-ios.xcworkspace`**，不要单独打开 `mbedtls.xcodeproj` 或 `mbedtls-demo.xcodeproj`，否则会出现“需指定 -project”或依赖解析问题。

- 在 Xcode 中：`File → Open` → 选择 **mbedtls-ios.xcworkspace**
- 命令行编译示例：
  - 编译 Framework（mbedtls iOS）：
    ```bash
    xcodebuild -workspace mbedtls-ios.xcworkspace -scheme "mbedtls iOS" -configuration Debug -sdk iphonesimulator build
    ```
  - 编译 Demo App（会先编译 mbedtls framework）：
    ```bash
    xcodebuild -workspace mbedtls-ios.xcworkspace -scheme "mbedtls-demo" -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' build
    ```

### 若仅编译 Framework

若只编译 framework、不编 demo，可指定工程与 scheme：

```bash
xcodebuild -project mbedtls.xcodeproj -scheme "mbedtls iOS" -configuration Debug -sdk iphonesimulator build
```

## 工程说明

- **mbedtls.xcodeproj**：产出 `mbedtls.framework`，包含 “mbedtls iOS” 与 “mbedtls macOS” 两个 target。
- **mbedtls-demo.xcodeproj**：示例 App，依赖上述 framework，需先或一并通过 workspace 编译 mbedtls。

头文件与源码路径已改为相对路径（`$(SRCROOT)/../include`、`../library`、`../include`），可在任意路径下打开 workspace 编译。
