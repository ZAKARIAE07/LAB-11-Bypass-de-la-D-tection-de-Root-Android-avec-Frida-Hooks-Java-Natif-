# 🛡️ LAB 11 — Android Root Detection Bypass with Frida (Java & Native Hooks)

> **⚠️ Ethical Warning:** Use these techniques **only** on applications and devices for which you have **explicit authorization**. This lab is purely educational and security-oriented. Unauthorized use may violate local laws and terms of service.

---

## 📋 Table of Contents

- [Objectives](#-objectives)
- [Prerequisites](#-prerequisites)
- [Architecture Overview](#-architecture-overview)
- [Setup — Starting frida-server on Android](#-setup--starting-frida-server-on-android)
- [Root Detection Techniques Overview](#-root-detection-techniques-overview)
- [Step 1 — Find the Target Package](#step-1--find-the-target-package)
- [Step 2 — Java Layer Bypass (`bypass_root.js`)](#step-2--java-layer-bypass-bypass_rootjs)
- [Step 3 — Native Layer Bypass (`bypass_native.js`)](#step-3--native-layer-bypass-bypass_nativejs)
- [Step 4 — Anti-Frida Masking (`anti_frida.js`)](#step-4--anti-frida-masking-anti_fridajs-optional)
- [Step 5 — Launch Methods & Practical Tips](#step-5--launch-methods--practical-tips)
- [Troubleshooting](#-troubleshooting)
- [File Structure](#-file-structure)
- [References](#-references)

---

## 🎯 Objectives

- Understand how Android apps detect root at both the **Java** and **native (JNI/C)** layers.
- Use **Frida** to neutralize these detections via targeted hooks.
- Launch a target app under Frida, verify the bypass works, and diagnose failures.

---

## ✅ Prerequisites

| Requirement | Details |
|---|---|
| **Frida** | Installed on host PC (`pip install frida-tools`) |
| **ADB** | Android Debug Bridge configured and working |
| **Rooted Android device** | USB debugging enabled |
| **frida-server** | Matching version pushed to device (see Setup) |
| **Target app** | An app with root detection (e.g., RootBeer sample app) |

---

## 🏗️ Architecture Overview

```
Host PC (Frida Client)
        │
        │  USB / TCP
        ▼
Android Device (frida-server running as root)
        │
        │  Injects into target process
        ▼
Target App (com.example.rootcheck)
   ├── Java Layer ──► Build.TAGS, File.exists(), Runtime.exec(), RootBeer
   └── Native Layer ─► open(), openat(), access(), stat(), lstat()
```

---

## ⚙️ Setup — Starting frida-server on Android

### 1. Identify the CPU Architecture

```bash
adb shell getprop ro.product.cpu.abi
# Example output: arm64-v8a
```

### 2. Download the Matching frida-server

Go to [https://github.com/frida/frida/releases](https://github.com/frida/frida/releases) and download:

```
frida-server-<version>-android-<arch>.xz
```

Make sure the version **exactly matches** your installed Frida client (`frida --version`).

### 3. Push and Launch on Device

```bash
# Extract the binary
unxz frida-server-<version>-android-<arch>.xz

# Push to device
adb push frida-server /data/local/tmp/

# Set permissions
adb shell chmod 755 /data/local/tmp/frida-server

# Start the server (run in background or keep terminal open)
adb shell "/data/local/tmp/frida-server -l 0.0.0.0"
# Or with nohup:
adb shell "nohup /data/local/tmp/frida-server -l 0.0.0.0 &"
```

### 4. Forward Ports (if needed)

```bash
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043
```

### 5. Verify the Device is Visible

```bash
frida-ps -Uai
```

---

## 🔍 Root Detection Techniques Overview

### Java (High-Level)

| Technique | Description |
|---|---|
| `Build.TAGS` | Checks for `test-keys` string (indicates custom/rooted ROM) |
| `File.exists()` | Looks for `/system/xbin/su`, `/system/bin/su`, `busybox`, etc. |
| `Runtime.exec()` | Runs commands like `su`, `which su`, `busybox` |
| **RootBeer** | Third-party library with `isRooted()`, `isRootedWithBusyBoxCheck()` |

### Native (JNI / C / C++)

| Technique | Description |
|---|---|
| `open` / `openat` | Opens suspicious paths to check existence |
| `access` / `stat` / `lstat` | Checks file metadata for su/busybox paths |
| `/proc/mounts` | Reads mount table for `rw` system partitions |
| Anti-Frida | Port scanning (27042/27043), string detection (`frida`) |

---

## Step 1 — Find the Target Package

List installed packages and filter by keyword:

```bash
# Linux / macOS
frida-ps -Uai | grep -i "root\|beer\|checker"

# Windows PowerShell
frida-ps -Uai | Select-String -Pattern "root,beer,checker"
```

> Replace `com.example.rootcheck` with your actual package name in all commands below.

---

## Step 2 — Java Layer Bypass (`bypass_root.js`)

This script hooks the most common **Java-level** root detection methods.

### What it hooks

| Hook | Effect |
|---|---|
| `Build.TAGS` | Always returns `release-keys` |
| `RootBeer.isRooted()` | Always returns `false` |
| `RootBeer.isRootedWithBusyBoxCheck()` | Always returns `false` |
| `File.exists()` | Returns `false` for known suspicious paths |
| `Runtime.exec()` | Blocks `su`, `which su`, and `busybox` commands |

### Script — `bypass_root.js`

```javascript
// bypass_root.js — Neutralizes common Java root checks
// Covers: Build.TAGS, File.exists, Runtime.exec, RootBeer

function safeContains(str, needle) {
  try {
    return (str || "").toLowerCase().indexOf((needle || "").toLowerCase()) !== -1;
  } catch (_) { return false; }
}

const suspiciousPaths = [
  "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
  "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
  "/system/bin/.ext/.su", "/system/usr/we-need-root/",
  "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
  "/system/bin/busybox", "/system/xbin/busybox"
];

Java.perform(function () {

  // 1) Force Build.TAGS to a non-suspicious value
  try {
    const Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'TAGS', {
      get: function () { return 'release-keys'; }
    });
    console.log('[+] Hook Build.TAGS -> release-keys');
  } catch (e) { console.log('[-] Build.TAGS hook failed:', e); }

  // 2) RootBeer (if present)
  try {
    const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function () {
      console.log('[+] RootBeer.isRooted -> false');
      return false;
    };
    if (RootBeer.isRootedWithBusyBoxCheck) {
      RootBeer.isRootedWithBusyBoxCheck.implementation = function () {
        console.log('[+] RootBeer.isRootedWithBusyBoxCheck -> false');
        return false;
      };
    }
  } catch (e) { console.log('[*] RootBeer not present or different name:', e.message); }

  // 3) File.exists -> return false for suspicious paths
  try {
    const File = Java.use('java.io.File');
    File.exists.implementation = function () {
      const path = this.getAbsolutePath();
      if (suspiciousPaths.indexOf(path) !== -1) {
        console.log('[+] File.exists bypass for', path);
        return false;
      }
      return this.exists.call(this);
    };
  } catch (e) { console.log('[-] File.exists hook failed:', e); }

  // 4) Runtime.exec -> block su/which/busybox commands
  try {
    const Runtime = Java.use('java.lang.Runtime');
    const JString = Java.use('java.lang.String');
    const StringArray = Java.use('[Ljava.lang.String;');

    function blockIfSuspicious(cmdOrArr) {
      const joined = Array.isArray(cmdOrArr) ? cmdOrArr.join(' ') : ('' + cmdOrArr);
      if (
        safeContains(joined, ' su') ||
        joined.trim().toLowerCase().startsWith('su') ||
        safeContains(joined, 'which su') ||
        safeContains(joined, 'busybox')
      ) {
        console.log('[+] Blocked Runtime.exec:', joined);
        return ['sh', '-c', 'echo'];
      }
      return null;
    }

    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      const repl = blockIfSuspicious(cmd);
      return repl ? this.exec(JString.$new(repl.join(' '))) : this.exec(cmd);
    };

    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
      const js = arr ? Array.from(arr) : [];
      const repl = blockIfSuspicious(js);
      if (repl) {
        const a = StringArray.$new(repl.length);
        for (let i = 0; i < repl.length; i++) a[i] = JString.$new(repl[i]);
        return this.exec(a);
      }
      return this.exec(arr);
    };

    Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (cmd, envp) {
      const repl = blockIfSuspicious(cmd);
      return repl ? this.exec(JString.$new(repl.join(' ')), envp) : this.exec(cmd, envp);
    };

    Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (arr, envp) {
      const js = arr ? Array.from(arr) : [];
      const repl = blockIfSuspicious(js);
      if (repl) {
        const a = StringArray.$new(repl.length);
        for (let i = 0; i < repl.length; i++) a[i] = JString.$new(repl[i]);
        return this.exec(a, envp);
      }
      return this.exec(arr, envp);
    };

    console.log('[+] Runtime.exec hooks installed');
  } catch (e) { console.log('[-] Runtime.exec hooks failed:', e); }

  console.log('[+] Java layer bypass installed');
});
```

### Launch

```bash
frida -U -f com.example.rootcheck -l bypass_root.js --no-pause
```

### Expected Output

```
[+] Hook Build.TAGS -> release-keys
[*] RootBeer not present or different name: ...
[+] Runtime.exec hooks installed
[+] Java layer bypass installed
```

The app should start and simple Java checks (RootBeer, Build.TAGS, File.exists, Runtime.exec) will no longer detect root.

---

## Step 3 — Native Layer Bypass (`bypass_native.js`)

When an app uses the NDK for root checks (C/C++ code), you need to hook system calls at a lower level.

### What it hooks

| Function | Path Argument | Purpose |
|---|---|---|
| `open` | arg[0] | Opens file descriptor |
| `openat` | arg[1] | Opens relative file descriptor |
| `access` | arg[0] | Checks file accessibility |
| `stat` | arg[0] | Gets file status |
| `lstat` | arg[0] | Gets symlink status |

All hooks return `-1` (ENOENT/error) when a suspicious path is detected.

### Script — `bypass_native.js`

```javascript
// bypass_native.js — Neutralizes open/openat/access/stat/lstat on suspicious paths

const SUS = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/system/su',
  '/system/bin/busybox', '/system/xbin/busybox'
];

function isSuspiciousPath(ptrPath) {
  try {
    const p = ptrPath.readCString();
    return !!p && (
      SUS.indexOf(p) !== -1 ||
      p.indexOf('/proc/mounts') !== -1 ||
      p.indexOf('/proc/self/mounts') !== -1
    );
  } catch (_) { return false; }
}

function hookFunc(name, argIndexForPath) {
  try {
    const addr = Module.getExportByName(null, name);
    Interceptor.attach(addr, {
      onEnter(args) {
        const pathPtr = argIndexForPath >= 0 ? args[argIndexForPath] : null;
        if (pathPtr && isSuspiciousPath(pathPtr)) {
          this.block = true;
          this.path = pathPtr.readCString();
        }
      },
      onLeave(retval) {
        if (this.block) {
          console.log('[+] Blocked', name, 'on', this.path);
          retval.replace(ptr(-1));
        }
      }
    });
    console.log('[+] Hooked', name);
  } catch (e) { /* silent if not available on this platform */ }
}

hookFunc('open', 0);      // int open(const char *pathname, int flags, ...)
hookFunc('openat', 1);    // int openat(int dirfd, const char *pathname, int flags, ...)
hookFunc('access', 0);    // int access(const char *pathname, int mode)
hookFunc('stat', 0);      // int stat(const char *pathname, struct stat *buf)
hookFunc('lstat', 0);     // int lstat(const char *pathname, struct stat *buf)
```

### Combined Launch (Java + Native)

```bash
frida -U -f com.example.rootcheck -l bypass_root.js -l bypass_native.js --no-pause
```

> **Tip:** If the app reads `/proc/mounts` to detect `rw` system partitions, you can falsify content by hooking `fopen`/`fgets`/`read` and filtering lines containing `rw,`.

---

## Step 4 — Anti-Frida Masking (`anti_frida.js`, Optional)

Some apps scan for Frida's presence by checking environment variables or scanning default Frida ports (27042, 27043).

### Script — `anti_frida.js`

```javascript
// anti_frida.js — Hides basic Frida indicators at the Java layer

Java.perform(function () {

  // Hide environment variables mentioning FRIDA
  try {
    const Sys = Java.use('java.lang.System');
    Sys.getenv.overload('java.lang.String').implementation = function (name) {
      if (name && name.toLowerCase().indexOf('frida') !== -1) {
        console.log('[+] Hiding env var', name);
        return null;
      }
      return this.getenv(name);
    };
  } catch (e) {}

  // Block connections to default Frida ports
  try {
    const Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.SocketAddress').implementation = function (addr) {
      try {
        const s = addr.toString();
        if (s.indexOf(':27042') !== -1 || s.indexOf(':27043') !== -1) {
          console.log('[+] Blocked connect to', s);
          throw new Error('Connection refused');
        }
      } catch (_) {}
      return this.connect(addr);
    };
  } catch (e) {}
});
```

### Launch with All Scripts

```bash
frida -U -f com.example.rootcheck \
  -l bypass_root.js \
  -l bypass_native.js \
  -l anti_frida.js \
  --no-pause
```

---

## Step 5 — Launch Methods & Practical Tips

### Spawn Mode (Inject at Startup) — Recommended

```bash
frida -U -f com.example.rootcheck -l bypass_root.js --no-pause
```

Use this when root checks happen very early in app initialization.

### Attach Mode (Attach to Running App)

```bash
frida -U -n "ProcessName" -l bypass_root.js
```

Useful if the app is already running, but note that early checks may have already executed.

### Trace Native Calls (Discovery / Diagnostics)

```bash
frida-trace -U -i open -i access -i stat -i openat -i fopen -i readlink com.example.rootcheck
```

Use this to discover which native functions and paths the app is actually checking, then tailor your hooks accordingly.

---

## 🐛 Troubleshooting

| Problem | Likely Cause | Solution |
|---|---|---|
| `frida-ps -Uai` shows nothing | `frida-server` not running or wrong version | Check version match: `frida --version` == server version |
| App crashes on launch | Hook runs too early or incorrect class name | Try attach mode instead of spawn, or add `Java.perform` delay |
| `RootBeer` hook has no effect | App uses obfuscated class names | Decompile APK with jadx and search for actual class names |
| Native bypass has no effect | App uses `syscall()` directly (bypasses libc) | Hook at kernel level with Stalker or use `ptrace` techniques |
| App detects Frida via `/proc/maps` | Frida's agent is visible in memory maps | Use more advanced Frida cloaking techniques or a custom gadget |
| `File.exists.call(this)` crashes | Recursive hook issue | Use `this.exists()` instead of `this.exists.call(this)` |

---

## 📁 File Structure

```
lab11-frida-root-bypass/
├── README.md               ← This file
├── bypass_root.js          ← Java layer hooks (Build.TAGS, File, Runtime, RootBeer)
├── bypass_native.js        ← Native layer hooks (open, access, stat, etc.)
└── anti_frida.js           ← Anti-Frida masking (env vars, port blocking)
```

---

## 📚 References

- [Frida Official Documentation](https://frida.re/docs/)
- [Frida Releases (frida-server downloads)](https://github.com/frida/frida/releases)
- [RootBeer Library](https://github.com/scottyab/rootbeer)
- [jadx — Android Decompiler](https://github.com/skylot/jadx)
- [OWASP Mobile Security Testing Guide (MSTG)](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android NDK — System Call Reference](https://man7.org/linux/man-pages/man2/syscalls.2.html)

---

## 📝 Lab Notes

> This lab was completed as part of a mobile security course curriculum. All tests were performed on a dedicated rooted test device with explicit authorization. No production apps or personal data were involved.

**Skills demonstrated:**
- Frida scripting (Java and native hooks)
- Android internals (JNI, Build properties, proc filesystem)
- Dynamic analysis and reverse engineering workflow
- Root detection evasion techniques for security research

---

*Lab 11 | Android Security | Frida Dynamic Instrumentation*


<img width="1600" height="800" alt="WhatsApp Image 2026-04-22 at 16 47 31" src="https://github.com/user-attachments/assets/945a8366-f678-4d5b-90c9-47c53b9f5937" />
