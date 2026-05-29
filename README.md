# Jarsec

A Claude Code skill that analyzes Minecraft mods for malware. It does both static analysis (reading the code) and dynamic analysis (actually running the mod in a sandbox) to check for infostealers, RATs, obfuscation, C2 infrastructure, and other nasty stuff.

## Install

```bash
npx skills add https://github.com/tinywifi/jarsec
```

## What you need

- **Docker** (required - the mod never runs on your actual machine)
- **Java** (required for decompilation - `openjdk-21-jdk` or any JDK 17+)
- Optional extras: `unzip`, `tcpdump`, `tshark`, `strace`, `python3-pip`

Decompilers (Vineflower + CFR fallback) are downloaded automatically on first run. The Docker sandbox image can be pre-built or built locally.

Jarsec will check what you have installed and tell you exactly what's missing.

## How to use it

### Analyze the source code in your current folder
```bash
claude
/jarsec
```

### Analyze a local JAR file
```bash
claude
/jarsec /path/to/mod.jar
```

### Download and analyze a JAR from a URL
```bash
claude
/jarsec https://cdn.modrinth.com/data/.../mod.jar
```

## What it actually checks

**Static analysis (4 agents running in parallel):**
- Decompiles JAR bytecode to readable Java source via Vineflower (falls back to CFR)
- Build configuration for malicious repos, shadow jars, or obfuscation
- Infostealer signatures (Discord webhooks, token grabbers, session theft)
- Known Weedhack/majanito malware IOCs
- Malicious APIs (Runtime.exec, ProcessBuilder, clipboard hijacking, etc.)
- Persistence mechanisms (startup injection, registry keys, scheduled tasks)
- Stage-2 droppers (OS fingerprinting, temp file writes, URLClassLoader)
- Viral propagation (JAR/zip file iteration, self-replication)
- Network C2 (hardcoded URLs, Telegram bots, blockchain/Ethereum C2)
- Mixin review (checking if mixins intercept sensitive packets without good reason)
- Unsafe deserialization (BleedingPipe vectors)
- Reflection abuse, anti-sandbox checks, JVM instrumentation, steganography
- **MITRE ATT&CK technique mapping** — auto-tags findings with MITRE IDs
- **YARA rule generation** — creates hunt rules from unique strings/bytecode
- **STIX/MISP IOC export** — machine-readable threat intel bundles

**Dynamic analysis (Docker sandbox):**
- Runs the actual Minecraft client with the mod loaded
- Plants fake Discord tokens and Minecraft session files as honeypots
- Captures all network traffic with tcpdump
- Monitors file system access with `inotifywait`, `strace`, and `lsof`
- **Disables SSL cert validation** so malware C2 connections succeed
- Dumps Java heap to extract runtime-decrypted strings
- Compares container state before/after to find dropped files
- **Auto-downloads and analyzes stage-2 payloads** if found

**String extraction:**
- Static XOR brute-force decryptor for common obfuscation schemes
- Dynamic reflection extractor for caller-context obfuscation (StackWalker-based)
- Bytecode scanner that finds decryptor methods by signature + call frequency

## Scripts

| Script | Purpose |
|--------|---------|
| `jarsec-decrypt.py` | Static XOR brute-force string decryptor |
| `jarsec-discover.py` | Bytecode scanner — finds candidate decryptor methods |
| `jarsec-extract.py` | Dynamic reflection extractor — loads classes to get decrypted strings |
| `jarsec-ioc.py` | STIX 2.1 + MISP JSON IOC export |
| `jarsec-yara.py` | Auto-generates YARA rules from analysis findings |
| `jarsec-mitre.py` | Maps findings to MITRE ATT&CK techniques |

## Docker Sandbox

The skill can use a **pre-built image** (`ghcr.io/tinywifi/jarsec-sandbox:latest`) for fast startup, or build locally if unavailable. The image includes:

- Eclipse Temurin JDK 21
- Vineflower + CFR decompilers
- `tcpdump`, `tshark`, `strace`, `lsof`, `inotify-tools`
- `xvfb` for headless rendering
- `portablemc` for Minecraft launching
- `python3` + `pip3`

## How it works

1. Figures out what you gave it (URL, file path, or current directory)
2. Checks that Docker is installed
3. Creates an isolated temp workspace (no cross-contamination between runs)
4. Decompiles JARs to Java source with Vineflower (CFR fallback)
5. Runs static decryptor + dynamic extractor for obfuscated strings
6. Spawns 4 static analysis agents in parallel
7. If it's source code, builds the mod first
8. Spins up a throwaway Docker container and runs the mod inside it
9. Watches filesystem events, network traffic, heap dumps, and process changes
10. If stage-2 droppers found, downloads and analyzes them recursively
11. Generates STIX/MISP IOCs, YARA rules, and MITRE mapping
12. Gives you a report with a single word verdict: **CLEAN**, **SUSPICIOUS**, or **MALICIOUS**

## Safety

The mod never touches your host. Everything dynamic happens inside a Docker container that gets destroyed after analysis. Even if the mod is pure evil, your machine is safe.

## License

MIT
