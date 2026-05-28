# JARSEC 🔍

**Jarsec Malware Analysis Task Force** — a Claude Code skill for comprehensive static and dynamic analysis of Minecraft mods (JARs or source code) to detect malicious behavior, infostealers, RATs, obfuscation, and C2 infrastructure.

## Installation

```bash
npx skills add https://github.com/tinywifi/jarsec
```

## Prerequisites

- **Docker** (required for dynamic sandbox — the suspicious mod is NEVER run on your host)
- Optional: `openjdk-21-jdk`, `unzip`, `tcpdump`, `tshark`, `strace`, `python3-pip` (for enhanced telemetry)

Jarsec checks for missing tools at startup and tells you exactly what to install.

## Usage

### Analyze source code in current directory
```bash
claude
/jarsec
```
Assumes the current folder is a Minecraft mod source project. Runs static analysis on all files, then builds and dynamically detonates in Docker.

### Analyze a local JAR file
```bash
claude
/jarsec /path/to/mod.jar
```

### Download and analyze a JAR from URL
```bash
claude
/jarsec https://cdn.modrinth.com/data/.../mod.jar
```

## What Jarsec Checks

| Phase | Checks |
|-------|--------|
| **Static — Agent 1** | Build config, embedded libs, native binaries, asset steganography |
| **Static — Agent 2** | Infostealer signatures, Weedhack IOCs, malicious APIs, persistence, droppers, viral propagation |
| **Static — Agent 3** | Hardcoded URLs/C2, Telegram/blockchain C2, mixin review, BleedingPipe deserialization |
| **Static — Agent 4** | Reflection, obfuscation footprints, anti-sandbox, JVM abuse, steganographic decoders |
| **Dynamic — Docker** | Full client detonation with honeytokens, tcpdump network capture, strace syscall monitoring, lsof file access checks |

## How It Works

1. **Target detection** — determines if you gave a URL, file path, or nothing (current dir)
2. **Prerequisite check** — verifies Docker and optional tools exist
3. **4 parallel static agents** — search the codebase for known malware signatures
4. **Build gate** — if source code, compiles the mod first
5. **Docker dynamic sandbox** — detonates the mod in an isolated container with:
   - Fake Discord tokens and Minecraft session files (honeytokens)
   - `tcpdump` network capture
   - `strace` / `lsof` file system monitoring
   - PortableMC to launch the actual Minecraft client with the mod loaded
6. **Synthesis report** — compiles all findings with a single-word verdict: **CLEAN**, **SUSPICIOUS**, or **MALICIOUS**

## Safety

- The suspicious mod **never touches your host** — all dynamic analysis runs inside a throwaway Docker container
- Honeytoken files are planted inside the container to detect credential theft attempts
- Container is automatically destroyed after analysis

## License

MIT
