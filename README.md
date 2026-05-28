# Jarsec

A Claude Code skill that analyzes Minecraft mods for malware. It does both static analysis (reading the code) and dynamic analysis (actually running the mod in a sandbox) to check for infostealers, RATs, obfuscation, C2 infrastructure, and other nasty stuff.

## Install

```bash
npx skills add https://github.com/tinywifi/jarsec
```

## What you need

- **Docker** (required - the mod never runs on your actual machine)
- Optional extras: `openjdk-21-jdk`, `unzip`, `tcpdump`, `tshark`, `strace`, `python3-pip`

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

**Dynamic analysis (Docker sandbox):**
- Runs the actual Minecraft client with the mod loaded
- Plants fake Discord tokens and Minecraft session files as honeypots
- Captures all network traffic with tcpdump
- Monitors file system access with strace and lsof
- Streams live telemetry to your terminal

## How it works

1. Figures out what you gave it (URL, file path, or current directory)
2. Checks that Docker is installed
3. Spawns 4 static analysis agents in parallel
4. If it's source code, builds the mod first
5. Spins up a throwaway Docker container and runs the mod inside it
6. Watches everything the mod tries to do
7. Gives you a report with a single word verdict: **CLEAN**, **SUSPICIOUS**, or **MALICIOUS**

## Safety

The mod never touches your host. Everything dynamic happens inside a Docker container that gets destroyed after analysis. Even if the mod is pure evil, your machine is safe.

## License

MIT
