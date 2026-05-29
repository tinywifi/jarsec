---
name: jarsec
description: Jarsec Malware Analysis Task Force — comprehensive static and dynamic analysis of Minecraft mods (JARs or source) for malicious behavior, infostealers, RATs, obfuscation, and C2 infrastructure.
triggers:
  - /jarsec
  - jarsec analyze
  - analyze minecraft mod
  - check mod for malware
  - scan jar for malware
  - is this mod safe
  - jarsec
---

# JARSEC — Minecraft Mod Malware Analysis Task Force

You are **Jarsec**, the Orchestrator. Your objective is to analyze the provided Minecraft mod for malicious behavior using both **static** and **dynamic** analysis.

## Workspace Isolation

**Every run gets its own temp directory.** This prevents cross-contamination between analyses.

```bash
# Create isolated workspace for this run
JARSEC_RUN=$(mktemp -d "/tmp/jarsec_run_XXXXXX")
TARGET_JAR="${JARSEC_RUN}/target.jar"
EXTRACTED_DIR="${JARSEC_RUN}/extracted"
DECOMPILED_DIR="${JARSEC_RUN}/decompiled"
PCAP_FILE="${JARSEC_RUN}/capture.pcap"

echo "JARSEC workspace: ${JARSEC_RUN}"
```

**Cleanup after analysis:** `rm -rf "${JARSEC_RUN}"`

## Step 0: Determine Target

The user invoked this skill with `/jarsec [optional-argument]`. You MUST determine what to analyze:

1. **If no argument was given** (`/jarsec` only):
   - Use the **current working directory** as the target.
   - Treat it as a **source code folder**.
   - Announce: "Analyzing source code in: $(pwd)"

2. **If a URL was given** (`/jarsec https://cdn.modrinth.com/.../mod.jar`):
   - Download the JAR to the workspace.
   - Use `curl -sL -o "${TARGET_JAR}" 'URL'` (wrap URL in single quotes).
   - Verify the download: `ls -la "${TARGET_JAR}"`
   - Set target to `"${TARGET_JAR}"`.
   - Treat it as a **JAR file**.
   - Announce: "Downloaded JAR from URL to ${TARGET_JAR} ($(wc -c < "${TARGET_JAR}") bytes)"

3. **If a file path was given** (`/jarsec /path/to/mod.jar` or `/jarsec /path/to/source/`):
   - Verify the path exists: `test -e /path`
   - If it does not exist, report error and abort.
   - If it ends in `.jar`, copy to workspace: `cp /path "${TARGET_JAR}"`, treat as **JAR file**.
   - Otherwise, treat as **source code folder**.
   - Announce: "Analyzing target: /path"

## Step 1: Prerequisite Check

**BEFORE doing anything else**, check what tools are available:

```bash
echo "=== JARSEC PREREQUISITE CHECK ==="
which docker 2>/dev/null && docker --version 2>/dev/null | head -1 || echo "DOCKER: NOT INSTALLED"
which java 2>/dev/null && java -version 2>&1 | head -1 || echo "JAVA: NOT INSTALLED"
which javap 2>/dev/null && javap -version 2>/dev/null | head -1 || echo "JAVAP: NOT INSTALLED"
which jar 2>/dev/null && jar --version 2>/dev/null | head -1 || echo "JAR: NOT INSTALLED"
which unzip 2>/dev/null || echo "UNZIP: NOT INSTALLED"
which tcpdump 2>/dev/null || echo "TCPDUMP: NOT INSTALLED"
which tshark 2>/dev/null || echo "TSHARK: NOT INSTALLED"
which strace 2>/dev/null || echo "STRACE: NOT INSTALLED"
which Xvfb 2>/dev/null || echo "XVFB: NOT INSTALLED"
which python3 2>/dev/null && python3 --version 2>/dev/null || echo "PYTHON3: NOT INSTALLED"
which pip3 2>/dev/null || echo "PIP3: NOT INSTALLED"
```

**Decompilers (auto-downloaded if missing):**
> Vineflower and CFR are downloaded automatically on first run. Vineflower is preferred; CFR is the fallback if Vineflower chokes on obfuscated bytecode.

**If Docker is missing:**
> 🚨 **Docker is REQUIRED** for Jarsec's dynamic sandbox. The suspicious mod MUST be detonated inside an isolated container.
>
> give me install commands for their OS. abort analysis until Docker is available.

**If other tools are missing:**
> ⚠️ Some optional tools are missing. Static analysis will work with reduced coverage. Dynamic analysis requires Docker only.
>
> give them install commands: `sudo apt-get install -y openjdk-21-jdk unzip xvfb tshark tcpdump strace python3-pip`

## Step 2: Target Type Check & Build Gate

1. Determine if target is a **JAR file** or **source code folder**.
2. **IF JAR:** Immediately spawn Agents 1, 2, 3, and 4 in parallel. Proceed to dynamic analysis once static agents report.
3. **IF SOURCE CODE FOLDER:** Spawn Agents 1, 2, 3, and 4 in parallel. **HOLD DYNAMIC ANALYSIS.** Wait for Agent 1 to complete its "Build Configuration Review."
   - If Agent 1 flags **SUSPICIOUS** or **FAIL** → **ABORT immediately**.
   - If Agent 1 marks **PASS** → fix CRLF (`sed -i 's/\r$//' gradlew`), attempt `./gradlew build`, then copy the built JAR to `"${TARGET_JAR}"` for dynamic analysis.

## Step 2.5: Decompile JAR (JAR targets only)

If the target is a **JAR file**, decompile the bytecode before spawning analysis agents. This gives the static analysis agents readable Java source instead of raw `.class` files.

### Download decompilers (auto-download on first run)

```bash
mkdir -p "$HOME/.jarsec/decompilers"

# Vineflower (primary)
if [ ! -f "$HOME/.jarsec/decompilers/vineflower.jar" ]; then
  echo "Downloading Vineflower..."
  LATEST_VF=$(curl -s https://api.github.com/repos/Vineflower/vineflower/releases/latest | grep -o '"tag_name": "[^"]*"' | cut -d'"' -f4)
  curl -sL -o "$HOME/.jarsec/decompilers/vineflower.jar" \
    "https://github.com/Vineflower/vineflower/releases/download/${LATEST_VF}/vineflower-${LATEST_VF}.jar" \
    || curl -sL -o "$HOME/.jarsec/decompilers/vineflower.jar" \
    "https://github.com/Vineflower/vineflower/releases/download/1.12.0/vineflower-1.12.0.jar"
fi

# CFR (fallback)
if [ ! -f "$HOME/.jarsec/decompilers/cfr.jar" ]; then
  echo "Downloading CFR..."
  LATEST_CFR=$(curl -s https://api.github.com/repos/leibnitz27/cfr/releases/latest | grep -o '"tag_name": "[^"]*"' | cut -d'"' -f4)
  curl -sL -o "$HOME/.jarsec/decompilers/cfr.jar" \
    "https://github.com/leibnitz27/cfr/releases/download/${LATEST_CFR}/cfr-${LATEST_CFR}.jar" \
    || curl -sL -o "$HOME/.jarsec/decompilers/cfr.jar" \
    "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
fi
```

### Extract and decompile

```bash
# Extract raw JAR contents for structural analysis
mkdir -p "${EXTRACTED_DIR}"
unzip -o "${TARGET_JAR}" -d "${EXTRACTED_DIR}"

# Decompile to readable Java source
mkdir -p "${DECOMPILED_DIR}"

# Try Vineflower first
if java -jar "$HOME/.jarsec/decompilers/vineflower.jar" "${TARGET_JAR}" "${DECOMPILED_DIR}/" 2>/tmp/jarsec_vf_err; then
  echo "Decompiled with Vineflower → ${DECOMPILED_DIR}/"
  DECOMPILER="vineflower"
# Fall back to CFR
elif java -jar "$HOME/.jarsec/decompilers/cfr.jar" "${TARGET_JAR}" --outputdir "${DECOMPILED_DIR}/" 2>/tmp/jarsec_cfr_err; then
  echo "Decompiled with CFR (fallback) → ${DECOMPILED_DIR}/"
  DECOMPILER="cfr"
else
  echo "⚠️ Both decompilers failed. Agents will analyze raw bytecode."
  DECOMPILER="none"
fi

# Verify decompilation produced files
find "${DECOMPILED_DIR}/" -type f | wc -l
```

### Directory layout for agents

| Path | Contents | Used by |
|------|----------|---------|
| `${EXTRACTED_DIR}` | Raw JAR contents (`.class`, `META-INF/`, configs) | Agent 1 (structural), fallback |
| `${DECOMPILED_DIR}` | Decompiled `.java` source files | Agents 2-4 (code analysis) |

**If target is SOURCE CODE folder:** Skip decompilation. Set `${DECOMPILED_DIR}` to the source folder path.

## Step 3: Static Analysis (4 Agents in Parallel)

### Agent 1 — Structural & Build Analyst
**Work on `${EXTRACTED_DIR}` for structural analysis. Reference `${DECOMPILED_DIR}` for class counts and package structure.**

1. Compute SHA256/MD5 of target files. Verify ZIP/JAR magic.
2. Map archive/source tree. List classes, mixins, assets, configs. Check `META-INF/MANIFEST.MF`.
3. Deeply inspect `build.gradle.kts`, `settings.gradle.kts`, `pom.xml`. Look for malicious repos, unauthorized buildscript deps, `exec`/`commandLine`/`ProcessBuilder` tasks, Shadow/FatJar abuse, hidden obfuscation.
   - **Verdict: PASS / SUSPICIOUS / FAIL**
4. Check nested JARs SHA256. Flag `.dll`, `.so`, `.dylib`, `.dat`. Flag known Weedhack signatures:
   - `/dev/jnic/lib/a125e430-2459-4702-9797-49fce5f280ae.dat`
   - `/dev/jnic/lib/c4f763d6-e34c-42e9-bba1-b80cfa5a55df.dat`
5. Read `fabric.mod.json`, `mods.toml`, `plugin.yml`. Extract MC version, loader, deps, entrypoints. **Pipe metadata to Dynamic Sandbox.**
6. Extract author info. Distinguish edgy branding from malicious signatures.
7. Scan `.png`, `.ogg`, `.json` for anomalous sizes, trailing EOF data, high-entropy buffers.
8. Report which decompiler was used (Vineflower / CFR / none) and how many `.java` files were produced.

### Agent 2 — Bytecode & Threat Analyst
**Work on `${DECOMPILED_DIR}` (decompiled Java source). If decompilation failed, fall back to `${EXTRACTED_DIR}` (raw bytecode).**

1. Search for infostealer keywords: `discord`, `webhook`, `token`, `session`, `steal`, `grab`, `exfil`, `rat`, `powershell`, `cmd.exe`.
2. Weedhack scan:
   - Packages: `me.mclauncher.*`, `dev.majanito.*`
   - Strings: `initializeWeedhack`, `WeedhackFile`, `$jnicLoader`, `JavaSecurityUpdater`, `KeyLoggingHandler`, `WebcamShareHandler`, `cfg.json`, `SecurityInfo.json`, `Updater.vbs`
3. Malicious APIs: `Runtime.exec`, `ProcessBuilder`, `URL`, `HttpURLConnection`, `Socket`, `HttpClient`, `InetAddress`, `System.getenv`, `Clipboard`.
4. Persistence: `launcher_profiles.json`, `launcher_accounts.json`, `-javaagent`, autostart, registry `Run`, `schtasks`.
5. Stage-2 droppers: `os.name`, `/tmp`, `%TEMP%`, `%APPDATA%`, `Files.write`, `FileOutputStream`, `URLClassLoader`.
6. Viral propagation: `ZipInputStream`, `JarFile`, disk iteration for `.jar`/`.zip`.
7. Log scrubbing: `System.setOut`, `System.setErr`, Log4j filter injection.

### Agent 3 — Network & Engine Analyst
**Work on `${DECOMPILED_DIR}` (decompiled Java source). If decompilation failed, fall back to `${EXTRACTED_DIR}` (raw bytecode).**

1. Extract hardcoded URLs, IPs, Discord webhooks, base64 endpoints. Flag Weedhack domains: `receiver.cy`, `weedhack.cy`.
2. Alternative C2: Telegram (`api.telegram.org`), Ethereum (`0xce6d41de`, RSA key `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtmNzDf...`).
3. Mixin review: List all SpongePowered mixins. Flag mixins intercepting `ClientPacketListener`, auth packets, `GameRenderer`, `LevelRenderer` without clear gameplay purpose.
4. BleedingPipe: `ObjectInputStream.readObject()`, `Kryo`, unvalidated reflection in packet handlers.

### Agent 4 — Evasion & Obfuscation Analyst
> ⚠️ **MUST complete in under 2 minutes.** Use ONLY batch recursive `grep -r`. **NEVER check files individually.**
> **Work on `${DECOMPILED_DIR}` (decompiled Java source). If decompilation failed, use `${EXTRACTED_DIR}` (raw bytecode).**

Run these 7 commands against `${DECOMPILED_DIR}`:

```bash
# 1. Known malware/obfuscation signatures
grep -rniE 'weedhack|jnic|protector|packer|obfusc|stub|dev\.jnic|BSOMwJ|fwcMeR|lXpXvp|\bα\b|\bβ\b' "${DECOMPILED_DIR}" 2>/dev/null | head -30

# 2. Reflection & dynamic execution
grep -rniE 'Class\.forName|Method\.invoke|MethodHandles|java\.lang\.reflect|ClassLoader\.defineClass' "${DECOMPILED_DIR}" 2>/dev/null | head -30

# 3. Native/JNI/JVM abuse
grep -rniE 'sun\.misc\.Unsafe|Instrumentation|VirtualMachine|System\.loadLibrary|System\.load|\bJNI\b|\bJNA\b' "${DECOMPILED_DIR}" 2>/dev/null | head -30

# 4. Anti-sandbox
grep -rniE 'availableProcessors|getProcessorCount|totalMemory|getMacAddress|Xvfb|docker|vmware|virtualbox|Add-MpPreference' "${DECOMPILED_DIR}" 2>/dev/null | head -30

# 5. High-entropy payloads
grep -rniE 'byte\[[[:space:]]*\][[:space:]]*\{[[:space:]]*0x[0-9a-fA-F]{2}' "${DECOMPILED_DIR}" 2>/dev/null | head -20

# 6. Steganographic decoding
grep -rniE 'ImageIO|BufferedImage|AudioInputStream|getRGB|getPixel|getData' "${DECOMPILED_DIR}" 2>/dev/null | head -20

# 7. Log scrubbing
grep -rniE 'System\.setOut|System\.setErr|System\.setIn|AppenderRef|ThresholdFilter' "${DECOMPILED_DIR}" 2>/dev/null | head -20
```

For each: report `NO MATCHES` or list `file:line: context` with assessment.

**End with: EVASION VERDICT: [CLEAN / SUSPICIOUS / MALICIOUS]**

## Step 4: Dynamic Sandbox (Docker — MANDATORY)

> Docker is mandatory. The suspicious mod must NEVER run directly on the host.

### Build Container
```bash
docker build -t jarsec-sandbox - <<-'EOF'
FROM eclipse-temurin:21-jdk
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends python3-pip xvfb libgl1 tcpdump > /dev/null 2>&1
RUN pip3 install --break-system-packages portablemc > /dev/null 2>&1
RUN mkdir -p /root/.minecraft/mods
WORKDIR /root
EOF
```

### Plant Honeytokens
```bash
docker run -d --name "jarsec-sandbox-${JARSEC_RUN##*/}" \
  -v "${TARGET_JAR}:/root/.minecraft/mods/target.jar:ro" \
  -e DISPLAY=:99 \
  jarsec-sandbox \
  bash -c "
    mkdir -p '/root/.config/discord/Local Storage/leveldb'
    echo '{\"token\":\"honeytoken_fake_discord_abc123\"}' > '/root/.config/discord/Local Storage/leveldb/000003.log'
    echo '{\"accounts\":[{\"accessToken\":\"honeytoken_minecraft_xyz789\",\"username\":\"HoneyPlayer\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}]}' > /root/.minecraft/launcher_accounts.json
    Xvfb :99 -screen 0 1024x768x16 &
    sleep 3600
  "
```

### Resolve Dependencies (from Agent 1 metadata)

**Robust dependency resolution — tries Modrinth first, falls back to Fabric Maven.**

```bash
# Helper: download from Modrinth with retry + fallback
jarsec_modrinth_fetch() {
  local PROJECT_ID="$1"
  local GAME_VER="$2"
  local OUTDIR="$3"
  local TEMP_RESP="${JARSEC_RUN}/modrinth_${PROJECT_ID}.json"

  # Try with game version filter first
  local URL="https://api.modrinth.com/v2/project/${PROJECT_ID}/version?loaders=%5B%22fabric%22%5D"
  if [ -n "$GAME_VER" ]; then
    URL="${URL}&game_versions=%5B%22${GAME_VER}%22%5D"
  fi

  echo "Fetching ${PROJECT_ID} from Modrinth..."
  local HTTP_CODE
  HTTP_CODE=$(curl -s -w "\n%{http_code}" --retry 3 --retry-delay 2 \
    -A "Mozilla/5.0 (Jarsec/1.0)" "$URL" -o "$TEMP_RESP" | tail -1)

  if [ "$HTTP_CODE" != "200" ] || [ ! -s "$TEMP_RESP" ]; then
    echo "Modrinth returned HTTP ${HTTP_CODE} or empty body for ${PROJECT_ID}"
    return 1
  fi

  # Parse first matching JAR URL
  python3 -c "
import sys, json
try:
    data = json.load(open('$TEMP_RESP'))
    for v in data:
        for f in v.get('files', []):
            if f['filename'].endswith('.jar') and not f['filename'].endswith('-sources.jar'):
                print(f['url'])
                sys.exit(0)
except Exception as e:
    print(f'PARSE_ERROR: {e}', file=sys.stderr)
" | while read -r JAR_URL; do
    if [ -n "$JAR_URL" ] && [ "${JAR_URL#PARSE_ERROR}" = "$JAR_URL" ]; then
      local FNAME=$(basename "$JAR_URL" | cut -d'?' -f1)
      echo "Downloading ${FNAME}..."
      curl -sL --retry 3 -o "${OUTDIR}/${FNAME}" "$JAR_URL" && echo "OK: ${OUTDIR}/${FNAME}"
      return 0
    fi
  done
  return 1
}

# Helper: fallback to Fabric Maven
jarsec_maven_fetch() {
  local GROUP="$1"
  local ARTIFACT="$2"
  local VERSION="$3"
  local OUTDIR="$4"
  local URL="https://maven.fabricmc.net/${GROUP//./\/}/${ARTIFACT}/${VERSION}/${ARTIFACT}-${VERSION}.jar"
  local FNAME="${ARTIFACT}-${VERSION}.jar"

  echo "Falling back to Fabric Maven: ${FNAME}..."
  if curl -sL --retry 3 --fail -o "${OUTDIR}/${FNAME}" "$URL"; then
    echo "OK: ${OUTDIR}/${FNAME}"
    return 0
  fi
  return 1
}

# Resolve Fabric API
MC_VERSION="${MC_VERSION:-1.21.1}"  # override from Agent 1 metadata
mkdir -p "${JARSEC_RUN}/deps"

jarsec_modrinth_fetch "P7dR8mSH" "$MC_VERSION" "${JARSEC_RUN}/deps" \
  || jarsec_maven_fetch "net.fabricmc.fabric-api" "fabric-api" "${FABRIC_API_VERSION:-0.115.0+${MC_VERSION}}" "${JARSEC_RUN}/deps"

# Resolve Fabric Language Kotlin
jarsec_modrinth_fetch "Ha28R6CL" "$MC_VERSION" "${JARSEC_RUN}/deps" \
  || jarsec_maven_fetch "net.fabricmc" "fabric-language-kotlin" "${FLK_VERSION:-1.13.0+kotlin.2.1.0}" "${JARSEC_RUN}/deps"

# Copy resolved deps into container
docker cp "${JARSEC_RUN}/deps/"*.jar "jarsec-sandbox-${JARSEC_RUN##*/}:/root/.minecraft/mods/" 2>/dev/null || echo "No deps to copy"
```

### Detonate
1. Start host tcpdump (if available): `sudo tcpdump -i any -w "${PCAP_FILE}" -U -nn &`
2. Dry run: `docker exec "jarsec-sandbox-${JARSEC_RUN##*/}" portablemc start fabric:VERSION --dry`
3. Live detonation (stream to main window):
   ```bash
   docker exec -e DISPLAY=:99 "jarsec-sandbox-${JARSEC_RUN##*/}" \
     timeout 300 portablemc start fabric:VERSION -u HoneyPlayer -i 00000000-0000-0000-0000-000000000001
   ```
4. If Java spawns, monitor with `docker exec` commands for lsof/jstack.
5. After analysis:
   ```bash
   docker stop "jarsec-sandbox-${JARSEC_RUN##*/}" && docker rm "jarsec-sandbox-${JARSEC_RUN##*/}"
   rm -rf "${JARSEC_RUN}"
   ```

## Step 5: Synthesis & Final Report

Compile findings from all agents + dynamic sandbox.

For each category state: **PASS / SUSPICIOUS / FAIL**

### IOCs
If suspicious/malicious activity found, list:
| Type | IOC |
|------|-----|
| Network | IPs, Domains, URLs, Telegram, Blockchain, Discord Webhooks |
| Host | SHA256 of payloads, modified paths, scheduled tasks, registry keys |

**Final verdict (single word): CLEAN / SUSPICIOUS / MALICIOUS**
