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

### Run static string decryptor

```bash
# Ensure decryptor is available (auto-download from repo if missing)
DECRYPTOR="$HOME/.claude/skills/jarsec/jarsec-decrypt.py"
if [ ! -f "$DECRYPTOR" ]; then
  mkdir -p "$HOME/.jarsec"
  curl -sL -o "$DECRYPTOR" \
    "https://raw.githubusercontent.com/tinywifi/jarsec/main/jarsec-decrypt.py" 2>/dev/null || true
fi

if [ -f "$DECRYPTOR" ]; then
  python3 "$DECRYPTOR" "${DECOMPILED_DIR}" > "${JARSEC_RUN}/decrypted_strings.txt" 2> "${JARSEC_RUN}/decryptor_errors.log" || true
  if [ -s "${JARSEC_RUN}/decrypted_strings.txt" ]; then
    echo "=== DECRYPTED STRINGS ==="
    tail -n +$(grep -n "PLAINTEXT STRINGS" "${JARSEC_RUN}/decrypted_strings.txt" | tail -1 | cut -d: -f1) "${JARSEC_RUN}/decrypted_strings.txt" 2>/dev/null | head -50
    echo "--- Full output: ${JARSEC_RUN}/decrypted_strings.txt ---"
  else
    echo "No encrypted strings decrypted."
  fi
else
  echo "⚠️ jarsec-decrypt.py not found. Install from https://github.com/tinywifi/jarsec"
fi
```

### Run dynamic string extractor (caller-context obfuscation)

> For obfuscators like zPdoG.rn() that use `StackWalker.getCallerClass().getName().hashCode()` as part of
the key, static brute-force can't reverse the algorithm. Instead, load the actual class via reflection —
the static initializer (`<clinit>`) decrypts strings with the correct caller context automatically.

```bash
# Ensure extractor is available (auto-download from repo if missing)
EXTRACTOR="$HOME/.claude/skills/jarsec/jarsec-extract.py"
if [ ! -f "$EXTRACTOR" ]; then
  curl -sL -o "$EXTRACTOR" \
    "https://raw.githubusercontent.com/tinywifi/jarsec/main/jarsec-extract.py" 2>/dev/null || true
fi

if [ -f "$EXTRACTOR" ] && [ -d "${DECOMPILED_DIR}" ]; then
  echo "Running dynamic string extractor..."
  python3 "$EXTRACTOR" "${TARGET_JAR}" "${DECOMPILED_DIR}" > "${JARSEC_RUN}/extracted_strings.txt" 2> "${JARSEC_RUN}/extractor_errors.log" || true
  if [ -s "${JARSEC_RUN}/extracted_strings.txt" ]; then
    echo "=== EXTRACTED STRINGS (via reflection) ==="
    grep -E "^  \[|^  [A-Za-z]|^---" "${JARSEC_RUN}/extracted_strings.txt" | head -60
    echo "--- Full output: ${JARSEC_RUN}/extracted_strings.txt ---"
  fi
else
  echo "⚠️ jarsec-extract.py not found or no decompiled source."
fi
```
```

**If target is SOURCE CODE folder:** Skip decompilation. Set `${DECOMPILED_DIR}` to the source folder path.

## Step 3: Static Analysis (4 Agents in Parallel)

### Agent 1 — Structural & Build Analyst
> ⚠️ **Do NOT use `javap` on individual `.class` files.** Decompiled `.java` source is already available at `${DECOMPILED_DIR}`. Read those instead.

1. Compute SHA256/MD5 of target files. Verify ZIP/JAR magic.
2. **Structural mapping (use `${EXTRACTED_DIR}`):**
   - List top-level packages, class count, file types
   - Check `META-INF/MANIFEST.MF`
   - Read `fabric.mod.json`, `mods.toml`, `plugin.yml` — extract MC version, loader, deps, entrypoints. **Pipe metadata to Dynamic Sandbox.**
   - Scan `.png`, `.ogg`, `.json` for anomalous sizes, trailing EOF data, high-entropy buffers
3. **Build config scan (use `${EXTRACTED_DIR}` or source root):**
   - Inspect `build.gradle.kts`, `settings.gradle.kts`, `pom.xml` for malicious repos, unauthorized buildscript deps, `exec`/`commandLine`/`ProcessBuilder`, Shadow/FatJar abuse
   - **Verdict: PASS / SUSPICIOUS / FAIL**
4. Check nested JARs SHA256. Flag `.dll`, `.so`, `.dylib`, `.dat`. Flag known Weedhack signatures:
   - `/dev/jnic/lib/a125e430-2459-4702-9797-49fce5f280ae.dat`
   - `/dev/jnic/lib/c4f763d6-e34c-42e9-bba1-b80cfa5a55df.dat`
5. **Code structure (use `${DECOMPILED_DIR}` .java files, NOT `javap`):**
   - List decompiled classes, packages, entrypoints (`onInitialize`, `main`, `premain`)
   - Read 3-5 most interesting `.java` files (largest, entrypoint, network-related) to understand architecture
   - Look for method signatures: `ProcessBuilder`, `HttpClient`, `Socket`, `URLClassLoader`, `defineClass`
6. Extract author info. Distinguish edgy branding from malicious signatures.
7. Report which decompiler was used (Vineflower / CFR / none) and how many `.java` files were produced.
8. If decrypted/extracted strings are available (`${JARSEC_RUN}/decrypted_strings.txt`, `${JARSEC_RUN}/extracted_strings.txt`), summarize key findings — especially C2 URLs, webhooks, tokens.

### Agent 2 — Bytecode & Threat Analyst
**Work on `${DECOMPILED_DIR}` (decompiled Java source). If decompilation failed, fall back to `${EXTRACTED_DIR}` (raw bytecode).**

1. Search for infostealer keywords: `discord`, `webhook`, `token`, `session`, `steal`, `grab`, `exfil`, `rat`, `powershell`, `cmd.exe`.
2. Weedhack scan:
   - Packages: `me.mclauncher.*`, `dev.majanito.*`
   - Strings: `initializeWeedhack`, `WeedhackFile`, `$jnicLoader`, `JavaSecurityUpdater`, `KeyLoggingHandler`, `WebcamShareHandler`, `cfg.json`, `SecurityInfo.json`, `Updater.vbs`
3. Malicious APIs: `Runtime.exec`, `ProcessBuilder`, `URL`, `HttpURLConnection`, `Socket`, `HttpClient`, `InetAddress`, `System.getenv`, `Clipboard`.
4. Persistence: `launcher_profiles.json`, `launcher_accounts.json`, `-javaagent`, autostart, registry `Run`, `schtasks`.
5. Stage-2 droppers: `os.name`, `/tmp`, `%TEMP%`, `%APPDATA%`, `Files.write`, `FileOutputStream`, `URLClassLoader`, `defineClass`.
   - **Flag for stage-2 analysis** if `URLClassLoader` + `defineClass` found together
   - Extract download URLs from decrypted strings and decompiled source
6. Viral propagation: `ZipInputStream`, `JarFile`, disk iteration for `.jar`/`.zip`.
7. Log scrubbing: `System.setOut`, `System.setErr`, Log4j filter injection.

### Agent 3 — Network & Engine Analyst
> ⚠️ **Use ONLY batch recursive `grep -r`. NEVER read files individually.** Token budget is tight.
> **Work on `${DECOMPILED_DIR}` (decompiled Java source). If decompilation failed, use `${EXTRACTED_DIR}` (raw bytecode).**

Run these 6 commands against `${DECOMPILED_DIR}`:

```bash
# 1. URLs, IPs, Discord webhooks, Telegram
grep -roniE 'https?://[^"\s<>{}|\^`\[\]]+|discord(app)?\.(com|gg)/api/webhooks/[0-9]+/[^"\s]+|api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+|\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]+)?\b' "${DECOMPILED_DIR}" 2>/dev/null | head -40

# 2. Base64-like strings (40+ chars of A-Za-z0-9+/=)
grep -roniE '\b[A-Za-z0-9+/]{40,}={0,2}\b' "${DECOMPILED_DIR}" 2>/dev/null | head -30

# 3. Weedhack / known C2 domains
grep -roniE 'receiver\.cy|weedhack\.cy|0xce6d41de|MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtmNzDf' "${DECOMPILED_DIR}" 2>/dev/null | head -20

# 4. Mixin injections (SpongePowered)
grep -roniE '@Mixin\s*\(|class\s+\w+.*implements.*Mixin|@Inject.*method.*=.*\{|@Redirect.*method.*=.*\{' "${DECOMPILED_DIR}" 2>/dev/null | head -30

# 5. Mixin target classes of interest
grep -roniE 'ClientPacketListener|ServerGamePacketListener|GameRenderer|LevelRenderer|PlayerList|Connection' "${DECOMPILED_DIR}" 2>/dev/null | head -30

# 6. BleedingPipe / deserialization vectors
grep -roniE 'ObjectInputStream\.readObject\(\)|Kryo|readUnshared\(\)|ObjectOutputStream' "${DECOMPILED_DIR}" 2>/dev/null | head -20
```

For each: report `NO MATCHES` or list `file:line: match` with assessment.

**Also scan decrypted strings** from Step 2.6 if available — pipe them through the same URL/IP/webhook regexes.

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

## Step 4.5: Stage-2 Payload Analysis (if found)

If Agent 2 or dynamic sandbox flagged **stage-2 droppers** (`URLClassLoader`, `defineClass`, `BOVhZh.AKH()`, etc.), automatically hunt and analyze the secondary payload.

### Extract stage-2 download URLs

```bash
# From decrypted/extracted strings
grep -oiE 'https?://[^"\s<>{}|\^`\[\]]+\.(jar|zip|class|dat|bin)' "${JARSEC_RUN}/decrypted_strings.txt" "${JARSEC_RUN}/extracted_strings.txt" 2>/dev/null | sort -u > "${JARSEC_RUN}/stage2_urls.txt"

# From decompiled source (additional URL patterns)
grep -roniE 'https?://[^"\s<>{}|\^`\[\]]+' "${DECOMPILED_DIR}" 2>/dev/null | grep -iE '\.(jar|zip|dat|bin|exe|dll|so)$' | sort -u >> "${JARSEC_RUN}/stage2_urls.txt"

# From pcap (if tcpdump captured anything)
if [ -f "${PCAP_FILE}" ]; then
  tshark -r "${PCAP_FILE}" -Y "http.request or tls.handshake" -T fields -e http.host -e tls.handshake.extensions_server_name 2>/dev/null | tr ',' '\n' | grep -viE 'ubuntu|cloudflare|kimi|modrinth|fabricmc|minecraft' | sort -u >> "${JARSEC_RUN}/stage2_urls.txt" || true
fi

# Deduplicate
sort -u -o "${JARSEC_RUN}/stage2_urls.txt" "${JARSEC_RUN}/stage2_urls.txt"
wc -l "${JARSEC_RUN}/stage2_urls.txt"
```

### Download and analyze stage-2 payloads

```bash
STAGE2_DIR="${JARSEC_RUN}/stage2"
mkdir -p "$STAGE2_DIR"

STAGE2_COUNT=0
while IFS= read -r url; do
  [ -z "$url" ] && continue
  # Only download http(s) URLs
  [[ "$url" =~ ^https?:// ]] || continue

  STAGE2_COUNT=$((STAGE2_COUNT + 1))
  STAGE2_FILE="${STAGE2_DIR}/payload_${STAGE2_COUNT}"
  echo "Downloading stage-2 payload: $url"

  # Download with strict timeouts
  if curl -sL --max-time 30 --connect-timeout 10 -o "$STAGE2_FILE" "$url" 2>/dev/null; then
    SIZE=$(wc -c < "$STAGE2_FILE")
    SHA=$(sha256sum "$STAGE2_FILE" | cut -d' ' -f1)
    echo "  Size: ${SIZE} bytes | SHA256: ${SHA}"

    # If it's a JAR, run static analysis on it
    if file "$STAGE2_FILE" | grep -qi 'zip\|jar\|java'; then
      echo "  JAR detected — running jarsec static analysis..."

      # Create isolated workspace for stage-2
      S2_RUN=$(mktemp -d "/tmp/jarsec_stage2_${STAGE2_COUNT}_XXXXXX")
      S2_EXTRACTED="${S2_RUN}/extracted"
      S2_DECOMPILED="${S2_RUN}/decompiled"
      mkdir -p "$S2_EXTRACTED" "$S2_DECOMPILED"

      # Extract
      unzip -o "$STAGE2_FILE" -d "$S2_EXTRACTED" 2>/dev/null || true

      # Decompile with Vineflower
      if java -jar "$HOME/.jarsec/decompilers/vineflower.jar" "$STAGE2_FILE" "$S2_DECOMPILED/" 2>/dev/null; then
        echo "  Decompiled stage-2 → ${S2_DECOMPILED}/"
      elif java -jar "$HOME/.jarsec/decompilers/cfr.jar" "$STAGE2_FILE" --outputdir "$S2_DECOMPILED/" 2>/dev/null; then
        echo "  Decompiled stage-2 with CFR → ${S2_DECOMPILED}/"
      fi

      # Quick static analysis (grep-based, no agents to save tokens)
      echo ""
      echo "  === STAGE-2 QUICK ANALYSIS ==="
      echo "  Entrypoints:"
      grep -roniE 'public static void main\(' "$S2_DECOMPILED" 2>/dev/null | head -5
      grep -roniE 'onInitialize|onClientSetup|premain' "$S2_DECOMPILED" 2>/dev/null | head -5

      echo ""
      echo "  Suspicious APIs:"
      grep -roniE 'Runtime\.exec|ProcessBuilder|URLClassLoader|defineClass|HttpClient|HttpURLConnection|Socket|InetAddress' "$S2_DECOMPILED" 2>/dev/null | head -10

      echo ""
      echo "  Network:"
      grep -roniE 'https?://[^"\s<>{}|\^`\[\]]+' "$S2_DECOMPILED" 2>/dev/null | sort -u | head -10

      echo ""
      echo "  Obfuscation:"
      grep -roniE 'Class\.forName|Method\.invoke|MethodHandles|ClassLoader\.defineClass|sun\.misc\.Unsafe' "$S2_DECOMPILED" 2>/dev/null | head -5

      echo ""
      echo "  --- Stage-2 workspace: ${S2_RUN} ---"
    fi
  else
    echo "  Failed to download"
  fi
done < "${JARSEC_RUN}/stage2_urls.txt"

echo ""
echo "Stage-2 analysis complete. ${STAGE2_COUNT} URL(s) processed."
```

### Report stage-2 findings

For each downloaded payload, include in final report:
| Field | Value |
|-------|-------|
| URL | Source URL |
| SHA256 | Payload hash |
| Size | Bytes |
| Type | JAR / EXE / DLL / Other |
| Static Verdict | CLEAN / SUSPICIOUS / MALICIOUS (from quick grep) |

## Step 5: Synthesis & Final Report

Compile findings from all agents + dynamic sandbox + stage-2 analysis.

For each category state: **PASS / SUSPICIOUS / FAIL**

### IOCs
If suspicious/malicious activity found, list:
| Type | IOC |
|------|-----|
| Network | IPs, Domains, URLs, Telegram, Blockchain, Discord Webhooks |
| Host | SHA256 of payloads, modified paths, scheduled tasks, registry keys |
| Stage-2 | URLs, SHA256s, and verdicts of secondary payloads |

**Final verdict (single word): CLEAN / SUSPICIOUS / MALICIOUS**
