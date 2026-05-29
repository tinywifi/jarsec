#!/usr/bin/env python3
"""
Jarsec Static Analyzer — Single-pass analysis script.
Replaces 20+ agent tool calls with one Python execution.
Outputs structured JSON for the orchestrator to synthesize.

Usage:
    python3 jarsec-analyze.py /path/to/target

Target can be a source directory or a JAR file.
"""

import json
import os
import re
import sys
import hashlib
import zipfile
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def grep_tree(root: Path, pattern: str, extensions=(".java", ".kt", ".gradle", ".kts", ".xml", ".json")) -> list:
    """Recursively grep for regex pattern in source files."""
    matches = []
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in extensions:
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                    for i, line in enumerate(text.splitlines(), 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            matches.append(f"{path}:{i}:{line.strip()}")
                except Exception:
                    pass
    except Exception:
        pass
    return matches[:50]  # cap output


def analyze_build_config(root: Path) -> dict:
    """Analyze build files for malicious repos, tasks, obfuscation."""
    result = {"files_checked": [], "issues": [], "verdict": "PASS"}
    build_files = list(root.rglob("build.gradle*")) + list(root.rglob("settings.gradle*")) + list(root.rglob("pom.xml"))
    for bf in build_files:
        result["files_checked"].append(str(bf))
        text = bf.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"exec\s*\(|commandLine|ProcessBuilder|Runtime\.getRuntime\(\)\.exec", text):
            result["issues"].append(f"{bf}: Found exec/commandLine/ProcessBuilder — investigate")
            result["verdict"] = "SUSPICIOUS"
        if re.search(r"shadow|fatjar|proguard|r8", text, re.I):
            result["issues"].append(f"{bf}: Shadow/ProGuard/R8 detected — verify legitimacy")
        if re.search(r"jnic|weedhack", text, re.I):
            result["issues"].append(f"{bf}: KNOWN MALWARE SIGNATURE")
            result["verdict"] = "FAIL"
    return result


def analyze_threats(root: Path) -> dict:
    """Agent 2: Infostealer signatures, Weedhack, malicious APIs."""
    signatures = {
        "infostealer": r"discord|webhook|token|session|steal|grab|exfil|rat|powershell|cmd\.exe",
        "weedhack": r"weedhack|initializeWeedhack|WeedhackFile|\$jnicLoader|JavaSecurityUpdater|KeyLoggingHandler|WebcamShareHandler|ScreenShareHandler|me\.mclauncher|dev\.majanito",
        "malicious_api": r"Runtime\.getRuntime\(\)|ProcessBuilder|HttpURLConnection|URLClassLoader|Clipboard|getSystemClipboard",
        "persistence": r"launcher_profiles|launcher_accounts|-javaagent|autostart|schtasks|registry",
        "droppers": r"os\.name|/tmp/|%TEMP%|%APPDATA%|Files\.write|FileOutputStream",
        "viral": r"ZipInputStream|ZipOutputStream|JarFile|JarOutputStream",
        "log_scrub": r"System\.setOut|System\.setErr|ThresholdFilter",
    }
    results = {}
    for name, pattern in signatures.items():
        matches = grep_tree(root, pattern)
        results[name] = {"count": len(matches), "matches": matches[:10]}
    return results


def analyze_network(root: Path) -> dict:
    """Agent 3: URLs, C2, mixins, deserialization."""
    # Hardcoded URLs / IPs
    url_pattern = r"https?://[^\s\"'<>]+"
    url_matches = grep_tree(root, url_pattern)

    # Weedhack domains
    weedhack_domains = grep_tree(root, r"receiver\.cy|weedhack\.cy")

    # Telegram / blockchain
    alt_c2 = grep_tree(root, r"api\.telegram\.org|0x[0-9a-fA-F]{40}|MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtmNzDf")

    # BleedingPipe
    deserialization = grep_tree(root, r"ObjectInputStream\.readObject|Kryo|readUnshared")

    # Mixin review
    mixin_files = list((root / "src" / "main" / "java").rglob("*.java")) if (root / "src" / "main" / "java").exists() else []
    mixins = []
    for mf in mixin_files:
        if "Mixin" in mf.name or "Accessor" in mf.name:
            text = mf.read_text(encoding="utf-8", errors="ignore")
            targets = re.findall(r"@Mixin\((.+?)\)", text)
            injects = re.findall(r"@(Inject|Redirect|ModifyVariable|ModifyArg|WrapOperation)\b", text)
            if targets or injects:
                mixins.append({
                    "file": str(mf),
                    "targets": targets,
                    "injections": injects,
                    "suspicious": any(t in text for t in ["ClientPacketListener", "GameRenderer", "LevelRenderer"])
                })

    return {
        "urls": url_matches[:20],
        "weedhack_domains": weedhack_domains,
        "alt_c2": alt_c2,
        "deserialization": deserialization,
        "mixins": mixins,
    }


def analyze_evasion(root: Path) -> dict:
    """Agent 4: Obfuscation, reflection, anti-sandbox, JVM abuse."""
    checks = {
        "reflection": r"Class\.forName|Method\.invoke|MethodHandles|java\.lang\.reflect|ClassLoader\.defineClass",
        "native_jvm": r"sun\.misc\.Unsafe|Instrumentation|VirtualMachine|System\.loadLibrary|JNI|JNA",
        "anti_sandbox": r"availableProcessors|getProcessorCount|totalMemory|getMacAddress|Xvfb|vmware|virtualbox|Add-MpPreference",
        "embedded_payloads": r"byte\[\s*\]\s*\{\s*0x[0-9a-fA-F]{2}",
        "steganography": r"ImageIO|BufferedImage|AudioInputStream|getRGB|getPixel",
        "obfuscation": r"dev\.jnic|BSOMwJ|fwcMeR|lXpXvp|\bα\b|\bβ\b",
    }
    results = {}
    for name, pattern in checks.items():
        matches = grep_tree(root, pattern)
        results[name] = {"count": len(matches), "matches": matches[:10]}
    return results


def analyze_assets(root: Path) -> dict:
    """Check PNGs for trailing data, OGGs, JSON validity."""
    assets_dir = root / "src" / "main" / "resources"
    results = {"pngs_checked": 0, "pngs_with_trailing_data": 0, "assets": []}
    if not assets_dir.exists():
        return results
    for f in assets_dir.rglob("*.png"):
        results["pngs_checked"] += 1
        data = f.read_bytes()
        iend = data.rfind(b"IEND")
        if iend != -1 and len(data) > iend + 8:
            trailing = len(data) - (iend + 8)
            if trailing > 0:
                results["pngs_with_trailing_data"] += 1
                results["assets"].append(f"{f}: {trailing} bytes trailing after IEND")
    return results


def analyze_jar(jar_path: Path) -> dict:
    """If target is a JAR, introspect its contents."""
    result = {"type": "jar", "sha256": sha256_file(jar_path), "nested_jars": [], "native_files": [], "classes": 0}
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".jar"):
                    result["nested_jars"].append(name)
                if any(name.endswith(ext) for ext in [".dll", ".so", ".dylib"]):
                    result["native_files"].append(name)
                if name.endswith(".class"):
                    result["classes"] += 1
    except Exception as e:
        result["error"] = str(e)
    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jarsec-analyze.py /path/to/target", file=sys.stderr)
        sys.exit(1)

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(json.dumps({"error": f"Target not found: {target}"}))
        sys.exit(1)

    output = {"target": str(target), "is_jar": target.suffix == ".jar"}

    if output["is_jar"]:
        output["jar_analysis"] = analyze_jar(target)
        # Also treat as source if there's a src/ alongside
        src_dir = target.parent / "src"
        if src_dir.exists():
            target = src_dir.parent
            output["source_dir"] = str(target)

    if target.is_dir():
        output["build_config"] = analyze_build_config(target)
        output["threats"] = analyze_threats(target)
        output["network"] = analyze_network(target)
        output["evasion"] = analyze_evasion(target)
        output["assets"] = analyze_assets(target)

    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()
