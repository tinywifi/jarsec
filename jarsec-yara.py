#!/usr/bin/env python3
"""
Jarsec YARA Generator — auto-generates YARA rules from analysis findings.

Usage:
    python3 jarsec-yara.py /path/to/analysis_workspace /path/to/target.jar

Generates a YARA rule from:
- Unique class names (obfuscated packages)
- Decrypted C2 URLs/domains
- Unique method names (decryptors, loaders)
- Bytecode magic + version fingerprint
- File size bounds

Output: yara_rule.yar
"""

import hashlib
import json
import re
import sys
from pathlib import Path
from uuid import uuid4


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_unique_strings(decompiled_dir: Path, extracted_strings: Path) -> dict:
    """Extract high-signal strings for YARA rule generation."""
    strings = {
        "classes": set(),
        "methods": set(),
        "urls": set(),
        "packages": set(),
    }

    # From decompiled source
    if decompiled_dir.exists():
        for java_file in decompiled_dir.rglob("*.java"):
            try:
                text = java_file.read_text(errors="replace")
            except Exception:
                continue

            # Package names
            for m in re.finditer(r'package\s+([\w.]+)', text):
                pkg = m.group(1)
                if len(pkg) > 8 and not pkg.startswith("java.") and not pkg.startswith("net."):
                    strings["packages"].add(pkg)

            # Class declarations
            for m in re.finditer(r'class\s+(\w+)', text):
                cls = m.group(1)
                if len(cls) > 6 and not cls.startswith("java"):
                    strings["classes"].add(cls)

            # Method names that look like decryptors/loaders
            for m in re.finditer(r'(?:static\s+)?(?:String|void|int)\s+(\w{2,8})\s*\(', text):
                method = m.group(1)
                if method not in ("main", "init", "run", "call", "get", "set", "toString"):
                    strings["methods"].add(method)

    # From extracted decrypted strings
    if extracted_strings.exists():
        text = extracted_strings.read_text(errors="replace")
        for m in re.finditer(r'https?://[^\s"<>|\\^`\[\]]+', text):
            url = m.group(0)
            # Extract domain only for YARA
            domain = re.sub(r'^https?://', '', url).split('/')[0]
            if domain and '.' in domain and len(domain) > 5:
                strings["urls"].add(domain)

    return {k: list(v)[:20] for k, v in strings.items()}  # cap at 20 each


def get_java_version_bytecode(jar_path: Path) -> tuple:
    """Extract Java version fingerprint from first .class file in JAR."""
    import zipfile
    try:
        with zipfile.ZipFile(jar_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.class'):
                    data = zf.read(name)
                    if len(data) > 8 and data[0:4] == b'\xca\xfe\xba\xbe':
                        major = int.from_bytes(data[6:8], 'big')
                        return major, name
    except Exception:
        pass
    return None, None


def generate_yara(target_jar: Path, workspace: Path, strings: dict) -> str:
    target_sha = sha256_file(target_jar)
    size = target_jar.stat().st_size
    rule_name = f"jarsec_{target_sha[:16]}"

    java_major, sample_class = get_java_version_bytecode(target_jar)
    java_hex = f"{java_major:04X}" if java_major else "????"

    yara_strings = []
    yara_conditions = [f"filesize < {size * 2}", f"filesize > {size // 2}"]

    idx = 1

    # Unique package/class names
    for pkg in strings.get("packages", [])[:5]:
        safe = re.sub(r'[^A-Za-z0-9]', '_', pkg)
        yara_strings.append(f'        $pkg_{idx} = "{pkg}" ascii wide')
        idx += 1

    for cls in strings.get("classes", [])[:8]:
        safe = re.sub(r'[^A-Za-z0-9]', '_', cls)
        yara_strings.append(f'        $cls_{idx} = "{cls}" ascii wide')
        idx += 1

    # Decryptor methods
    for method in strings.get("methods", [])[:5]:
        safe = re.sub(r'[^A-Za-z0-9]', '_', method)
        yara_strings.append(f'        $m_{idx} = "{method}" ascii wide')
        idx += 1

    # C2 domains
    for url in strings.get("urls", [])[:5]:
        safe = re.sub(r'[^A-Za-z0-9]', '_', url)
        yara_strings.append(f'        $c2_{idx} = "{url}" ascii wide')
        idx += 1

    # Java magic + version
    yara_strings.append(f'        $java_magic = {{ CA FE BA BE [4-8] 00 {java_hex} }}')
    yara_conditions.append("$java_magic")

    # Require some string matches
    total_strings = idx - 1
    if total_strings > 3:
        yara_conditions.append(f"4 of ($pkg_*, $cls_*, $m_*, $c2_*)")

    rule = f'''rule {rule_name} {{
    meta:
        description = "Auto-generated YARA rule from Jarsec analysis"
        author = "jarsec"
        date = "{__import__('datetime').datetime.now().isoformat()}"
        sha256 = "{target_sha}"
        sample = "{target_jar.name}"
        size = {size}
        java_version = "{java_major if java_major else 'unknown'}"

    strings:
{chr(10).join(yara_strings)}

    condition:
        { " and ".join(yara_conditions) }
}}
'''
    return rule


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} /path/to/workspace /path/to/target.jar")
        sys.exit(1)

    workspace = Path(sys.argv[1])
    target_jar = Path(sys.argv[2])

    decompiled = workspace / "decompiled"
    extracted = workspace / "extracted_strings.txt"

    strings = extract_unique_strings(decompiled, extracted)
    rule = generate_yara(target_jar, workspace, strings)

    out_path = workspace / "yara_rule.yar"
    out_path.write_text(rule)

    print(f"YARA rule: {out_path}")
    print(f"  Classes: {len(strings['classes'])}")
    print(f"  Packages: {len(strings['packages'])}")
    print(f"  Methods: {len(strings['methods'])}")
    print(f"  C2 Domains: {len(strings['urls'])}")
    print(f"")
    print(rule)


if __name__ == "__main__":
    main()
