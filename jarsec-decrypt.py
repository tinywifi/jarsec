#!/usr/bin/env python3
"""
Jarsec Static String Decryptor — reverse-engineers XOR and common obfuscation
schemes from decompiled Java source.

Usage:
    python3 jarsec-decrypt.py /path/to/decompiled/source

Scans for encrypted string literals passed to decryption methods, tries common
XOR/rotation/key-derivation strategies, and outputs decrypted strings that look
plausible (URLs, tokens, English words, etc.).
"""

import ast
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Optional

# ── String literal extraction from Java source ──────────────────────────────

JAVA_STRING_RE = re.compile(
    r'"((?:[^"\\]|\\.)*?)"'  # double-quoted string
)

JAVA_CHAR_RE = re.compile(
    r"'(?:[^'\\]|\\.)'"  # char literal
)

# Unicode escapes like A, \udc40
UNICODE_ESCAPE_RE = re.compile(r'\\u([0-9a-fA-F]{4})')

# Octal escapes like \101
OCTAL_ESCAPE_RE = re.compile(r'\\([0-3]?[0-7]{1,2})')

# Common escape sequences
ESCAPE_MAP = {
    '\\n': '\n', '\\r': '\r', '\\t': '\t', '\\b': '\b',
    '\\f': '\f', '\\\\': '\\', '\\"': '"', "\\'": "'",
}


def unescape_java(s: str) -> str:
    """Convert Java string literal escapes to actual Python string."""
    # Handle unicode escapes first
    def unicode_repl(m):
        return chr(int(m.group(1), 16))

    def octal_repl(m):
        return chr(int(m.group(1), 8))

    # Process \uXXXX escapes
    s = UNICODE_ESCAPE_RE.sub(unicode_repl, s)
    # Process \0..\377 octal escapes
    s = OCTAL_ESCAPE_RE.sub(octal_repl, s)
    # Process standard escapes
    for esc, repl in ESCAPE_MAP.items():
        s = s.replace(esc, repl)
    return s


# ── Decryption strategies ───────────────────────────────────────────────────

Strategy = Tuple[str, callable]


def make_strategies(key: int) -> List[Strategy]:
    """Build a list of (name, decrypt_func) pairs for a given integer key."""
    k32 = key & 0xFFFFFFFF
    kb = key.to_bytes(4, 'big', signed=True)
    kble = key.to_bytes(4, 'little', signed=True)

    strategies = [
        # 1. Simple XOR with key (char-wise)
        ("xor_const", lambda c, i: chr((c ^ k32) & 0xFFFF)),

        # 2. XOR with key + index
        ("xor_key_plus_idx", lambda c, i: chr((c ^ (k32 + i)) & 0xFFFF)),

        # 3. XOR with key - index
        ("xor_key_minus_idx", lambda c, i: chr((c ^ (k32 - i)) & 0xFFFF)),

        # 4. XOR with key XOR index
        ("xor_key_xor_idx", lambda c, i: chr((c ^ (k32 ^ i)) & 0xFFFF)),

        # 5. XOR with key * index
        ("xor_key_mul_idx", lambda c, i: chr((c ^ (k32 * (i + 1))) & 0xFFFF)),

        # 6. XOR with key rotated right by (i % 32)
        ("xor_rot_r_32", lambda c, i: chr((c ^ ((k32 >> (i % 32)) | (k32 << (32 - (i % 32))))) & 0xFFFF)),

        # 7. XOR with key rotated left by (i % 32)
        ("xor_rot_l_32", lambda c, i: chr((c ^ ((k32 << (i % 32)) | (k32 >> (32 - (i % 32))))) & 0xFFFF)),

        # 8. XOR with low 16 bits of key rotated by i
        ("xor_rot_r_16", lambda c, i: chr((c ^ ((k32 >> (i % 16)) | ((k32 & 0xFFFF) << (16 - (i % 16))))) & 0xFFFF)),

        # 9. XOR with byte from big-endian key bytes
        ("xor_byte_be", lambda c, i: chr(c ^ kb[i % 4])),

        # 10. XOR with byte from little-endian key bytes
        ("xor_byte_le", lambda c, i: chr(c ^ kble[i % 4])),

        # 11. XOR with key shifted right by (i * 8) mod 32
        ("xor_shift_r_byte", lambda c, i: chr((c ^ ((k32 >> ((i % 4) * 8)) & 0xFF)) & 0xFFFF)),

        # 12. XOR with key shifted left by (i * 8) mod 32
        ("xor_shift_l_byte", lambda c, i: chr((c ^ (((k32 << ((i % 4) * 8)) & 0xFFFFFFFF) >> 24)) & 0xFFFF)),

        # 13. XOR with key + (i * 1337) — common obfuscator pattern
        ("xor_key_plus_1337_idx", lambda c, i: chr((c ^ (k32 + i * 1337)) & 0xFFFF)),

        # 14. XOR with key where key changes per char: key = key * 31 + c
        ("xor_key_evolve", lambda c, i: chr((c ^ ((k32 * (31 ** (i + 1))) & 0xFFFFFFFF)) & 0xFFFF)),

        # 15. Add key instead of XOR (some obfuscators use addition)
        ("sub_const", lambda c, i: chr((c - k32) & 0xFFFF)),

        # 16. Add key + index
        ("sub_key_plus_idx", lambda c, i: chr((c - (k32 + i)) & 0xFFFF)),
    ]

    return strategies


# ── Readability scoring ─────────────────────────────────────────────────────

# High-value patterns that indicate successful decryption
VALUE_PATTERNS = [
    r'https?://',           # URLs
    r'discord',             # Discord references
    r'webhook',             # Webhooks
    r'token',               # Tokens
    r'minecraft',           # Minecraft
    r'fabric',              # Fabric loader
    r'session',             # Sessions
    r'localhost',
    r'\.com',
    r'\.net',
    r'\.org',
    r'\.xyz',
    r'\.cy',               # Weedhack domain
    r'receiver\.cy',
    r'weedhack',
    r'api\.telegram',
    r'POST',
    r'GET',
    r'Content-Type',
    r'Authorization',
    r'application/json',
    r'User-Agent',
]

VALUE_RE = re.compile('|'.join(VALUE_PATTERNS), re.IGNORECASE)

# Characters that are common in readable text
GOOD_CHARS = set(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    ' .,;:!?-_/\\@#$%^&*()[]{}<>+=~`|\'\"\n\t'
)


def score_result(s: str) -> float:
    """
    Score a decrypted string. Higher = more likely to be correct plaintext.
    Returns 0.0 for garbage, >0.5 for likely readable text.
    """
    if not s:
        return 0.0

    # Penalize strings with null bytes or lots of control chars
    bad_count = sum(1 for c in s if ord(c) < 32 and c not in '\n\t\r')
    if bad_count > max(1, len(s) * 0.05):
        return 0.0

    # Penalize replacement characters (decryption failed for some chars)
    if '�' in s:
        return 0.0

    # Check for high-value patterns
    pattern_score = len(VALUE_RE.findall(s)) * 0.3

    # Ratio of "good" printable characters
    printable = sum(1 for c in s if c in GOOD_CHARS or ord(c) > 127 and ord(c) < 0x10000)
    printable_ratio = printable / len(s)

    # ASCII ratio (most decrypted strings are ASCII)
    ascii_count = sum(1 for c in s if ord(c) < 128)
    ascii_ratio = ascii_count / len(s)

    # Length bonus (very short strings are less interesting)
    length_bonus = min(len(s) / 20.0, 1.0)

    # Combine
    score = (printable_ratio * 0.3 +
             ascii_ratio * 0.2 +
             pattern_score +
             length_bonus * 0.1)

    return min(score, 2.0)  # cap at 2.0


def is_likely_readable(s: str) -> bool:
    """Quick check: does this look like readable text?"""
    return score_result(s) >= 0.5


# ── Source scanning ─────────────────────────────────────────────────────────

# Pattern to find decryption method calls like:
#   zPdoG.rn("encrypted", -12345)
#   SomeClass.decrypt("encrypted", 0xDEADBEEF)
#   Utils.getString("encrypted", 42)
DECRYPT_CALL_RE = re.compile(
    r'\b(\w+)\.(\w+)\s*\(\s*"((?:[^"\\]|\\.)*?)"\s*,\s*(-?\d+|0x[0-9a-fA-F]+)\s*\)',
    re.MULTILINE
)

# Also catch multi-line strings spanning lines
DECRYPT_CALL_MULTILINE_RE = re.compile(
    r'\b(\w+)\.(\w+)\s*\(\s*"((?:[^"\\]|\\.)*?)"\s*\+\s*"((?:[^"\\]|\\.)*?)"\s*,\s*(-?\d+|0x[0-9a-fA-F]+)\s*\)',
    re.MULTILINE
)


def parse_key(key_str: str) -> int:
    """Parse a Java integer literal."""
    key_str = key_str.strip()
    if key_str.startswith('0x') or key_str.startswith('0X'):
        return int(key_str, 16)
    return int(key_str)


def scan_file(path: Path) -> List[Tuple[str, str, str, int, str]]:
    """
    Scan a single Java file for encrypted string calls.
    Returns list of (filename, class_name, method_name, key, encrypted_string).
    """
    results = []
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return results

    # Simple one-line calls
    for m in DECRYPT_CALL_RE.finditer(text):
        class_name, method_name, encrypted, key_str = m.groups()
        try:
            key = parse_key(key_str)
            encrypted_unescaped = unescape_java(encrypted)
            results.append((path.name, class_name, method_name, key, encrypted_unescaped))
        except Exception:
            continue

    # Multi-line concatenated strings
    for m in DECRYPT_CALL_MULTILINE_RE.finditer(text):
        class_name, method_name, enc1, enc2, key_str = m.groups()
        try:
            key = parse_key(key_str)
            encrypted_unescaped = unescape_java(enc1) + unescape_java(enc2)
            results.append((path.name, class_name, method_name, key, encrypted_unescaped))
        except Exception:
            continue

    return results


# ── Decryption engine ───────────────────────────────────────────────────────

MAX_RESULTS_PER_PAIR = 3  # Don't flood output with every strategy


def decrypt_all(source_dir: Path) -> List[dict]:
    """
    Scan all Java files, find encrypted strings, try to decrypt them.
    Returns list of dicts with decryption results.
    """
    all_calls = []

    # Collect all encrypted string calls
    for java_file in source_dir.rglob("*.java"):
        calls = scan_file(java_file)
        all_calls.extend(calls)

    if not all_calls:
        return []

    # Group by (class_name, method_name) to find decryption routines
    methods = {}
    for filename, class_name, method_name, key, encrypted in all_calls:
        sig = (class_name, method_name)
        if sig not in methods:
            methods[sig] = []
        methods[sig].append((filename, key, encrypted))

    results = []

    for (class_name, method_name), calls in methods.items():
        # Try to find the best strategy for this method
        best_strategy = None
        best_score = 0.0
        best_decryptions = []

        # Try each strategy against all calls for this method
        # We test on a sample first (up to 10 calls)
        sample = calls[:10]

        for strategy_name, strategy_fn in make_strategies(0):  # dummy key, will vary
            total_score = 0.0
            sample_results = []

            for filename, key, encrypted in sample:
                _, actual_fn = next(
                    (n, f) for n, f in make_strategies(key)
                    if n == strategy_name
                )
                try:
                    decrypted = ''.join(
                        actual_fn(ord(c), i)
                        for i, c in enumerate(encrypted)
                    )
                    sc = score_result(decrypted)
                    total_score += sc
                    sample_results.append((filename, key, encrypted, decrypted, sc))
                except Exception:
                    continue

            if total_score > best_score:
                best_score = total_score
                best_strategy = strategy_name
                best_decryptions = sample_results

        # If we found a promising strategy, decrypt ALL calls with it
        if best_score >= 0.3:
            # Get the actual decrypt function for each key
            all_decryptions = []
            for filename, key, encrypted in calls:
                _, actual_fn = next(
                    (n, f) for n, f in make_strategies(key)
                    if n == best_strategy
                )
                try:
                    decrypted = ''.join(
                        actual_fn(ord(c), i)
                        for i, c in enumerate(encrypted)
                    )
                    sc = score_result(decrypted)
                    if sc >= 0.3:
                        all_decryptions.append({
                            'file': filename,
                            'method': f"{class_name}.{method_name}",
                            'strategy': best_strategy,
                            'key': key,
                            'encrypted_preview': encrypted[:60] + ('...' if len(encrypted) > 60 else ''),
                            'decrypted': decrypted,
                            'score': round(sc, 2),
                        })
                except Exception:
                    continue

            results.extend(all_decryptions)

    # Sort by score descending
    results.sort(key=lambda x: x['score'], reverse=True)
    return results


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/decompiled/source")
        sys.exit(1)

    source_dir = Path(sys.argv[1])
    if not source_dir.exists():
        print(f"Error: {source_dir} does not exist")
        sys.exit(1)

    print(f"Scanning {source_dir} for encrypted strings...")
    results = decrypt_all(source_dir)

    if not results:
        print("No encrypted strings found or no successful decryptions.")
        sys.exit(0)

    # Deduplicate by decrypted value
    seen = set()
    unique_results = []
    for r in results:
        if r['decrypted'] not in seen:
            seen.add(r['decrypted'])
            unique_results.append(r)

    print(f"\nFound {len(unique_results)} unique decrypted strings:\n")
    print("-" * 80)

    for r in unique_results:
        print(f"Method:    {r['method']}")
        print(f"Strategy:  {r['strategy']}")
        print(f"Key:       {r['key']}")
        print(f"Encrypted: {r['encrypted_preview']!r}")
        print(f"Decrypted: {r['decrypted']!r}")
        print(f"Score:     {r['score']}")
        print("-" * 80)

    # Output just the strings for grepping
    print("\n=== PLAINTEXT STRINGS ===")
    for r in unique_results:
        print(r['decrypted'])


if __name__ == '__main__':
    main()
