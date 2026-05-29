#!/usr/bin/env python3
"""
Jarsec Decryptor Discovery — finds string decryption routines in JARs without
running any code. Scans bytecode to identify methods with (String,int)->String
signatures that are called heavily with string literals.

Usage:
    python3 jarsec-discover.py /path/to/jar/or/extracted/classes

Outputs:
    - Candidate decryptor methods ranked by call frequency
    - All encrypted string + key pairs extracted from call sites
    - A JSON file that the JVM agent or decryptor can consume
"""

import json
import os
import re
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set

# ── Java bytecode constants ─────────────────────────────────────────────────

# Constant pool tags
TAG_UTF8 = 1
TAG_INTEGER = 3
TAG_FLOAT = 4
TAG_LONG = 5
TAG_DOUBLE = 6
TAG_CLASS = 7
TAG_STRING = 8
TAG_FIELDREF = 9
TAG_METHODREF = 10
TAG_INTERFACE_METHODREF = 11
TAG_NAME_AND_TYPE = 12
TAG_METHOD_HANDLE = 15
TAG_METHOD_TYPE = 16
TAG_DYNAMIC = 17
TAG_INVOKE_DYNAMIC = 18
TAG_MODULE = 19
TAG_PACKAGE = 20

# Opcodes we care about
OP_LDC = 0x12
OP_LDC_W = 0x13
OP_LDC2_W = 0x14
OP_INVOKESTATIC = 0xB8
OP_ICONST_M1 = 0x02
OP_ICONST_0 = 0x03
OP_ICONST_1 = 0x04
OP_ICONST_2 = 0x05
OP_ICONST_3 = 0x06
OP_ICONST_4 = 0x07
OP_ICONST_5 = 0x08
OP_BIPUSH = 0x10
OP_SIPUSH = 0x11


def read_u1(f):
    return struct.unpack(">B", f.read(1))[0]

def read_u2(f):
    return struct.unpack(">H", f.read(2))[0]

def read_u4(f):
    return struct.unpack(">I", f.read(4))[0]


def parse_constant_pool(f) -> List[Tuple]:
    """Parse Java constant pool. Returns list of (tag, value) tuples."""
    count = read_u2(f)
    pool = [None]  # 1-indexed

    i = 1
    while i < count:
        tag = read_u1(f)
        if tag == TAG_UTF8:
            length = read_u2(f)
            value = f.read(length).decode('utf-8', errors='replace')
            pool.append((tag, value))
        elif tag in (TAG_INTEGER, TAG_FLOAT):
            pool.append((tag, read_u4(f)))
        elif tag in (TAG_LONG, TAG_DOUBLE):
            pool.append((tag, (read_u4(f), read_u4(f))))
            pool.append(None)  # 8-byte entries take 2 slots
            i += 1
        elif tag in (TAG_CLASS, TAG_STRING, TAG_METHOD_TYPE, TAG_MODULE, TAG_PACKAGE):
            pool.append((tag, read_u2(f)))
        elif tag in (TAG_FIELDREF, TAG_METHODREF, TAG_INTERFACE_METHODREF, TAG_NAME_AND_TYPE, TAG_DYNAMIC, TAG_INVOKE_DYNAMIC):
            pool.append((tag, (read_u2(f), read_u2(f))))
        elif tag == TAG_METHOD_HANDLE:
            pool.append((tag, (read_u1(f), read_u2(f))))
        else:
            raise ValueError(f"Unknown constant pool tag: {tag}")
        i += 1

    return pool


def get_utf8(pool, idx: int) -> str:
    """Get UTF8 string from constant pool."""
    if idx < len(pool) and pool[idx]:
        tag, value = pool[idx]
        if tag == TAG_UTF8:
            return value
    return ""


def get_string_literal(pool, idx: int) -> Optional[str]:
    """Get string literal from constant pool (TAG_STRING points to TAG_UTF8)."""
    if idx < len(pool) and pool[idx]:
        tag, value = pool[idx]
        if tag == TAG_STRING:
            return get_utf8(pool, value)
    return None


def get_integer(pool, idx: int) -> Optional[int]:
    """Get integer constant from pool."""
    if idx < len(pool) and pool[idx]:
        tag, value = pool[idx]
        if tag == TAG_INTEGER:
            # signed 32-bit
            if value >= 0x80000000:
                return value - 0x100000000
            return value
    return None


def parse_descriptor(desc: str) -> Tuple[List[str], str]:
    """Parse method descriptor into (param_types, return_type)."""
    params = []
    i = 1  # skip leading '('
    while i < len(desc) and desc[i] != ')':
        if desc[i] == 'L':
            end = desc.find(';', i)
            params.append(desc[i:end+1])
            i = end + 1
        elif desc[i] == '[':
            j = i
            while desc[j] == '[':
                j += 1
            if desc[j] == 'L':
                end = desc.find(';', j)
                params.append(desc[i:end+1])
                i = end + 1
            else:
                params.append(desc[i:j+1])
                i = j + 1
        else:
            params.append(desc[i])
            i += 1
    return_type = desc[i+1:]  # skip ')'
    return params, return_type


def is_decryptor_signature(desc: str) -> bool:
    """Check if method descriptor matches (String, int) -> String or variants."""
    params, ret = parse_descriptor(desc)
    # Match (Ljava/lang/String;I)Ljava/lang/String;
    # Or (Ljava/lang/String;J)Ljava/lang/String;
    # Or (Ljava/lang/String;I)Ljava/lang/Object; (might return String)
    if len(params) >= 2 and params[0] == 'Ljava/lang/String;':
        if params[1] in ('I', 'J', 'S', 'B') and ret in ('Ljava/lang/String;', 'Ljava/lang/Object;', 'Ljava/lang/CharSequence;'):
            return True
        # Also match (String, int, int) -> String (some obfuscators use extra key param)
        if len(params) == 3 and params[1] in ('I', 'J') and params[2] in ('I', 'J') and ret == 'Ljava/lang/String;':
            return True
    return False


@dataclass
class Candidate:
    class_name: str
    method_name: str
    descriptor: str
    call_count: int
    unique_callers: int
    string_args: List[Tuple[str, int]]  # (encrypted, key)
    files: Set[str]

    def to_dict(self):
        d = asdict(self)
        d['files'] = list(d['files'])
        return d


def analyze_classfile(data: bytes, filename: str) -> Tuple[List[Tuple[str, str, str]], List[Tuple[int, str, int]]]:
    """
    Analyze a single .class file.
    Returns (decryptor_methods, call_sites).
    decryptor_methods: list of (class_name, method_name, descriptor)
    call_sites: list of (pool_index_of_string, class_method_ref, key_value)
    """
    from io import BytesIO
    f = BytesIO(data)

    magic = read_u4(f)
    if magic != 0xCAFEBABE:
        return [], []

    minor = read_u2(f)
    major = read_u2(f)

    try:
        pool = parse_constant_pool(f)
    except Exception:
        return [], []

    access_flags = read_u2(f)
    this_class_idx = read_u2(f)
    super_class_idx = read_u2(f)

    this_class_name = get_utf8(pool, get_utf8(pool, this_class_idx) if pool[this_class_idx] else "")
    # class names are stored as "a/b/c" format in constant pool
    # TAG_CLASS stores index to UTF8 with slashes
    if pool[this_class_idx] and pool[this_class_idx][0] == TAG_CLASS:
        this_class_name = get_utf8(pool, pool[this_class_idx][1]).replace('/', '.')

    # Skip interfaces
    interfaces_count = read_u2(f)
    for _ in range(interfaces_count):
        read_u2(f)

    # Skip fields
    fields_count = read_u2(f)
    for _ in range(fields_count):
        access = read_u2(f)
        name_idx = read_u2(f)
        desc_idx = read_u2(f)
        attrs_count = read_u2(f)
        for _ in range(attrs_count):
            attr_name_idx = read_u2(f)
            attr_len = read_u4(f)
            f.seek(attr_len, 1)

    # Parse methods
    methods_count = read_u2(f)
    decryptors = []
    for _ in range(methods_count):
        access = read_u2(f)
        name_idx = read_u2(f)
        desc_idx = read_u2(f)
        attrs_count = read_u2(f)

        method_name = get_utf8(pool, name_idx)
        descriptor = get_utf8(pool, desc_idx)

        code_found = False
        for _ in range(attrs_count):
            attr_name_idx = read_u2(f)
            attr_len = read_u4(f)
            attr_name = get_utf8(pool, attr_name_idx)
            if attr_name == 'Code':
                code_found = True
                max_stack = read_u2(f)
                max_locals = read_u2(f)
                code_length = read_u4(f)
                f.seek(code_length, 1)
                # exception table
                et_count = read_u2(f)
                for _ in range(et_count * 4):
                    read_u2(f)
                # code attrs
                ca_count = read_u2(f)
                for _ in range(ca_count):
                    read_u2(f)
                    ca_len = read_u4(f)
                    f.seek(ca_len, 1)
            else:
                f.seek(attr_len, 1)

        # Check if this is a decryptor
        if is_decryptor_signature(descriptor):
            # Additional heuristic: method should be static
            if access & 0x0008:  # ACC_STATIC
                decryptors.append((this_class_name, method_name, descriptor))

    # Now scan the bytecode for invocations
    # We need to re-read the code attributes
    f.seek(0)
    read_u4(f)  # magic
    read_u2(f)  # minor
    read_u2(f)  # major
    pool = parse_constant_pool(f)
    read_u2(f)  # access
    read_u2(f)  # this
    read_u2(f)  # super
    interfaces_count = read_u2(f)
    for _ in range(interfaces_count):
        read_u2(f)
    fields_count = read_u2(f)
    for _ in range(fields_count):
        read_u2(f)
        read_u2(f)
        read_u2(f)
        attrs_count = read_u2(f)
        for _ in range(attrs_count):
            read_u2(f)
            attr_len = read_u4(f)
            f.seek(attr_len, 1)

    call_sites = []
    methods_count = read_u2(f)
    for _ in range(methods_count):
        read_u2(f)  # access
        read_u2(f)  # name
        read_u2(f)  # desc
        attrs_count = read_u2(f)
        for _ in range(attrs_count):
            attr_name_idx = read_u2(f)
            attr_len = read_u4(f)
            attr_name = get_utf8(pool, attr_name_idx)
            if attr_name == 'Code':
                read_u2(f)  # max_stack
                read_u2(f)  # max_locals
                code_length = read_u4(f)
                code = f.read(code_length)

                # Scan bytecode for invocations
                i = 0
                while i < len(code):
                    op = code[i]

                    if op == OP_INVOKESTATIC:
                        # invokestatic takes 2-byte index
                        if i + 2 < len(code):
                            idx = (code[i+1] << 8) | code[i+2]
                            if idx < len(pool) and pool[idx] and pool[idx][0] in (TAG_METHODREF, TAG_INTERFACE_METHODREF):
                                class_idx, name_type_idx = pool[idx][1]
                                if name_type_idx < len(pool) and pool[name_type_idx] and pool[name_type_idx][0] == TAG_NAME_AND_TYPE:
                                    name_idx, desc_idx = pool[name_type_idx][1]
                                    desc = get_utf8(pool, desc_idx)
                                    if is_decryptor_signature(desc):
                                        # Look backward for string literal and int constant
                                        # We scan backward up to 20 bytes
                                        string_lit = None
                                        int_val = None
                                        for j in range(max(0, i-20), i):
                                    found_string = False
                                    found_int = False
                                    for j in range(max(0, i-20), i):
                                        prev_op = code[j]
                                        if prev_op == OP_LDC and j + 1 < len(code):
                                            pool_idx = code[j+1]
                                            lit = get_string_literal(pool, pool_idx)
                                            if lit is not None and not found_string:
                                                string_lit = lit
                                                found_string = True
                                        elif prev_op == OP_LDC_W and j + 2 < len(code):
                                            pool_idx = (code[j+1] << 8) | code[j+2]
                                            lit = get_string_literal(pool, pool_idx)
                                            if lit is not None and not found_string:
                                                string_lit = lit
                                                found_string = True
                                        elif prev_op == OP_ICONST_M1:
                                            if not found_int:
                                                int_val = -1
                                                found_int = True
                                        elif prev_op in (OP_ICONST_0, OP_ICONST_1, OP_ICONST_2, OP_ICONST_3, OP_ICONST_4, OP_ICONST_5):
                                            if not found_int:
                                                int_val = prev_op - OP_ICONST_0
                                                found_int = True
                                        elif prev_op == OP_BIPUSH and j + 1 < len(code):
                                            if not found_int:
                                                int_val = struct.unpack("b", bytes([code[j+1]]))[0]
                                                found_int = True
                                        elif prev_op == OP_SIPUSH and j + 2 < len(code):
                                            if not found_int:
                                                int_val = struct.unpack(">h", bytes([code[j+1], code[j+2]]))[0]
                                                found_int = True

                                        if found_string and found_int:
                                            break

                                        if string_lit and int_val is not None:
                                            call_sites.append((string_lit, idx, int_val))
                        i += 3
                    elif op in (OP_LDC,):
                        i += 2
                    elif op in (OP_LDC_W,):
                        i += 3
                    elif op in (OP_ICONST_M1, OP_ICONST_0, OP_ICONST_1, OP_ICONST_2, OP_ICONST_3, OP_ICONST_4, OP_ICONST_5):
                        i += 1
                    elif op == OP_BIPUSH:
                        i += 2
                    elif op == OP_SIPUSH:
                        i += 3
                    elif op == 0xAA or op == 0xAB:  # tableswitch/lookupswitch
                        # alignment + variable length
                        i += 1
                        while i % 4 != 0:
                            i += 1
                        # skip default + pairs/high/low
                        if i + 12 <= len(code):
                            if op == 0xAB:  # lookupswitch
                                npairs = struct.unpack(">i", bytes(code[i+4:i+8]))[0]
                                i += 8 + npairs * 8
                            else:  # tableswitch
                                low = struct.unpack(">i", bytes(code[i+4:i+8]))[0]
                                high = struct.unpack(">i", bytes(code[i+8:i+12]))[0]
                                i += 12 + (high - low + 1) * 4
                    else:
                        i += 1

                # skip exception table
                et_count = read_u2(f)
                for _ in range(et_count):
                    read_u2(f)
                    read_u2(f)
                    read_u2(f)
                    read_u2(f)
                ca_count = read_u2(f)
                for _ in range(ca_count):
                    read_u2(f)
                    ca_len = read_u4(f)
                    f.seek(ca_len, 1)
            else:
                f.seek(attr_len, 1)

    return decryptors, call_sites


def find_classes(target: Path) -> List[Tuple[str, bytes]]:
    """Find all .class files in target (directory or JAR)."""
    classes = []
    if target.is_file() and target.suffix == '.jar':
        with zipfile.ZipFile(target, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.class'):
                    classes.append((name, zf.read(name)))
    elif target.is_dir():
        for f in target.rglob('*.class'):
            classes.append((str(f.relative_to(target)), f.read_bytes()))
    return classes


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/jar/or/classes")
        sys.exit(1)

    target = Path(sys.argv[1])
    if not target.exists():
        print(f"Error: {target} does not exist")
        sys.exit(1)

    print(f"Scanning {target} for decryptor candidates...")

    classes = find_classes(target)
    print(f"Found {len(classes)} class files")

    all_decryptors = Counter()  # (class, method, desc) -> count
    all_call_sites = defaultdict(list)  # (class, method, desc) -> [(string, key), ...]
    caller_map = defaultdict(set)  # (class, method, desc) -> set of caller filenames

    for filename, data in classes:
        try:
            decryptors, call_sites = analyze_classfile(data, filename)
            for string_lit, method_ref, int_val in call_sites:
                # We need to resolve method_ref to actual class+method name
                # For now, just accumulate by the method ref index
                # We need to re-scan with full constant pool to resolve
                # Let's do a simpler approach: scan for invokestatic and resolve
                pass
        except Exception as e:
            continue

    # Second pass: resolve method refs and collect properly
    all_decryptors = Counter()
    all_call_sites = defaultdict(list)
    caller_map = defaultdict(set)

    for filename, data in classes:
        try:
            from io import BytesIO
            f = BytesIO(data)
            magic = read_u4(f)
            if magic != 0xCAFEBABE:
                continue
            read_u2(f)
            read_u2(f)
            pool = parse_constant_pool(f)

            # Skip to methods
            read_u2(f)  # access
            read_u2(f)  # this
            read_u2(f)  # super
            interfaces_count = read_u2(f)
            for _ in range(interfaces_count):
                read_u2(f)
            fields_count = read_u2(f)
            for _ in range(fields_count):
                read_u2(f)
                read_u2(f)
                read_u2(f)
                attrs_count = read_u2(f)
                for _ in range(attrs_count):
                    read_u2(f)
                    attr_len = read_u4(f)
                    f.seek(attr_len, 1)

            methods_count = read_u2(f)
            for _ in range(methods_count):
                read_u2(f)  # access
                read_u2(f)  # name
                read_u2(f)  # desc
                attrs_count = read_u2(f)
                for _ in range(attrs_count):
                    attr_name_idx = read_u2(f)
                    attr_len = read_u4(f)
                    attr_name = get_utf8(pool, attr_name_idx)
                    if attr_name == 'Code':
                        read_u2(f)
                        read_u2(f)
                        code_length = read_u4(f)
                        code = f.read(code_length)

                        i = 0
                        while i < len(code):
                            op = code[i]
                            if op == OP_INVOKESTATIC and i + 2 < len(code):
                                idx = (code[i+1] << 8) | code[i+2]
                                if idx < len(pool) and pool[idx] and pool[idx][0] in (TAG_METHODREF, TAG_INTERFACE_METHODREF):
                                    class_idx, name_type_idx = pool[idx][1]
                                    if name_type_idx < len(pool) and pool[name_type_idx] and pool[name_type_idx][0] == TAG_NAME_AND_TYPE:
                                        name_idx, desc_idx = pool[name_type_idx][1]
                                        desc = get_utf8(pool, desc_idx)
                                        if is_decryptor_signature(desc):
                                            class_name = get_utf8(pool, pool[class_idx][1]).replace('/', '.') if pool[class_idx] else "?"
                                            method_name = get_utf8(pool, name_idx)
                                            sig = (class_name, method_name, desc)
                                            all_decryptors[sig] += 1
                                            caller_map[sig].add(filename)

                                            # Find args
                                            string_lit = None
                                            int_val = None
                                            found_string = False
                                            found_int = False
                                            for j in range(max(0, i-20), i):
                                                prev_op = code[j]
                                                if prev_op == OP_LDC and j + 1 < len(code) and not found_string:
                                                    lit = get_string_literal(pool, code[j+1])
                                                    if lit is not None:
                                                        string_lit = lit
                                                        found_string = True
                                                elif prev_op == OP_LDC_W and j + 2 < len(code) and not found_string:
                                                    lit = get_string_literal(pool, (code[j+1] << 8) | code[j+2])
                                                    if lit is not None:
                                                        string_lit = lit
                                                        found_string = True
                                                elif prev_op == OP_ICONST_M1 and not found_int:
                                                    int_val = -1
                                                    found_int = True
                                                elif prev_op in (OP_ICONST_0, OP_ICONST_1, OP_ICONST_2, OP_ICONST_3, OP_ICONST_4, OP_ICONST_5) and not found_int:
                                                    int_val = prev_op - OP_ICONST_0
                                                    found_int = True
                                                elif prev_op == OP_BIPUSH and j + 1 < len(code) and not found_int:
                                                    int_val = struct.unpack("b", bytes([code[j+1]]))[0]
                                                    found_int = True
                                                elif prev_op == OP_SIPUSH and j + 2 < len(code) and not found_int:
                                                    int_val = struct.unpack(">h", bytes([code[j+1], code[j+2]]))[0]
                                                    found_int = True

                                                if found_string and found_int:
                                                    break

                                            if string_lit and int_val is not None:
                                                all_call_sites[sig].append((string_lit, int_val))
                                i += 3
                            elif op == OP_LDC:
                                i += 2
                            elif op == OP_LDC_W:
                                i += 3
                            elif op in (OP_ICONST_M1, OP_ICONST_0, OP_ICONST_1, OP_ICONST_2, OP_ICONST_3, OP_ICONST_4, OP_ICONST_5):
                                i += 1
                            elif op == OP_BIPUSH:
                                i += 2
                            elif op == OP_SIPUSH:
                                i += 3
                            elif op == 0xAA or op == 0xAB:
                                i += 1
                                while i % 4 != 0:
                                    i += 1
                                if i + 12 <= len(code):
                                    if op == 0xAB:
                                        npairs = struct.unpack(">i", bytes(code[i+4:i+8]))[0]
                                        i += 8 + npairs * 8
                                    else:
                                        low = struct.unpack(">i", bytes(code[i+4:i+8]))[0]
                                        high = struct.unpack(">i", bytes(code[i+8:i+12]))[0]
                                        i += 12 + (high - low + 1) * 4
                            else:
                                i += 1

                        # skip exception table
                        et_count = read_u2(f)
                        for _ in range(et_count):
                            read_u2(f)
                            read_u2(f)
                            read_u2(f)
                            read_u2(f)
                        ca_count = read_u2(f)
                        for _ in range(ca_count):
                            read_u2(f)
                            ca_len = read_u4(f)
                            f.seek(ca_len, 1)
                    else:
                        f.seek(attr_len, 1)
        except Exception:
            continue

    # Build candidates
    candidates = []
    for sig, count in all_decryptors.most_common():
        class_name, method_name, desc = sig
        unique_callers = len(caller_map[sig])
        strings = all_call_sites[sig]
        # Deduplicate strings
        seen = set()
        unique_strings = []
        for s, k in strings:
            key = (s, k)
            if key not in seen and len(s) > 5:
                seen.add(key)
                unique_strings.append((s, k))

        candidates.append(Candidate(
            class_name=class_name,
            method_name=method_name,
            descriptor=desc,
            call_count=count,
            unique_callers=unique_callers,
            string_args=unique_strings[:50],  # cap at 50
            files=caller_map[sig]
        ))

    # Filter: keep only candidates with 5+ calls from 2+ different files
    candidates = [c for c in candidates if c.call_count >= 5 and c.unique_callers >= 2]
    candidates.sort(key=lambda c: (c.unique_callers, c.call_count), reverse=True)

    # Output
    print(f"\n{'='*60}")
    print(f"Found {len(candidates)} candidate decryptor(s)")
    print(f"{'='*60}")

    output = {
        'candidates': [c.to_dict() for c in candidates],
        'total_call_sites': sum(len(c.string_args) for c in candidates)
    }

    for c in candidates:
        print(f"\n{c.class_name}.{c.method_name}{c.descriptor}")
        print(f"  Calls: {c.call_count} | Unique callers: {c.unique_callers} | Strings: {len(c.string_args)}")
        print(f"  Sample strings:")
        for s, k in c.string_args[:5]:
            preview = s[:80].replace('\n', '\\n')
            if len(s) > 80:
                preview += "..."
            print(f"    \"{preview}\", {k}")

    # Write JSON output
    out_path = target.with_suffix('.discovered.json') if target.is_file() else target / 'discovered.json'
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nWrote {out_path}")

    # Also output flat list for piping
    print(f"\n{'='*60}")
    print("ALL ENCRYPTED STRINGS (for brute-force):")
    for c in candidates:
        for s, k in c.string_args:
            print(f"{c.class_name}.{c.method_name}|{k}|{s}")


if __name__ == '__main__':
    main()
