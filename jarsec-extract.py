#!/usr/bin/env python3
"""
Jarsec Dynamic String Extractor — loads target JAR classes via reflection to
extract decrypted strings from static fields. This handles caller-context
obfuscation (StackWalker, etc.) that static brute-force can't reverse.

How it works:
1. Scans decompiled source for classes with static String fields/arrays
   initialized by decryptor calls (e.g., zPdoG.rn(), SomeClass.decrypt())
2. Generates a Java program that loads each candidate class via reflection
3. <clinit> runs automatically, decrypting strings with correct caller context
4. Reads static String fields and outputs plaintext

Usage:
    python3 jarsec-extract.py /path/to/target.jar /path/to/decompiled/source

Requires: Java (javac + java)
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple, Set


def find_decryptor_pattern(decompiled_dir: Path) -> str:
    """
    Find the most common decryptor call pattern in decompiled source.
    Returns something like 'zPdoG.rn' or 'a.b.decrypt'.
    """
    # Pattern: ClassName.methodName("...", 12345)
    pattern = re.compile(r'\b(\w+(?:\.\w+)*\.\w+)\s*\(\s*"[^"]*"\s*,\s*-?\d+\s*\)')
    counter = {}

    for java_file in decompiled_dir.rglob("*.java"):
        try:
            text = java_file.read_text(encoding='utf-8', errors='replace')
            for m in pattern.finditer(text):
                call = m.group(1)
                counter[call] = counter.get(call, 0) + 1
        except Exception:
            continue

    if not counter:
        return None

    # Return the most frequent call
    best = max(counter, key=counter.get)
    if counter[best] < 5:
        return None
    return best


def find_candidate_classes(decompiled_dir: Path, decryptor_pattern: str) -> List[Tuple[str, List[str]]]:
    """
    Find classes that have static String fields/arrays initialized with
the decryptor. Returns list of (class_name, field_names).
    """
    candidates = []
    decryptor_method = decryptor_pattern.split('.')[-1] if decryptor_pattern else None

    for java_file in decompiled_dir.rglob("*.java"):
        try:
            text = java_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue

        # Check if this file uses the decryptor
        if decryptor_method and decryptor_method not in text:
            continue

        # Extract package
        pkg_match = re.search(r'package\s+([\w.]+)\s*;', text)
        if not pkg_match:
            continue
        package = pkg_match.group(1)

        # Extract class name
        class_match = re.search(r'(?:public\s+)?(?:final\s+)?class\s+(\w+)', text)
        if not class_match:
            continue
        class_name = package + '.' + class_match.group(1)

        # Find static String fields
        fields = []

        # Pattern: static String fieldName = ... or static String[] fieldName = ...
        # Also catch var10000[0] = decryptor(...) patterns in static blocks
        static_block = re.search(
            r'static\s*\{([^}]*)\}',
            text,
            re.DOTALL
        )

        if static_block:
            block_text = static_block.group(1)
            # Look for field assignments in static block
            for m in re.finditer(r'(\w+)\s*\[\s*\d+\s*\]\s*=\s*' + re.escape(decryptor_method) if decryptor_method else r'\w+\s*\[\s*\d+\s*\]\s*=\s*\w+\.\w+\(', block_text):
                field_name = m.group(1)
                if field_name not in fields:
                    fields.append(field_name)

        # Also look for direct static field declarations
        for m in re.finditer(
            r'static\s+(?:final\s+)?String(?:\[\s*\])?\s+(\w+)\s*=',
            text
        ):
            fields.append(m.group(1))

        # Deduplicate and filter
        fields = list(dict.fromkeys(fields))
        if fields:
            candidates.append((class_name, fields))

    return candidates


def generate_extractor(candidates: List[Tuple[str, List[str]]], output_dir: Path) -> Path:
    """Generate a Java extractor program."""
    java_file = output_dir / "JarsecExtract.java"

    class_loads = []
    field_reads = []

    for class_name, fields in candidates:
        var_name = 'cls_' + class_name.replace('.', '_').replace('$', '_')
        class_loads.append(f'''
            try {{
                Class<?> {var_name} = Class.forName("{class_name}", true, classLoader);
                System.out.println("--- {class_name} ---");
''')
        for field_name in fields:
            class_loads[-1] += f'''
                try {{
                    java.lang.reflect.Field f = {var_name}.getDeclaredField("{field_name}");
                    f.setAccessible(true);
                    Object val = f.get(null);
                    if (val != null) {{
                        if (val.getClass().isArray()) {{
                            Object[] arr = (Object[]) val;
                            System.out.println("  {field_name}[" + arr.length + "]:");
                            for (int i = 0; i < arr.length; i++) {{
                                if (arr[i] != null) {{
                                    String s = arr[i].toString();
                                    if (!s.isEmpty() && s.length() > 1) {{
                                        System.out.println("    [" + i + "] " + s);
                                    }}
                                }}
                            }}
                        }} else {{
                            String s = val.toString();
                            if (!s.isEmpty() && s.length() > 1) {{
                                System.out.println("  {field_name} = " + s);
                            }}
                        }}
                    }}
                }} catch (Exception e) {{
                    System.out.println("  {field_name}: " + e.getMessage());
                }}
'''
        class_loads[-1] += '''            } catch (Exception e) {
                System.err.println("Failed to load ''' + class_name + ''': " + e.getMessage());
            }
'''

    java_code = f'''import java.net.*;
import java.io.*;

public class JarsecExtract {{
    public static void main(String[] args) throws Exception {{
        if (args.length < 1) {{
            System.err.println("Usage: JarsecExtract <target.jar>");
            System.exit(1);
        }}

        String jarPath = args[0];
        URLClassLoader classLoader = new URLClassLoader(
            new URL[] {{ new File(jarPath).toURI().toURL() }},
            JarsecExtract.class.getClassLoader()
        );

        System.out.println("=== Extracting decrypted strings from static fields ===");

        {''.join(class_loads)}

        classLoader.close();
        System.out.println("=== Done ===");
    }}
}}
'''

    java_file.write_text(java_code)
    return java_file


def run_extractor(extractor_java: Path, target_jar: Path, work_dir: Path) -> str:
    """Compile and run the extractor. Returns output."""
    # Compile
    compile_cmd = ['javac', '-d', str(work_dir), str(extractor_java)]
    result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=str(work_dir))
    if result.returncode != 0:
        print(f"Compile error: {result.stderr}")
        return ""

    # Run
    classpath = f"{work_dir}:{target_jar}"
    run_cmd = ['java', '-cp', classpath, 'JarsecExtract', str(target_jar)]
    result = subprocess.run(run_cmd, capture_output=True, text=True, cwd=str(work_dir), timeout=60)

    if result.returncode != 0:
        print(f"Runtime error: {result.stderr}")

    return result.stdout


def extract_all_strings(target_jar: Path, decompiled_dir: Path, work_dir: Path) -> str:
    """Generic extractor: load ALL classes and read ALL static String fields."""
    java_file = work_dir / "JarsecExtractAll.java"

    java_code = '''import java.net.*;
import java.io.*;
import java.util.*;
import java.util.jar.*;

public class JarsecExtractAll {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: JarsecExtractAll <target.jar>");
            System.exit(1);
        }

        String jarPath = args[0];
        URLClassLoader classLoader = new URLClassLoader(
            new URL[] { new File(jarPath).toURI().toURL() },
            JarsecExtractAll.class.getClassLoader()
        );

        // Enumerate all classes in JAR
        JarFile jar = new JarFile(jarPath);
        List<String> classes = new ArrayList<>();
        for (JarEntry entry : Collections.list(jar.entries())) {
            if (entry.getName().endsWith(".class")) {
                String className = entry.getName().replace('/', '.').replace(".class", "");
                classes.add(className);
            }
        }
        jar.close();

        System.out.println("=== Scanning " + classes.size() + " classes for static String fields ===");
        int found = 0;

        for (String className : classes) {
            try {
                Class<?> cls = Class.forName(className, true, classLoader);
                for (java.lang.reflect.Field f : cls.getDeclaredFields()) {
                    if (java.lang.reflect.Modifier.isStatic(f.getModifiers()) &&
                        (f.getType() == String.class || f.getType() == String[].class)) {
                        f.setAccessible(true);
                        Object val = f.get(null);
                        if (val != null) {
                            if (f.getType() == String[].class) {
                                String[] arr = (String[]) val;
                                boolean hasContent = false;
                                for (String s : arr) {
                                    if (s != null && !s.isEmpty() && s.length() > 2) {
                                        hasContent = true;
                                        break;
                                    }
                                }
                                if (hasContent) {
                                    System.out.println("--- " + className + "." + f.getName() + "[" + arr.length + "] ---");
                                    for (int i = 0; i < arr.length; i++) {
                                        if (arr[i] != null && !arr[i].isEmpty() && arr[i].length() > 2) {
                                            System.out.println("  [" + i + "] " + arr[i]);
                                        }
                                    }
                                    found++;
                                }
                            } else {
                                String s = (String) val;
                                if (!s.isEmpty() && s.length() > 2 && !s.equals(className)) {
                                    System.out.println("--- " + className + "." + f.getName() + " ---");
                                    System.out.println("  " + s);
                                    found++;
                                }
                            }
                        }
                    }
                }
            } catch (Throwable e) {
                // Skip classes that fail to load
            }
        }

        classLoader.close();
        System.out.println("=== Found " + found + " fields with content ===");
    }
}
'''

    java_file.write_text(java_code)

    # Compile and run
    compile_cmd = ['javac', '-d', str(work_dir), str(java_file)]
    result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=str(work_dir))
    if result.returncode != 0:
        print(f"Compile error: {result.stderr}")
        return ""

    classpath = f"{work_dir}:{target_jar}"
    run_cmd = ['java', '-cp', classpath, 'JarsecExtractAll', str(target_jar)]
    result = subprocess.run(run_cmd, capture_output=True, text=True, cwd=str(work_dir), timeout=120)

    if result.returncode != 0:
        print(f"Runtime error: {result.stderr}")

    return result.stdout


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} /path/to/target.jar /path/to/decompiled/source")
        print(f"   or: {sys.argv[0]} /path/to/target.jar --all")
        sys.exit(1)

    target_jar = Path(sys.argv[1])
    decompiled_dir = Path(sys.argv[2]) if sys.argv[2] != '--all' else None

    if not target_jar.exists():
        print(f"Error: {target_jar} not found")
        sys.exit(1)

    work_dir = Path(tempfile.mkdtemp(prefix="jarsec_extract_"))
    print(f"Working directory: {work_dir}")

    if decompiled_dir and decompiled_dir.exists():
        # Smart extraction: find decryptor pattern, candidate classes, extract
        decryptor = find_decryptor_pattern(decompiled_dir)
        print(f"Detected decryptor: {decryptor}")

        candidates = find_candidate_classes(decompiled_dir, decryptor or "")
        print(f"Found {len(candidates)} candidate classes")
        for cls, fields in candidates[:10]:
            print(f"  {cls}: {fields}")

        if candidates:
            extractor = generate_extractor(candidates, work_dir)
            print(f"Generated extractor: {extractor}")
            output = run_extractor(extractor, target_jar, work_dir)
            print(output)
        else:
            print("No candidates found, falling back to --all mode")
            output = extract_all_strings(target_jar, decompiled_dir, work_dir)
            print(output)
    else:
        # Brute-force: scan all classes
        print("Scanning all classes for static String fields...")
        output = extract_all_strings(target_jar, None, work_dir)
        print(output)


if __name__ == '__main__':
    main()
