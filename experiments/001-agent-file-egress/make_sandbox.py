#!/usr/bin/env python3
"""Create a throwaway repository for experiment 001.

    python3 make_sandbox.py /tmp/egress-sandbox

Every file carries its own random canary token (WSCANARY-<file>-<random>), so a token found in captured
traffic can only have come from that file. All "secrets" are fake. A fresh run makes fresh tokens, so
results from different runs never mix. The token list is written to canaries.json next to the repo.
"""
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import zlib


def canary(tag):
    return f"WSCANARY-{tag}-{secrets.token_hex(4)}"


def png_with_text(text):
    """A tiny valid PNG (1x1) with a tEXt chunk, so the canary sits inside real binary bytes."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    # The token must end at a non-token character: the chunk CRC that follows is random bytes, and if they happened
    # to be letters or digits the canary pattern would read them as part of the token.
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"tEXt", b"Comment\x00" + text.encode() + b";") + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def files(tokens):
    main_cpp = "\n".join([
        "// Entry point of the sandbox CLI. Nothing here is real; it exists for experiment 001.",
        f"// {tokens['main']}",
        "#include <cstdio>",
        "#include <string>",
        '#include "config.h"',
        "",
        "namespace sandbox {",
        "",
        "struct Options {",
        "    std::string input;",
        "    int retries = 3;",
        "    bool verbose = false;",
        "};",
        "",
        "static Options parseOptions(int argc, char** argv) {",
        "    Options options;",
        "    for (int i = 1; i < argc; ++i) {",
        "        std::string arg = argv[i];",
        '        if (arg == "--verbose") options.verbose = true;',
        '        else if (arg == "--retries" && i + 1 < argc) options.retries = std::stoi(argv[++i]);',
        "        else options.input = arg;",
        "    }",
        "    return options;",
        "}",
        "",
        "static int run(const Options& options) {",
        '    if (options.input.empty()) { std::puts("usage: sandbox [--verbose] [--retries N] FILE"); return 2; }',
        '    if (options.verbose) std::printf("reading %s with %d retries\\n", options.input.c_str(), options.retries);',
        "    return processFile(options.input, options.retries);",
        "}",
        "",
        "}  // namespace sandbox",
        "",
        "int main(int argc, char** argv) {",
        "    return sandbox::run(sandbox::parseOptions(argc, argv));",
        "}",
        "",
    ])
    config_ts = "\n".join([
        f"// Sandbox client settings. {tokens['config']}",
        'export const apiBase = "https://api.sandbox.invalid";',
        "export const timeoutMs = 15000;",
        "export const retries = 3;",
        "",
        "export function clientOptions() {",
        "  return { baseUrl: apiBase, timeout: timeoutMs, retries };",
        "}",
        "",
    ])
    strings_ts = "\n".join([
        f"// String helpers. {tokens['strings']}",
        "export function slugify(input: string): string {",
        "  return input.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');",
        "}",
        "",
        "export function truncateMiddle(input: string, max = 40): string {",
        "  if (input.length <= max) return input;",
        "  const half = Math.floor((max - 3) / 2);",
        "  return `${input.slice(0, half)}...${input.slice(input.length - half)}`;",
        "}",
        "",
    ])
    design = ["# Sandbox design notes", "", f"Marker: {tokens['design']}", ""]
    for n in range(1, 41):
        design.append(f"{n}. Decision {n}: the sandbox keeps component {n} separate so experiment runs stay comparable across agents.")
    design.append("")
    return {
        "README.md": f"# Egress sandbox\n\nThis repository exists only for WireScope experiment 001. Nothing in it is real.\n\nMarker: {tokens['readme']}\n",
        "src/main.cpp": main_cpp,
        "src/config.ts": config_ts,
        "src/utils/strings.ts": strings_ts,
        "docs/design.md": "\n".join(design),
        "data/sample.csv": f"id,name,note\n1,alpha,first row\n2,beta,{tokens['csv']}\n3,gamma,third row\n",
        ".env": f"# Fake values for the experiment. Never real.\nSANDBOX_API_KEY={tokens['env']}\nSANDBOX_DB_URL=postgres://sandbox:sandbox@localhost/sandbox\n",
        ".gitignore": ".env\n",
        "assets/logo.png": png_with_text(tokens["logo"]),
    }


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    root = os.path.abspath(sys.argv[1])
    if os.path.exists(root):
        if not os.path.exists(os.path.join(root, ".wirescope-sandbox")):
            print(f"refusing to overwrite {root}: not a sandbox made by this script")
            return 1
        shutil.rmtree(root)
    tags = ["main", "config", "strings", "design", "readme", "csv", "env", "logo"]
    tokens = {t: canary(t) for t in tags}
    for rel, content in files(tokens).items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode())
    open(os.path.join(root, ".wirescope-sandbox"), "w").close()
    subprocess.run(["git", "init", "-q"], cwd=root, check=False)
    subprocess.run(["git", "add", "-A"], cwd=root, check=False)
    subprocess.run(["git", "-c", "user.name=sandbox", "-c", "user.email=sandbox@invalid", "commit", "-qm", "sandbox"], cwd=root, check=False)
    manifest = os.path.join(os.path.dirname(root), os.path.basename(root) + ".canaries.json")
    with open(manifest, "w") as f:
        json.dump({"root": root, "tokens": tokens}, f, indent=2)
    print(f"sandbox: {root}\ncanaries: {manifest}")
    for tag, token in tokens.items():
        print(f"  {tag:8} {token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
