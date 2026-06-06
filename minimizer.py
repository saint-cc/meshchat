import os
import shutil
import time

import htmlmin
import rcssmin
import rjsmin

INPUT_DIR = "project"
OUTPUT_DIR = "static"
POLL_INTERVAL = 1  # seconds


# ── HTML ─────────────────────────────────────────────
def minify_html(content: str) -> str:
    return htmlmin.minify(
        content,
        remove_comments=True,
        reduce_empty_attributes=True,
        remove_optional_attribute_quotes=False
    )


# ── CSS ──────────────────────────────────────────────
def minify_css(content: str) -> str:
    return rcssmin.cssmin(content)


# ── JS ───────────────────────────────────────────────
def minify_js(content: str) -> str:
    return rjsmin.jsmin(content)


# ── FILE HANDLER ─────────────────────────────────────
def process_file(input_path, output_path):
    ext = os.path.splitext(input_path)[1].lower()
    
    if ext not in (".html", ".css", ".js"):
        print(f"[SKIP] {input_path}")
        return

    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    if ext == ".html":
        result = minify_html(content)
    elif ext == ".css":
        result = minify_css(content)
    elif ext == ".js":
        result = minify_js(content)
    else:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        shutil.copy(input_path, output_path)
        return

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(result)

    print(f"[BUILD] {input_path} → {output_path}")


# ── INITIAL BUILD ────────────────────────────────────
def process_directory():
    # don't rmtree, just process files
    for root, _, files in os.walk(INPUT_DIR):
        for file in files:
            in_path = os.path.join(root, file)
            rel_path = os.path.relpath(in_path, INPUT_DIR)
            out_path = os.path.join(OUTPUT_DIR, rel_path)
            process_file(in_path, out_path)


# ── WATCH MODE ───────────────────────────────────────
def watch():
    print("[WATCH] Watching for changes...")

    file_mtimes = {}

    while True:
        for root, _, files in os.walk(INPUT_DIR):
            for file in files:
                in_path = os.path.join(root, file)
                rel_path = os.path.relpath(in_path, INPUT_DIR)
                out_path = os.path.join(OUTPUT_DIR, rel_path)

                try:
                    mtime = os.path.getmtime(in_path)
                except FileNotFoundError:
                    continue

                if in_path not in file_mtimes:
                    file_mtimes[in_path] = mtime
                    process_file(in_path, out_path)

                elif file_mtimes[in_path] != mtime:
                    file_mtimes[in_path] = mtime
                    process_file(in_path, out_path)

        time.sleep(POLL_INTERVAL)


# ── ENTRY POINT ──────────────────────────────────────
if __name__ == "__main__":
    process_directory()
    watch()