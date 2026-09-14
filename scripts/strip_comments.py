import os
import re

def strip_rust_comments(src: str) -> str:
    i = 0
    n = len(src)
    out = []
    
    while i < n:
        # Check raw string: r"...", r#"..."#, r##"..."##, etc.
        if src[i] == 'r' and i + 1 < n:
            # Check if followed by #* then "
            j = i + 1
            hashes = 0
            while j < n and src[j] == '#':
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                # Raw string literal
                out.append(src[i:j+1])
                i = j + 1
                end_marker = '"' + ('#' * hashes)
                end_pos = src.find(end_marker, i)
                if end_pos == -1:
                    out.append(src[i:])
                    break
                else:
                    out.append(src[i:end_pos + len(end_marker)])
                    i = end_pos + len(end_marker)
                continue

        # Check normal string literal: "..."
        if src[i] == '"':
            out.append('"')
            i += 1
            while i < n:
                ch = src[i]
                out.append(ch)
                if ch == '\\':
                    i += 1
                    if i < n:
                        out.append(src[i])
                elif ch == '"':
                    i += 1
                    break
                i += 1
            continue

        # Check char literal: '...'
        # Note: In Rust, lifetimes also start with ', e.g. 'a, 'static.
        # A char literal is 'c', '\n', '\'', etc. followed by '
        if src[i] == "'":
            # Check if this might be a char literal vs lifetime
            # Lifetimes look like 'a, 'b, 'static, etc.
            out.append("'")
            i += 1
            if i < n:
                if src[i] == '\\':
                    out.append('\\')
                    i += 1
                    while i < n and src[i] != "'":
                        out.append(src[i])
                        i += 1
                    if i < n and src[i] == "'":
                        out.append("'")
                        i += 1
                elif i + 1 < n and src[i+1] == "'":
                    out.append(src[i])
                    out.append("'")
                    i += 2
                else:
                    # Likely a lifetime or unclosed char
                    pass
            continue

        # Check line comment: //...
        if src[i:i+2] == '//':
            i += 2
            while i < n and src[i] != '\n':
                i += 1
            continue

        # Check block comment: /* ... */ (supports nesting)
        if src[i:i+2] == '/*':
            i += 2
            depth = 1
            while i < n and depth > 0:
                if src[i:i+2] == '/*':
                    depth += 1
                    i += 2
                elif src[i:i+2] == '*/':
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue

        out.append(src[i])
        i += 1

    cleaned = "".join(out)
    
    # Clean up excessive blank lines (more than 2 consecutive blank lines)
    cleaned_lines = []
    blank_count = 0
    for line in cleaned.split("\n"):
        if not line.strip():
            blank_count += 1
            if blank_count <= 2:
                cleaned_lines.append("")
        else:
            blank_count = 0
            # Also remove any trailing whitespace on the line
            cleaned_lines.append(line.rstrip())

    return "\n".join(cleaned_lines)

def process_all_rust_files():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    rust_files = []
    for base in ["crates", "services"]:
        target_dir = os.path.join(root_dir, base)
        for root, _, files in os.walk(target_dir):
            for file in files:
                if file.endswith(".rs"):
                    rust_files.append(os.path.join(root, file))

    print(f"Found {len(rust_files)} Rust files to process.")
    for file_path in rust_files:
        with open(file_path, "r", encoding="utf-8") as f:
            original = f.read()
        
        cleaned = strip_rust_comments(original)
        if cleaned != original:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(cleaned)

    print("All Rust files processed successfully.")

if __name__ == "__main__":
    process_all_rust_files()
