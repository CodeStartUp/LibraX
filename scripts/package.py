import os
import zipfile

ZIP_NAME = "librax-submission.zip"
EXCLUDE_DIRS = {
    ".git",
    "target",
    "node_modules",
    "dist",
    "site",
    "__pycache__",
    ".pytest_cache",
    ".opencode",
}
EXCLUDE_FILES = {
    ZIP_NAME,
    ".build.log",
    "package.py",
}

def create_zip():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    zip_path = os.path.join(root_dir, ZIP_NAME)

    if os.path.exists(zip_path):
        os.remove(zip_path)

    file_count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(root_dir):
            # Modify dirs in-place to prevent descending into excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]

            for file in files:
                if file in EXCLUDE_FILES or file.endswith(".pyc"):
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, root_dir)

                # Skip any nested build/target/node_modules directories
                parts = rel_path.split(os.sep)
                if any(part in EXCLUDE_DIRS for part in parts):
                    continue

                zf.write(full_path, rel_path)
                file_count += 1

    size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    print(f"Created {ZIP_NAME}: {file_count} files, {size_mb:.2f} MB")

if __name__ == "__main__":
    create_zip()
