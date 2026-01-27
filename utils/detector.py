import magic

def detect_file_type(file_path):
    """
    Detect the real MIME type of a file using its content
    """
    try:
        return magic.from_file(file_path, mime=True)
    except Exception as e:
        return f"unknown ({e})"


def analyze_file(file_path, filename, detected_type):
    extension = filename.split('.')[-1].lower()

    # Known safe extension → MIME mappings
    safe_mappings = {
        "doc": ["application/msword"],
        "docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
        "pdf": ["application/pdf"],
        "jpg": ["image/jpeg"],
        "jpeg": ["image/jpeg"],
        "png": ["image/png"],
        "txt": ["text/plain"]
    }

    dangerous_types = [
        "application/x-executable",
        "application/x-msdownload",
        "application/x-sh",
        "application/x-python",
        "application/x-elf"
    ]

    # Rule 1: Dangerous executable
    if detected_type in dangerous_types:
        return "DANGEROUS", "Executable or script file detected"

    # Rule 2: Legit mapping exists
    if extension in safe_mappings:
        if detected_type in safe_mappings[extension]:
            return "SAFE", "File type matches trusted format"

        return "SUSPICIOUS", "File extension does not match its content"

    # Rule 3: Unknown extension
    return "SUSPICIOUS", "Unknown or uncommon file type"

    """
    Analyze file risk based on content and extension
    """
    extension = filename.split('.')[-1].lower()

    dangerous_types = [
        "application/x-executable",
        "application/x-msdownload",
        "application/x-sh",
        "application/x-python",
        "application/x-elf"
    ]

    if detected_type in dangerous_types:
        return "DANGEROUS", "Executable or script file detected"

    if extension not in detected_type:
        return "SUSPICIOUS", "File extension does not match detected content"

    return "SAFE", "File appears legitimate"

import hashlib

def generate_hash(file_path):
    """
    Generate SHA-256 hash of a file
    """
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)

    return sha256.hexdigest()

