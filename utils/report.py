def generate_report(filename, extension, detected_type, risk, reason, file_hash):
    report = f"""
    TRUSTFILE SECURITY REPORT
    -------------------------
    Filename: {filename}
    Extension: .{extension}
    Detected Type: {detected_type}
    Risk Level: {risk}
    Reason: {reason}
    SHA-256 Hash: {file_hash}
    """
    return report

