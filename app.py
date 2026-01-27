from flask import Flask, request, render_template, redirect, url_for
from utils.detector import detect_file_type, analyze_file, generate_hash
from utils.report import generate_report
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if uploaded_file and uploaded_file.filename != "":
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(file_path)

            # Analyze file (example, replace with your functions)
            detected_type = detect_file_type(file_path)
            risk_level, reason = analyze_file(file_path, uploaded_file.filename, detected_type)
            sha256 = generate_hash(file_path)

            return render_template(
                "report.html",
                filename=uploaded_file.filename,
                extension=uploaded_file.filename.split('.')[-1],
                detected_type=detected_type,
                risk_level=risk_level,
                reason=reason,
                sha256=sha256,
                report_image=None
            )
    return render_template("upload.html")

if __name__ == "__main__":
    app.run(debug=True)

