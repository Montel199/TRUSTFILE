import streamlit as st
import os
import requests  # Required for API calls
from fpdf import FPDF
from utils.detector import detect_file_type, analyze_file, generate_hash

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- MALWARE DATABASE CHECK (VIRUSTOTAL SIMULATION) ---
def check_malware_db(file_hash):
    """
    In a production app, you would use:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": "YOUR_API_KEY"}
    """
    # For now, we simulate a database check
    # In a real scenario, this would return 'MALICIOUS' if found in a blocklist
    known_threats = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] 
    if file_hash in known_threats:
        return "⚠️ MALICIOUS (Found in Database)"
    return "✅ NOT FOUND (Clean in Database)"

# --- PDF GENERATOR ---
def create_pdf(res):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="TRUSTFILE Analysis Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"File Name: {res['filename']}", ln=True)
    pdf.cell(200, 10, txt=f"Risk Level: {res['risk_level']}", ln=True)
    pdf.cell(200, 10, txt=f"DB Status: {res['db_status']}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Reason: {res['reason']}")
    pdf.ln(5)
    pdf.set_font("Arial", 'I', 10)
    pdf.multi_cell(0, 10, txt=f"SHA-256 Hash: {res['sha256']}")
    return pdf.output(dest='S').encode('latin-1')

# --- PAGE: UPLOAD ---
def render_upload_page():
    st.markdown("<div style='text-align: center;'><h1>🛡️ TRUSTFILE</h1><p>Advanced Integrity Analysis</p></div>", unsafe_allow_html=True)
    
    with st.container(border=True):
        uploaded_file = st.file_uploader("Drop file to scan", type=None)
        
        if uploaded_file is not None:
            file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            with st.status("Performing Deep Scan...") as status:
                st.write("Detecting file signatures...")
                detected_type = detect_file_type(file_path)
                
                st.write("Analyzing heuristics...")
                risk_level, reason = analyze_file(file_path, uploaded_file.name, detected_type)
                
                st.write("Generating SHA-256 fingerprint...")
                sha256 = generate_hash(file_path)
                
                st.write("Querying malware databases...")
                db_status = check_malware_db(sha256)
                
                status.update(label="Analysis Complete!", state="complete", expanded=False)

            results = {
                "filename": uploaded_file.name,
                "detected_type": detected_type,
                "risk_level": risk_level,
                "reason": reason,
                "sha256": sha256,
                "db_status": db_status
            }
            
            if 'history' not in st.session_state:
                st.session_state.history = []
            st.session_state.history.append(results)
            st.session_state.results = results
            st.session_state.page = 'report'
            st.rerun()

# --- PAGE: REPORT ---
def render_report_page():
    res = st.session_state.results
    light_mode = st.toggle("💡 Light Mode")

    bg_color = "#f0f2f6" if light_mode else "#0f2027"
    text_color = "#000" if light_mode else "#fff"
    card_bg = "#ffffff" if light_mode else "#1e2129"

    st.markdown(f"""
    <div style="background-color: {bg_color}; color: {text_color}; padding: 30px; border-radius: 15px;">
        <h2 style="text-align: center;">Scan Results</h2>
        <div style="background-color: {card_bg}; padding: 25px; border-radius: 12px; border: 1px solid #4e4e4e;">
            <p><strong>📄 File:</strong> {res['filename']}</p>
            <p><strong>🛡️ Risk Score:</strong> <span style="color: {'#ff4b4b' if 'SUSPICIOUS' in res['risk_level'] else '#00cc66'};">{res['risk_level']}</span></p>
            <p><strong>🌐 DB Status:</strong> {res['db_status']}</p>
            <p><strong>📝 Findings:</strong> {res['reason']}</p>
            <p style="font-size: 0.8em; font-family: monospace; word-break: break-all; margin-top: 15px;"><strong>FINGERPRINT:</strong> {res['sha256']}</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.write("") 
    cols = st.columns(3)
    if cols[0].button("🔄 New Scan", use_container_width=True):
        st.session_state.page = 'upload'
        st.rerun()
    
    pdf_bytes = create_pdf(res)
    cols[1].download_button("📥 Report PDF", data=pdf_bytes, file_name=f"TRUSTFILE_{res['filename']}.pdf", use_container_width=True)
    
    if cols[2].button("🏠 Home", use_container_width=True):
        st.session_state.page = 'upload'
        st.rerun()

# --- MAIN ---
def main():
    st.set_page_config(page_title="TRUSTFILE", page_icon="🛡️", layout="wide")
    if 'page' not in st.session_state: st.session_state.page = 'upload'
    if 'history' not in st.session_state: st.session_state.history = []

    with st.sidebar:
        st.title("📜 History")
        for i, entry in enumerate(reversed(st.session_state.history)):
            if st.button(f"{entry['filename']}", key=f"h_{i}", use_container_width=True):
                st.session_state.results = entry
                st.session_state.page = 'report'
                st.rerun()
        if st.session_state.history and st.button("Clear All"):
            st.session_state.history = []
            st.session_state.page = 'upload'
            st.rerun()

    if st.session_state.page == 'upload':
        render_upload_page()
    else:
        render_report_page()

if __name__ == "__main__":
    main()
