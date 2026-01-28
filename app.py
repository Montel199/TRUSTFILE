import streamlit as st
import os
import requests
from fpdf import FPDF
from utils.detector import detect_file_type, analyze_file, generate_hash

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- HELPER: MALWARE DB CHECK ---
def check_malware_db(file_hash):
    # Simulated check: In production, you'd use a real API like VirusTotal here
    known_threats = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] 
    if file_hash in known_threats:
        return "⚠️ MALICIOUS (Found in Database)"
    return "✅ NOT FOUND (Clean in Database)"

# --- HELPER: SAFE PDF GENERATOR ---
def create_pdf(res):
    pdf = FPDF()
    pdf.add_page()
    
    # Helper to strip emojis/special chars that crash Latin-1 PDF encoding
    def clean_for_pdf(text):
        if not text: return ""
        return str(text).encode('latin-1', 'ignore').decode('latin-1')

    # Header
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="TRUSTFILE Analysis Report", ln=True, align='C')
    pdf.ln(10)
    
    # Body
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"File Name: {clean_for_pdf(res['filename'])}", ln=True)
    pdf.cell(200, 10, txt=f"Risk Level: {clean_for_pdf(res['risk_level'])}", ln=True)
    pdf.cell(200, 10, txt=f"DB Status: {clean_for_pdf(res['db_status'])}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Reason: {clean_for_pdf(res['reason'])}")
    pdf.ln(5)
    
    # Footer (Technical)
    pdf.set_font("Arial", 'I', 10)
    pdf.multi_cell(0, 10, txt=f"SHA-256 Hash: {res['sha256']}")
    
    return pdf.output(dest='S').encode('latin-1')

# --- PAGE: UPLOAD ---
def render_upload_page():
    st.markdown("<h1 style='text-align: center;'>🛡️ TRUSTFILE</h1>", unsafe_allow_html=True)
    
    with st.container(border=True):
        uploaded_file = st.file_uploader("Upload file for security scan", type=None)
        
        if uploaded_file is not None:
            file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            with st.status("Running Deep Analysis...") as status:
                st.write("Checking file signatures...")
                detected_type = detect_file_type(file_path)
                
                st.write("Analyzing heuristics...")
                risk_level, reason = analyze_file(file_path, uploaded_file.name, detected_type)
                
                st.write("Hashing file...")
                sha256 = generate_hash(file_path)
                
                st.write("Cross-referencing databases...")
                db_status = check_malware_db(sha256)
                
                status.update(label="Scan Complete!", state="complete", expanded=False)

            results = {
                "filename": uploaded_file.name,
                "detected_type": detected_type,
                "risk_level": risk_level,
                "reason": reason,
                "sha256": sha256,
                "db_status": db_status
            }
            
            # Save to history and set current view
            if 'history' not in st.session_state: st.session_state.history = []
            st.session_state.history.append(results)
            st.session_state.results = results
            st.session_state.page = 'report'
            st.rerun()

# --- PAGE: REPORT ---
def render_report_page():
    res = st.session_state.results
    
    # Theme Logic
    col_t1, col_t2 = st.columns([0.8, 0.2])
    with col_t2:
        light_mode = st.toggle("💡 Light")

    bg = "#f0f2f6" if light_mode else "#0f2027"
    txt = "#000" if light_mode else "#fff"
    card = "#ffffff" if light_mode else "#1e2129"

    st.markdown(f"""
    <div style="background-color: {bg}; color: {txt}; padding: 30px; border-radius: 15px;">
        <h2 style="text-align: center;">Security Report</h2>
        <div style="background-color: {card}; padding: 25px; border-radius: 12px; border: 1px solid #4e4e4e;">
            <p><strong>📄 File:</strong> {res['filename']}</p>
            <p><strong>🛡️ Risk:</strong> <span style="color: {'#ff4b4b' if 'SUSPICIOUS' in res['risk_level'] else '#00cc66'};">{res['risk_level']}</span></p>
            <p><strong>🌐 DB Status:</strong> {res['db_status']}</p>
            <p><strong>📝 Findings:</strong> {res['reason']}</p>
            <p style="font-size: 0.8em; font-family: monospace; word-break: break-all; margin-top:15px;"><strong>SHA-256:</strong> {res['sha256']}</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.write("")
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("🔄 New Scan", use_container_width=True):
            st.session_state.page = 'upload'
            st.rerun()
    with c2:
        try:
            pdf_bytes = create_pdf(res)
            st.download_button("📥 PDF Report", data=pdf_bytes, file_name=f"Report_{res['filename']}.pdf", use_container_width=True)
        except Exception as e:
            st.error("PDF Export Error")
    with c3:
        if st.button("🏠 Home", use_container_width=True):
            st.session_state.page = 'upload'
            st.rerun()

# --- MAIN CONTROL ---
def main():
    st.set_page_config(page_title="TRUSTFILE", page_icon="🛡️", layout="wide")
    
    if 'page' not in st.session_state: st.session_state.page = 'upload'
    if 'history' not in st.session_state: st.session_state.history = []

    # Sidebar History
    with st.sidebar:
        st.title("📜 Scan History")
        for i, entry in enumerate(reversed(st.session_state.history)):
            if st.button(f"{entry['filename']}", key=f"h_{i}", use_container_width=True):
                st.session_state.results = entry
                st.session_state.page = 'report'
                st.rerun()
        if st.session_state.history and st.button("Clear All Logs", use_container_width=True):
            st.session_state.history = []
            st.session_state.page = 'upload'
            st.rerun()

    if st.session_state.page == 'upload':
        render_upload_page()
    else:
        render_report_page()

if __name__ == "__main__":
    main()
