import streamlit as st
import os
from fpdf import FPDF
from utils.detector import detect_file_type, analyze_file, generate_hash

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- PDF GENERATOR ---
def create_pdf(res):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="TRUSTFILE Analysis Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"File Name: {res['filename']}", ln=True)
    pdf.cell(200, 10, txt=f"Detected Type: {res['detected_type']}", ln=True)
    pdf.cell(200, 10, txt=f"Risk Level: {res['risk_level']}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Reason: {res['reason']}")
    pdf.ln(5)
    pdf.set_font("Arial", 'I', 10)
    pdf.multi_cell(0, 10, txt=f"SHA-256 Hash: {res['sha256']}")
    return pdf.output(dest='S').encode('latin-1')

# --- PAGE: UPLOAD ---
def render_upload_page():
    st.markdown("<div style='text-align: center;'><h1>🛡️ TRUSTFILE</h1></div>", unsafe_allow_html=True)
    
    with st.container(border=True):
        uploaded_file = st.file_uploader("Upload your file", type=None)
        
        if uploaded_file is not None:
            file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            with st.spinner('Analyzing...'):
                detected_type = detect_file_type(file_path)
                risk_level, reason = analyze_file(file_path, uploaded_file.name, detected_type)
                sha256 = generate_hash(file_path)

            results = {
                "filename": uploaded_file.name,
                "detected_type": detected_type,
                "risk_level": risk_level,
                "reason": reason,
                "sha256": sha256
            }
            
            # --- UPDATE HISTORY ---
            if 'history' not in st.session_state:
                st.session_state.history = []
            st.session_state.history.append(results)
            
            st.session_state.results = results
            st.session_state.page = 'report'
            st.rerun()

# --- PAGE: REPORT ---
def render_report_page():
    res = st.session_state.results
    
    col_t1, col_t2 = st.columns([0.8, 0.2])
    with col_t2:
        light_mode = st.toggle("💡 Light")

    bg_color = "#f0f2f6" if light_mode else "#0f2027"
    text_color = "#000" if light_mode else "#fff"
    card_bg = "#ffffff" if light_mode else "#1e2129"

    st.markdown(f"""
    <div style="background-color: {bg_color}; color: {text_color}; padding: 30px; border-radius: 15px;">
        <h2 style="text-align: center;">Analysis Report</h2>
        <div style="background-color: {card_bg}; padding: 25px; border-radius: 12px; border: 1px solid #4e4e4e;">
            <p><strong>📄 File:</strong> {res['filename']}</p>
            <p><strong>⚠️ Risk:</strong> <span style="color: {'#ff4b4b' if 'SUSPICIOUS' in res['risk_level'] else '#00cc66'};">{res['risk_level']}</span></p>
            <p><strong>📝 Reason:</strong> {res['reason']}</p>
            <p style="font-size: 0.8em; font-family: monospace; word-break: break-all;"><strong>HASH:</strong> {res['sha256']}</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.write("") 
    btn_col1, btn_col2, btn_col3 = st.columns(3)
    with btn_col1:
        if st.button("🔄 New Scan", use_container_width=True):
            st.session_state.page = 'upload'
            st.rerun()
    with btn_col2:
        pdf_bytes = create_pdf(res)
        st.download_button("📥 PDF", data=pdf_bytes, file_name=f"Report_{res['filename']}.pdf", use_container_width=True)
    with btn_col3:
        if st.button("🏠 Home", use_container_width=True):
            st.session_state.page = 'upload'
            st.rerun()

# --- MAIN LOGIC WITH SIDEBAR ---
def main():
    st.set_page_config(page_title="TRUSTFILE", page_icon="🛡️", layout="wide")

    # Initialize session states
    if 'page' not in st.session_state: st.session_state.page = 'upload'
    if 'history' not in st.session_state: st.session_state.history = []

    # --- SIDEBAR HISTORY ---
    with st.sidebar:
        st.title("📜 Scan History")
        if not st.session_state.history:
            st.info("No files scanned yet.")
        else:
            for i, entry in enumerate(reversed(st.session_state.history)):
                if st.button(f"{entry['filename']}", key=f"hist_{i}", use_container_width=True):
                    st.session_state.results = entry
                    st.session_state.page = 'report'
                    st.rerun()
        
        if st.session_state.history and st.button("Clear History"):
            st.session_state.history = []
            st.session_state.page = 'upload'
            st.rerun()

    if st.session_state.page == 'upload':
        render_upload_page()
    else:
        render_report_page()

if __name__ == "__main__":
    main()
