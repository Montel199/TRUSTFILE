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
    # Add Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="TRUSTFILE Analysis Report", ln=True, align='C')
    pdf.ln(10)
    
    # Add Content
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"File Name: {res['filename']}", ln=True)
    pdf.cell(200, 10, txt=f"Detected Type: {res['detected_type']}", ln=True)
    pdf.cell(200, 10, txt=f"Risk Level: {res['risk_level']}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Reason: {res['reason']}")
    pdf.ln(5)
    pdf.set_font("Arial", 'I', 10)
    pdf.multi_cell(0, 10, txt=f"SHA-256 Hash: {res['sha256']}")
    
    # Return as bytes
    return pdf.output(dest='S').encode('latin-1')

# --- PAGE: UPLOAD ---
def render_upload_page():
    st.markdown("""
        <div style='text-align: center; padding: 20px;'>
            <h1>🛡️ TRUSTFILE</h1>
            <p>Secure File Type & Risk Analysis</p>
        </div>
    """, unsafe_allow_html=True)
    
    with st.container(border=True):
        uploaded_file = st.file_uploader("Upload your file for analysis", type=None)
        
        if uploaded_file is not None:
            # Save file locally
            file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            # Run Analysis
            with st.spinner('Analyzing file integrity...'):
                detected_type = detect_file_type(file_path)
                risk_level, reason = analyze_file(file_path, uploaded_file.name, detected_type)
                sha256 = generate_hash(file_path)

            # Store results in Session State
            st.session_state.results = {
                "filename": uploaded_file.name,
                "detected_type": detected_type,
                "risk_level": risk_level,
                "reason": reason,
                "sha256": sha256
            }
            st.session_state.page = 'report'
            st.rerun()

# --- PAGE: REPORT ---
def render_report_page():
    if 'results' not in st.session_state:
        st.session_state.page = 'upload'
        st.rerun()
        return

    res = st.session_state.results
    
    # 1. Header & Theme Toggle
    col_t1, col_t2 = st.columns([0.8, 0.2])
    with col_t2:
        light_mode = st.toggle("💡 Light Mode")

    # Dynamic styling colors
    bg_color = "#f0f2f6" if light_mode else "#0f2027"
    text_color = "#000" if light_mode else "#fff"
    card_bg = "#ffffff" if light_mode else "#1e2129"

    # 2. Visual Report Card
    st.markdown(f"""
    <div style="background-color: {bg_color}; color: {text_color}; padding: 30px; border-radius: 15px; transition: 0.3s;">
        <h2 style="text-align: center; margin-bottom: 20px;">Analysis Report</h2>
        <div style="background-color: {card_bg}; padding: 25px; border-radius: 12px; border: 1px solid #4e4e4e; box-shadow: 0px 4px 12px rgba(0,0,0,0.1);">
            <p style="margin: 10px 0;"><strong>📄 File:</strong> {res['filename']}</p>
            <p style="margin: 10px 0;"><strong>🔍 Type:</strong> {res['detected_type']}</p>
            <p style="margin: 10px 0;"><strong>⚠️ Risk:</strong> 
                <span style="color: {'#ff4b4b' if 'SUSPICIOUS' in res['risk_level'] else '#00cc66'}; font-weight: bold;">
                    {res['risk_level']}
                </span>
            </p>
            <p style="margin: 10px 0;"><strong>📝 Reason:</strong> {res['reason']}</p>
            <hr style="border: 0.5px solid #4e4e4e; margin: 20px 0;">
            <p style="font-size: 0.85em; font-family: monospace; word-break: break-all; opacity: 0.8;">
                <strong>HASH (SHA-256):</strong><br>{res['sha256']}
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 3. Action Buttons
    st.write("") 
    btn_col1, btn_col2, btn_col3 = st.columns(3)
    
    with btn_col1:
        if st.button("🔄 Scan Another", use_container_width=True):
            st.session_state.page = 'upload'
            st.rerun()

    with btn_col2:
        try:
            pdf_bytes = create_pdf(res)
            st.download_button(
                label="📥 Download PDF",
                data=pdf_bytes,
                file_name=f"Report_{res['filename']}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        except Exception as e:
            st.error("Could not generate PDF")

    with btn_col3:
        if st.button("🏠 Back to Home", use_container_width=True):
            st.session_state.page = 'upload'
            st.rerun()

# --- MAIN APP LOGIC ---
def main():
    st.set_page_config(page_title="TRUSTFILE Analysis", page_icon="🛡️")

    if 'page' not in st.session_state:
        st.session_state.page = 'upload'

    if st.session_state.page == 'upload':
        render_upload_page()
    else:
        render_report_page()

if __name__ == "__main__":
    main()
