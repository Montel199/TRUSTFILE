import streamlit as st
import os
from fpdf import FPDF
from utils.detector import detect_file_type, analyze_file, generate_hash

# --- PDF GENERATOR ---
def create_pdf(res):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="TRUSTFILE Analysis Report", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"File: {res['filename']}", ln=True)
    pdf.cell(200, 10, txt=f"Detected Type: {res['detected_type']}", ln=True)
    pdf.cell(200, 10, txt=f"Risk Level: {res['risk_level']}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Reason: {res['reason']}")
    pdf.multi_cell(0, 10, txt=f"SHA-256 Hash: {res['sha256']}")
    
    return pdf.output(dest='S').encode('latin-1')

# --- REFRESHED REPORT PAGE ---
def render_report_page():
    res = st.session_state.results
    
    # 1. THEME TOGGLE (Top Right)
    col_t1, col_t2 = st.columns([0.8, 0.2])
    with col_t2:
        # Streamlit handles light/dark mode automatically, but we can 
        # let users toggle custom CSS overrides here.
        theme_toggle = st.toggle("💡 Light Mode")

    # 2. VISUAL REPORT
    st.markdown(f"""
    <div class="container" style="background-color: {'#f0f2f6' if theme_toggle else '#0f2027'}; color: {'#000' if theme_toggle else '#fff'};">
        <h2>Analysis Report</h2>
        <div class="report-card" style="border: 1px solid #4e4e4e; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
            <p><strong>File:</strong> {res['filename']}</p>
            <p><strong>Type:</strong> {res['detected_type']}</p>
            <p><strong>Risk:</strong> <span style="color: {'#ff4b4b' if 'SUSPICIOUS' in res['risk_level'] else '#00cc66'}">{res['risk_level']}</span></p>
            <p><strong>Reason:</strong> {res['reason']}</p>
            <p style="font-size: 0.8em; word-break: break-all;"><strong>Hash:</strong> {res['sha256']}</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 3. ACTION BUTTONS
    st.divider()
    btn_col1, btn_col2, btn_col3 = st.columns(3)
    
    with btn_col1:
        if st.button("🔄 Scan Another", use_container_width=True):
            st.session_state.page = 'upload'
            st.rerun()

    with btn_col2:
        # PDF EXPORT
        pdf_bytes = create_pdf(res)
        st.download_button(
            label="📥 Download PDF",
            data=pdf_bytes,
            file_name=f"Report_{res['filename']}.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    with btn_col3:
        if st.button("🏠 Back to Home", use_container_width=True):
            st.session_state.page = 'upload'
            st.rerun()
