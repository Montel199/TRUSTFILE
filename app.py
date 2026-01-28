import streamlit as st
import os
from utils.detector import detect_file_type, analyze_file, generate_hash

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- INJECT CUSTOM CSS ---
# (Paste your CSS here wrapped in <style> tags)
st.markdown("""
<style>
    .stApp { background-color: #0f2027; color: white; }
    .container { 
        background-image: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)), url('your_image_url');
        padding: 40px; border-radius: 16px; text-align: center;
    }
    /* ... rest of your CSS ... */
</style>
""", unsafe_allow_html=True)

# --- APP LOGIC ---
def main():
    # Initialize session state to track which "page" we are on
    if 'page' not in st.session_state:
        st.session_state.page = 'upload'

    if st.session_state.page == 'upload':
        render_upload_page()
    else:
        render_report_page()

def render_upload_page():
    st.markdown('<div class="container"><h2>Upload Your File</h2></div>', unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader("Choose a file", type=None, label_visibility="collapsed")
    
    if uploaded_file is not None:
        # Save file locally (matching your Flask logic)
        file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        # Run your utility functions
        detected_type = detect_file_type(file_path)
        risk_level, reason = analyze_file(file_path, uploaded_file.name, detected_type)
        sha256 = generate_hash(file_path)

        # Store results and switch page
        st.session_state.results = {
            "filename": uploaded_file.name,
            "detected_type": detected_type,
            "risk_level": risk_level,
            "reason": reason,
            "sha256": sha256
        }
        st.session_state.page = 'report'
        st.rerun()

def render_report_page():
    res = st.session_state.results
    st.markdown(f"""
    <div class="container">
        <h2>Analysis Report</h2>
        <div class="report-card">
            <p><span class="report-label">File:</span> {res['filename']}</p>
            <p><span class="report-label">Type:</span> {res['detected_type']}</p>
            <p><span class="report-label">Risk:</span> {res['risk_level']}</p>
            <p><span class="report-label">Reason:</span> {res['reason']}</p>
            <p><span class="report-label">Hash:</span> {res['sha256']}</p>
        </div>
        <button onclick="window.location.reload();" class="btn-primary">Scan Another</button>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("Back to Home"):
        st.session_state.page = 'upload'
        st.rerun()

if __name__ == "__main__":
    main()
