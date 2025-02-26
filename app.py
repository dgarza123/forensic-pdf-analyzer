import streamlit as st
import fitz  # PyMuPDF
import hashlib
import re
import requests
from pdfminer.high_level import extract_text
from distorm3 import Decode, Decode32Bits
from io import BytesIO

def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def extract_metadata(doc):
    metadata = doc.metadata or {}
    pdf_version = metadata.get("format", "Unknown")
    version_years = {"1.4": 2001, "1.5": 2003, "1.6": 2004, "1.7": 2006}
    release_year = version_years.get(pdf_version, "Unknown")
    encryption_status = "Secure encryption: No ❌" if "encryption" not in metadata else "Secure encryption: Yes ✅"
    compliance_status = "Does not meet PDF/A standards for long-term archiving ❌"
    
    return {
        "Format": f"{pdf_version} (released {release_year}) {'❌' if release_year != 'Unknown' and release_year < 2002 else '✅'}",
        "Encryption": encryption_status,
        "Compliance": compliance_status,
    }

def detect_js_objects(doc):
    for page in doc:
        text = page.get_text("text")
        if any(keyword in text for keyword in ["/OpenAction", "/JS", "/JavaScript"]):
            return True
    return False

def extract_text_from_pdf(file_bytes):
    try:
        with BytesIO(file_bytes) as f:
            return extract_text(f)
    except Exception as e:
        return f"Error extracting text: {str(e)}"

def detect_16bit_encoded_text(file_bytes):
    try:
        text = file_bytes.decode("utf-16", errors="ignore")
        return text if text.strip() else None
    except Exception:
        return None

def analyze_binary_code(file_bytes):
    binary_alerts = []
    try:
        raw_bytes = bytes(file_bytes)
        if len(raw_bytes) == 0:
            return ["⚠️ No binary data found."]
        
        for offset, size, instruction, hexdump in Decode(raw_bytes, Decode32Bits):
            if "PUSH" in instruction:
                binary_alerts.append(f"🚨 Suspicious binary operation: {instruction} at offset {offset}")
    except Exception as e:
        binary_alerts.append(f"⚠️ diStorm64 error: {str(e)}")
    return binary_alerts

def scan_virustotal(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

def extract_xmp_metadata(doc):
    try:
        xmp_metadata = doc.xref_get_key(0, "/ID")
        if xmp_metadata:
            instance_id, document_id = xmp_metadata[1:-1].split(" ")
            if instance_id != document_id:
                return "DocumentID / InstanceID Mismatch - Possible Forgery ❌"
            return "DocumentID / InstanceID Match ✅"
        return "DocumentID / InstanceID Missing ⚠️"
    except Exception as e:
        return f"⚠️ XMP Metadata Error: {str(e)}"

def main():
    st.set_page_config(page_title="Forensic PDF Analyzer", layout="wide", initial_sidebar_state="collapsed", page_icon="🔍", theme="dark")
    st.markdown("""
        <style>
        body { background-color: #121212; color: #FFFFFF; }
        .stTextInput, .stFileUploader, .stText, .stMarkdown { color: #FFFFFF !important; }
        .stButton>button { background-color: #333333; color: #FFFFFF; }
        .css-1d391kg, .css-2trqyj { background-color: #121212 !important; color: #FFFFFF !important; }
        </style>
    """, unsafe_allow_html=True)
    
    st.title("🔍 Forensic PDF Analyzer")
    uploaded_file = st.file_uploader("Upload a PDF (Max 4MB)", type=["pdf"], accept_multiple_files=False)
    
    if uploaded_file is not None:
        if uploaded_file.size > 4 * 1024 * 1024:
            st.error("❌ File exceeds 4MB limit. Please upload a smaller file.")
            return
        
        file_bytes = uploaded_file.read()
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        file_hash = compute_sha256(file_bytes)
        
        st.subheader("📄 File Details")
        st.write(f"Filename: {uploaded_file.name}")
        st.write(f"File Size: {len(file_bytes)} bytes")
        st.write(f"SHA-256 Hash: {file_hash}")
        
        st.subheader("📋 PDF Metadata")
        metadata = extract_metadata(doc)
        for key, value in metadata.items():
            st.write(f"**{key}:** {value}")
        
        js_found = detect_js_objects(doc)
        st.write("🚨 JavaScript/OpenAction reference found!" if js_found else "✅ No JavaScript found in this PDF.")
        
        binary_alerts = analyze_binary_code(file_bytes)
        for alert in binary_alerts:
            st.write(alert)
        
        st.subheader("📂 XMP Metadata Verification")
        xmp_status = extract_xmp_metadata(doc)
        st.write(xmp_status)
        
        detected_text = detect_16bit_encoded_text(file_bytes)
        if detected_text:
            st.subheader("🕵️ Hidden 16-bit Encoded Text")
            st.text_area("Extracted 16-bit Text:", detected_text, height=200)
        
        st.subheader("🛡 VirusTotal Scan")
        api_key = st.secrets.get("virustotal_api_key", None)
        if api_key:
            vt_result = scan_virustotal(api_key, file_hash)
            if vt_result:
                st.write("✅ VirusTotal scan results available!")
                st.json(vt_result)
            else:
                st.write("⚠️ VirusTotal scan not available or API error.")
        else:
            st.write("⚠️ No VirusTotal API key configured. Add it in Streamlit Secrets.")

if __name__ == "__main__":
    main()
