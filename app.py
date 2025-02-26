import streamlit as st
import fitz  # PyMuPDF
import hashlib
import re
import requests
from pdfminer.high_level import extract_text
from distorm3 import Decode, Decode32Bits
from io import BytesIO
from datetime import datetime
import unicodedata
from bidi.algorithm import get_display

def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def extract_metadata(doc):
    metadata = doc.metadata or {}
    pdf_version = metadata.get("format", "Unknown")
    version_years = {"1.4": 2001, "1.5": 2003, "1.6": 2004, "1.7": 2006}
    release_year = version_years.get(pdf_version, "Unknown")
    version_status = "❌ Bad (Outdated)" if release_year != "Unknown" and release_year < 2007 else "✅ Good"
    
    encryption_status = "❌ No Encryption" if "encryption" not in metadata else "✅ Encrypted"
    compliance_status = "❌ Does not meet PDF/A standards for long-term archiving"
    
    creation_date = metadata.get("creationDate", "Unknown")
    modification_date = metadata.get("modDate", "Unknown")
    
    return {
        "Format": f"{pdf_version} (released {release_year}) {version_status}",
        "Encryption": encryption_status,
        "Compliance": compliance_status,
        "Creation Date": creation_date,
        "Modification Date": modification_date,
    }

def detect_js_objects(doc):
    for page in doc:
        text = page.get_text("text")
        if any(keyword in text for keyword in ["/OpenAction", "/JS", "/JavaScript"]):
            return "🚨 JavaScript/OpenAction reference found!"
    return "✅ No JavaScript found in this PDF."

def extract_text_from_pdf(file_bytes):
    try:
        with BytesIO(file_bytes) as f:
            return extract_text(f)
    except Exception as e:
        return f"Error extracting text: {str(e)}"

def detect_16bit_encoded_text(file_bytes):
    try:
        text = file_bytes.decode("utf-16", errors="replace").strip()
        if not text:
            text = file_bytes.decode("utf-16le", errors="replace").strip()
        if not text:
            text = file_bytes.decode("utf-16be", errors="replace").strip()
        if text:
            text = unicodedata.normalize("NFKC", text)
            return get_display(text)  # Corrects RTL text display
        return None
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
                return "❌ DocumentID / InstanceID Mismatch - Possible Forgery"
            return "✅ DocumentID / InstanceID Match"
        return "⚠️ DocumentID / InstanceID Missing"
    except Exception as e:
        return f"⚠️ XMP Metadata Error: {str(e)}"

def main():
    st.set_page_config(page_title="Forensic PDF Analyzer", layout="wide", initial_sidebar_state="collapsed", page_icon="🔍")
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
        
        st.write(detect_js_objects(doc))
        
        binary_alerts = analyze_binary_code(file_bytes)
        for alert in binary_alerts:
            st.write(alert)
        
        st.subheader("📂 XMP Metadata Verification")
        st.write(extract_xmp_metadata(doc))
        
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
