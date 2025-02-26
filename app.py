import streamlit as st
import fitz  # PyMuPDF
import hashlib
import re
import requests
from pdfminer.high_level import extract_text
from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
from io import BytesIO

def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def extract_metadata(doc):
    metadata = doc.metadata
    return {
        "Format": metadata.get("format", "Not Found"),
        "Title": metadata.get("title", "Not Found"),
        "Author": metadata.get("author", "Not Found"),
        "Subject": metadata.get("subject", "Not Found"),
        "Keywords": metadata.get("keywords", "Not Found"),
        "Creator": metadata.get("creator", "Not Found"),
        "Producer": metadata.get("producer", "Not Found"),
        "CreationDate": metadata.get("creationDate", "Not Found"),
        "ModDate": metadata.get("modDate", "Not Found"),
        "Trapped": metadata.get("trapped", "Not Found"),
    }

def detect_itext_version(text):
    match = re.search(r'iText (\d+\.\d+\.\d+)', text)
    if match:
        return match.group(1)
    return "Not Found"

def detect_js_objects(doc):
    js_found = False
    for page in doc:
        if "OpenAction" in page.get_text("text") or "/JS" in page.get_text("text"):
            js_found = True
            break
    return js_found

def extract_text_from_pdf(file_bytes):
    with BytesIO(file_bytes) as f:
        return extract_text(f)

def analyze_binary_code(file_bytes):
    binary_alerts = []
    
    raw_bytes = bytearray(file_bytes)
    
    try:
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
    if response.status_code == 200:
        return response.json()
    return None

def main():
    st.title("🔍 Forensic PDF Analyzer")
    uploaded_file = st.file_uploader("Upload a PDF", type=["pdf"])
    
    if uploaded_file is not None:
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
            
        st.subheader("📂 iText & JavaScript Detection")
        extracted_text = extract_text_from_pdf(file_bytes)
        itext_version = detect_itext_version(extracted_text)
        js_found = detect_js_objects(doc)
        
        st.write(f"**iText Version Detected:** {itext_version}")
        if js_found:
            st.write("🚨 JavaScript/OpenAction reference found!")
        else:
            st.write("✅ No JavaScript found in this PDF.")
        
        st.subheader("🔍 Binary Code Analysis with diStorm64")
        binary_alerts = analyze_binary_code(file_bytes)
        for alert in binary_alerts:
            st.write(alert)
        
        st.subheader("🛡 VirusTotal Scan")
        api_key = st.secrets["virustotal_api_key"]  # Store API key in Streamlit secrets
        vt_result = scan_virustotal(api_key, file_hash)
        
        if vt_result:
            st.write("✅ VirusTotal scan results available!")
            st.json(vt_result)
        else:
            st.write("⚠️ VirusTotal scan not available or API error.")
        
if __name__ == "__main__":
    main()
