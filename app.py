import streamlit as st
import fitz  # PyMuPDF
import hashlib
import re
import requests
import pdfplumber
import pytesseract
from pdfminer.high_level import extract_text
from io import BytesIO
from datetime import datetime
import unicodedata
from bidi.algorithm import get_display
from PIL import Image

def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def extract_metadata(doc):
    metadata = doc.metadata or {}
    pdf_version = metadata.get("format", "Unknown")
    version_years = {"1.4": 2001, "1.5": 2003, "1.6": 2004, "1.7": 2006}
    release_year = version_years.get(pdf_version, "Unknown")
    version_status = "❌ Bad (Outdated)" if release_year != "Unknown" and release_year < 2007 else "✅ Good"
    
    encryption_status = "❌ Content is encrypted, but signatures are missing" if "encryption" in metadata else "✅ No Encryption"
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
        if any(keyword in text for keyword in ["/OpenAction", "/JS", "/JavaScript", "/AA", "/Action"]):
            return "🚨 JavaScript/OpenAction reference found!"
    return "✅ No JavaScript found in this PDF."

def extract_text_from_pdf(file_bytes):
    try:
        with pdfplumber.open(BytesIO(file_bytes)) as pdf:
            text = "\n".join(page.extract_text() or "" for page in pdf.pages)
            return text.strip() if text else "⚠️ No extractable text found."
    except Exception as e:
        return f"Error extracting text: {str(e)}"

def extract_text_with_ocr(file_bytes):
    try:
        with pdfplumber.open(BytesIO(file_bytes)) as pdf:
            images = [page.to_image().original for page in pdf.pages]
            ocr_text = "\n".join(pytesseract.image_to_string(img) for img in images if img)
            return ocr_text.strip() if ocr_text else "⚠️ OCR failed to extract text."
    except Exception as e:
        return f"Error extracting OCR text: {str(e)}"

def detect_16bit_encoded_text(file_bytes):
    try:
        encodings = ["utf-16", "utf-16le", "utf-16be", "utf-8"]
        for encoding in encodings:
            try:
                text = file_bytes.decode(encoding, errors="replace").strip()
                if text:
                    normalized_text = get_display(unicodedata.normalize("NFKC", text))
                    js_patterns = re.findall(r"(?i)(eval\(|document\.|window\.|script>|onload=|setTimeout\()", normalized_text)
                    if js_patterns:
                        return f"🚨 Hidden JavaScript detected in Unicode text! Found: {', '.join(set(js_patterns))}"
                    return normalized_text
            except Exception:
                continue
        return None
    except Exception:
        return None

def scan_virustotal(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

def extract_xmp_metadata(doc):
    try:
        xmp_metadata = doc.metadata.get("/ID", None)
        if xmp_metadata:
            ids = xmp_metadata.strip("[]").split()
            if len(ids) == 2 and ids[0] != ids[1]:
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
        st.write(f"SHA-256 Hash: {file_hash}")
        
        st.subheader("📋 PDF Metadata")
        metadata = extract_metadata(doc)
        for key, value in metadata.items():
            st.write(f"**{key}:** {value}")
        
        extracted_text = extract_text_from_pdf(file_bytes)
        if "⚠️" in extracted_text:
            extracted_text = extract_text_with_ocr(file_bytes)
        st.text_area("Extracted Text:", extracted_text, height=200)
        
        st.subheader("🛡 VirusTotal Scan")
        api_key = "3cc8d84f66577cd5cccb7357cf121b36d12d81cc7b690d58439abf6bc69d0c52"
        vt_result = scan_virustotal(api_key, file_hash)
        st.json(vt_result) if vt_result else st.write("⚠️ VirusTotal scan not available or API error.")

if __name__ == "__main__":
    main()
