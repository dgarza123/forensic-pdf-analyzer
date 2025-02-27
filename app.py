import streamlit as st
import fitz  # PyMuPDF
import hashlib
import re
import requests
import pdfplumber
import pytesseract
from pdfminer.high_level import extract_text
from io import BytesIO
import unicodedata
from bidi.algorithm import get_display
from PIL import Image

def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def extract_metadata(doc):
    if doc.is_encrypted:
        return {"Error": "❌ PDF is encrypted. Unable to extract metadata."}
    
    metadata = doc.metadata or {}
    pdf_version = metadata.get("format", "Unknown")
    version_years = {"1.4": 2001, "1.5": 2003, "1.6": 2004, "1.7": 2006}
    release_year = version_years.get(pdf_version, "Unknown")
    version_status = "❌ Outdated" if release_year != "Unknown" and release_year < 2007 else "✅ Up-to-date"
    
    encryption_status = "✅ No Encryption" if not doc.is_encrypted else "❌ Encrypted (May hide modifications)"
    compliance_status = "❌ Not PDF/A Compliant"
    
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
        for obj in page.get_text("dict")["blocks"]:
            text = obj.get("text", "")
            if any(kw in text for kw in ["/OpenAction", "/JS", "/JavaScript", "/AA", "/Action"]):
                return "🚨 JavaScript/OpenAction reference found!"
    return "✅ No JavaScript detected."

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

def detect_xmp_metadata(doc):
    try:
        xref_obj = doc.xref_object(1)
        if "/ID" in xref_obj:
            ids = re.findall(r'\[(.*?)\]', xref_obj)
            if len(ids) == 2 and ids[0] != ids[1]:
                return "❌ DocumentID / InstanceID Mismatch - Possible Forgery"
            return "✅ DocumentID / InstanceID Match"
        return "⚠️ DocumentID / InstanceID Missing"
    except Exception:
        return "⚠️ Error Extracting XMP Metadata"

def scan_virustotal(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

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
        
        st.subheader("🛡 JavaScript Detection")
        js_detection = detect_js_objects(doc)
        st.write(js_detection)
        
        st.subheader("📑 XMP Metadata Analysis")
        xmp_result = detect_xmp_metadata(doc)
        st.write(xmp_result)
        
        st.subheader("🛡 VirusTotal Scan")
        api_key = st.secrets["VT_API_KEY"] if "VT_API_KEY" in st.secrets else None
        if api_key:
            vt_result = scan_virustotal(api_key, file_hash)
            st.json(vt_result) if vt_result else st.write("⚠️ VirusTotal scan not available or API error.")
        else:
            st.write("⚠️ VirusTotal API key missing. Scan disabled.")

if __name__ == "__main__":
    main()
