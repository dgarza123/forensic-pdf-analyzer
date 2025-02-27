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

##########################
#     GLOBAL SETTINGS    #
##########################

# YOUR VirusTotal API key (for demonstration only).
# Recommended: move this to a .env file for better security.
VIRUSTOTAL_API_KEY = "3cc8d84f66577cd5cccb7357cf121b36d12d81cc7b690d58439abf6bc69d0c52"


##########################
#       FUNCTIONS        #
##########################

def compute_sha256(file_bytes):
    """Compute the SHA-256 hash of the uploaded file."""
    return hashlib.sha256(file_bytes).hexdigest()


def extract_metadata(doc):
    """
    Extract PDF metadata and identify the PDF version.
    This function tries:
      1) doc.pdf_version (float from PyMuPDF)
      2) doc.metadata['format'] if pdf_version is None or zero
    """
    # Attempt doc.pdf_version (often a float, e.g. 1.4)
    pdf_version = doc.pdf_version
    if pdf_version is not None and pdf_version != 0:
        # Convert float to string (1.4 -> "1.4")
        pdf_version_str = f"{pdf_version:.1f}"
    else:
        # Fallback to metadata
        meta_format = (doc.metadata or {}).get("format", "Unknown")
        # Sometimes meta_format is "PDF 1.4" or just "1.4"
        pdf_version_str = meta_format.upper().replace("PDF ", "").strip()

    # Known versions -> release years
    version_years = {
        "1.4": 2001,
        "1.5": 2003,
        "1.6": 2004,
        "1.7": 2006
    }

    # Determine release year
    release_year = version_years.get(pdf_version_str, "Unknown")

    # Mark as severely outdated if year < 2007 and known
    if release_year != "Unknown" and release_year < 2007:
        version_status = "❌ Bad (Severely Outdated)"
    else:
        version_status = "✅ Good"

    # Encryption check (this simplistic approach may need refining)
    if "encryption" in (doc.metadata or {}):
        encryption_status = "❌ Content is encrypted, but signatures are missing"
    else:
        encryption_status = "✅ No Encryption"

    # Hard-coded compliance status for demonstration
    compliance_status = "❌ Not PDF/A Compliant"

    # Grab creation/modification dates from metadata
    metadata_dict = doc.metadata or {}
    creation_date = metadata_dict.get("creationDate", "Unknown")
    modification_date = metadata_dict.get("modDate", "Unknown")

    # Construct final string for PDF version
    format_str = f"PDF {pdf_version_str} (released {release_year}) {version_status}"

    return {
        "Format": format_str,
        "Encryption": encryption_status,
        "Compliance": compliance_status,
        "Creation Date": creation_date,
        "Modification Date": modification_date,
    }


def detect_js_objects(doc):
    """
    Scan for JavaScript references like /OpenAction, /JS, /JavaScript, /AA, /Action.
    """
    for page in doc:
        text = page.get_text("text")
        if any(keyword in text for keyword in ["/OpenAction", "/JS", "/JavaScript", "/AA", "/Action"]):
            return "🚨 JavaScript/OpenAction reference found!"
    return "✅ No JavaScript detected."


def extract_text_from_pdf(file_bytes):
    """Attempt to extract text using pdfplumber."""
    try:
        with pdfplumber.open(BytesIO(file_bytes)) as pdf:
            text = "\n".join(page.extract_text() or "" for page in pdf.pages)
            return text.strip() if text else "⚠️ No extractable text found."
    except Exception as e:
        return f"Error extracting text: {str(e)}"


def extract_text_with_ocr(file_bytes):
    """
    Fallback OCR extraction if direct text extraction fails.
    Requires Tesseract installed on the system.
    """
    try:
        with pdfplumber.open(BytesIO(file_bytes)) as pdf:
            images = [page.to_image().original for page in pdf.pages]
            ocr_text = "\n".join(pytesseract.image_to_string(img) for img in images if img)
            return ocr_text.strip() if ocr_text else "⚠️ OCR failed to extract text."
    except Exception as e:
        return f"Error extracting OCR text: {str(e)}"


def detect_16bit_encoded_text(file_bytes):
    """
    Attempt to detect hidden JavaScript or suspicious strings
    in various 16-bit encodings (UTF-16, UTF-16LE, etc.).
    """
    try:
        encodings = ["utf-16", "utf-16le", "utf-16be", "utf-8"]
        for encoding in encodings:
            try:
                text = file_bytes.decode(encoding, errors="replace").strip()
                if text:
                    # Normalize and handle right-to-left
                    normalized_text = get_display(unicodedata.normalize("NFKC", text))
                    # Look for typical JS patterns
                    js_patterns = re.findall(
                        r"(?i)(eval\(|document\.|window\.|script>|onload=|setTimeout\()",
                        normalized_text
                    )
                    if js_patterns:
                        return f"🚨 Hidden JavaScript detected in Unicode text! Found: {', '.join(set(js_patterns))}"
                    return normalized_text
            except Exception:
                continue
        return None
    except Exception:
        return None


def scan_virustotal(api_key, file_hash):
    """Query the VirusTotal API for the given file hash."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None


def extract_xmp_metadata(doc):
    """
    Check for DocumentID / InstanceID in XMP metadata to detect mismatch.
    """
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


##########################
#         MAIN APP       #
##########################

def main():
    st.set_page_config(
        page_title="Forensic PDF Analyzer",
        layout="wide",
        initial_sidebar_state="collapsed",
        page_icon="🔍"
    )
    st.title("🔍 Forensic PDF Analyzer")

    # File Uploader
    uploaded_file = st.file_uploader(
        "Upload a PDF (Max 4MB)",
        type=["pdf"],
        accept_multiple_files=False
    )
    
    if uploaded_file is not None:
        # Enforce file size limit
        if uploaded_file.size > 4 * 1024 * 1024:
            st.error("❌ File exceeds 4MB limit. Please upload a smaller file.")
            return
        
        file_bytes = uploaded_file.read()
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        file_hash = compute_sha256(file_bytes)
        
        # Display file details
        st.subheader("📄 File Details")
        st.write(f"**Filename:** {uploaded_file.name}")
        st.write(f"**SHA-256 Hash:** {file_hash}")
        
        # Extract and display PDF metadata
        st.subheader("📋 PDF Metadata")
        metadata = extract_metadata(doc)
        for key, value in metadata.items():
            st.write(f"**{key}:** {value}")
        
        # Extract text (try direct, else OCR)
        extracted_text = extract_text_from_pdf(file_bytes)
        if "⚠️" in extracted_text:
            extracted_text = extract_text_with_ocr(file_bytes)
        
        # Display extracted text
        st.text_area("Extracted Text:", extracted_text, height=200)
        
        # 16-bit/Unicode detection
        st.subheader("🔎 16-bit/Unicode Text Analysis")
        unicode_result = detect_16bit_encoded_text(file_bytes)
        if unicode_result:
            st.write(unicode_result)
        else:
            st.write("✅ No suspicious 16-bit encoded text found.")
        
        # JavaScript detection
        st.subheader("🛡 JavaScript Detection")
        js_status = detect_js_objects(doc)
        st.write(js_status)
        
        # XMP Metadata Analysis
        st.subheader("📑 XMP Metadata Analysis")
        xmp_status = extract_xmp_metadata(doc)
        st.write(xmp_status)
        
        # VirusTotal Scan
        st.subheader("🛡 VirusTotal Scan")
        if VIRUSTOTAL_API_KEY:
            vt_result = scan_virustotal(VIRUSTOTAL_API_KEY, file_hash)
            if vt_result:
                st.json(vt_result)
            else:
                st.write("⚠️ VirusTotal scan not available or API error.")
        else:
            st.write("⚠️ VirusTotal API key missing. Scan disabled.")


if __name__ == "__main__":
    main()
