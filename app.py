import streamlit as st
import subprocess
import fitz  # PyMuPDF
import hashlib
import re
import pdfplumber
import pytesseract
from io import BytesIO
import unicodedata
from bidi.algorithm import get_display
from PIL import Image
import binascii

##########################
#   Helper Functions     #
##########################

def get_git_commit():
    """Return the current git commit hash (short version) or 'unknown' if unavailable."""
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"]).strip().decode("utf-8")
        return commit
    except Exception:
        return "unknown"

def compute_sha256(file_bytes):
    """Compute the SHA-256 hash of the uploaded file."""
    return hashlib.sha256(file_bytes).hexdigest()

def extract_metadata(doc, file_bytes):
    """
    Extract PDF metadata and identify the PDF version.
    Attempts to use:
      1. doc.pdf_version (if available),
      2. The file header from file_bytes,
      3. Finally, falls back to doc.metadata.
    If creation or modification dates are missing or empty, displays "⚠️ Sanitized by PDF source."
    """
    # Attempt to get doc.pdf_version if it exists
    pdf_version = getattr(doc, "pdf_version", None)
    if pdf_version is not None and pdf_version != 0:
        pdf_version_str = f"{pdf_version:.1f}"
    else:
        # Fallback: read the header from file_bytes (e.g., "%PDF-1.4")
        try:
            header = file_bytes[:20].decode("latin1", errors="replace")
            m = re.search(r"%PDF-(\d\.\d)", header)
            if m:
                pdf_version_str = m.group(1)
            else:
                # Final fallback: try to use metadata field "format"
                meta_format = (doc.metadata or {}).get("format", "Unknown")
                pdf_version_str = meta_format.upper().replace("PDF ", "").strip()
        except Exception:
            pdf_version_str = "Unknown"

    # Mapping known PDF versions to their release years
    version_years = {
        "1.4": 2001,
        "1.5": 2003,
        "1.6": 2004,
        "1.7": 2006
    }
    release_year = version_years.get(pdf_version_str, "Unknown")

    # Mark as severely outdated if known release year is less than 2007
    if release_year != "Unknown" and release_year < 2007:
        version_status = "❌ Severely Outdated"
    else:
        version_status = "✅ Good"

    # Simple encryption check
    if "encryption" in (doc.metadata or {}):
        encryption_status = "❌ Content is encrypted, but signatures are missing"
    else:
        encryption_status = "✅ No Encryption"

    compliance_status = "❌ Not PDF/A Compliant"
    metadata_dict = doc.metadata or {}

    # Handle creation date: treat empty string as missing
    creation_date = metadata_dict.get("creationDate", "")
    if not creation_date or creation_date.strip() == "":
        creation_date = "⚠️ Sanitized by PDF source"

    # Handle modification date: treat empty string as missing
    modification_date = metadata_dict.get("modDate", "")
    if not modification_date or modification_date.strip() == "":
        modification_date = "⚠️ Sanitized by PDF source"

    format_str = f"PDF {pdf_version_str} (released {release_year}) {version_status}"

    return {
        "Format": format_str,
        "Encryption": encryption_status,
        "Compliance": compliance_status,
        "Creation Date": creation_date,
        "Modification Date": modification_date,
    }

def detect_js_objects(doc):
    """Scan for JavaScript references like /OpenAction, /JS, /JavaScript, /AA, /Action."""
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
    """Fallback OCR extraction if direct text extraction fails. Requires Tesseract installed."""
    try:
        with pdfplumber.open(BytesIO(file_bytes)) as pdf:
            images = [page.to_image().original for page in pdf.pages]
            ocr_text = "\n".join(pytesseract.image_to_string(img) for img in images if img)
            return ocr_text.strip() if ocr_text else "⚠️ OCR failed to extract text."
    except Exception as e:
        return f"Error extracting OCR text: {str(e)}"

def detect_16bit_encoded_text(file_bytes):
    """
    Attempt to detect hidden JavaScript or suspicious strings in various 16-bit encodings.
    This function decodes the file using multiple encodings and returns the raw decoded text.
    It also converts the entire file to hex and binary representations for additional analysis.
    """
    result = ""
    # Try decoding using several encodings and log the output
    encodings = ["utf-16", "utf-16le", "utf-16be", "utf-8"]
    for encoding in encodings:
        try:
            text = file_bytes.decode(encoding, errors="replace").strip()
            if text:
                normalized_text = get_display(unicodedata.normalize("NFKC", text))
                result += f"\n--- Decoded with {encoding} ---\n{normalized_text}\n"
                js_patterns = re.findall(
                    r"(?i)(eval\(|document\.|window\.|script>|onload=|setTimeout\()",
                    normalized_text
                )
                if js_patterns:
                    result += f"\n🚨 Hidden JavaScript detected! Patterns: {', '.join(set(js_patterns))}\n"
        except Exception:
            continue

    # Convert the entire file to a hex string and look for suspicious patterns
    try:
        hex_data = binascii.hexlify(file_bytes).decode("utf-8")
        result += f"\n--- Hexadecimal Representation ---\n{hex_data}\n"
        # Example: Look for hex representation of "eval(" which is 6576616c28
        if "6576616c28" in hex_data.lower():
            result += "\n🚨 Found 'eval(' in hex representation!\n"
    except Exception as e:
        result += f"\nError converting file to hex: {str(e)}\n"

    # Convert the entire file to binary (a string of 0s and 1s) if desired (this can be very long)
    try:
        bin_data = bin(int(binascii.hexlify(file_bytes), 16))[2:]
        result += f"\n--- Binary Representation (truncated) ---\n{bin_data[:500]}...\n"
    except Exception as e:
        result += f"\nError converting file to binary: {str(e)}\n"

    return result if result.strip() != "" else None

def detect_hidden_data(file_bytes):
    """
    Check for hidden data appended after the PDF's EOF marker.
    """
    eof_marker = b"%%EOF"
    eof_index = file_bytes.rfind(eof_marker)
    if eof_index != -1 and eof_index < len(file_bytes) - len(eof_marker):
        hidden = file_bytes[eof_index + len(eof_marker):]
        if hidden.strip():
            try:
                # Attempt to decode the hidden data
                hidden_text = hidden.decode("latin1", errors="replace")
            except Exception:
                hidden_text = str(hidden)
            return f"🚨 Hidden data found after EOF:\n{hidden_text}"
    return "✅ No hidden data found after EOF."

def extract_xmp_metadata(doc):
    """Check for DocumentID / InstanceID in XMP metadata to detect mismatch."""
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

    # Display the current commit hash in the sidebar for debugging
    st.sidebar.write(f"**Commit:** {get_git_commit()}")

    # File Uploader
    uploaded_file = st.file_uploader("Upload a PDF (Max 4MB)", type=["pdf"], accept_multiple_files=False)
    
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
        
        # Extract and display PDF metadata (pass file_bytes for header extraction)
        st.subheader("📋 PDF Metadata")
        metadata = extract_metadata(doc, file_bytes)
        for key, value in metadata.items():
            st.write(f"**{key}:** {value}")
        
        # Extract text (try direct extraction, else OCR)
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
        
        # Hidden data detection (e.g., after EOF marker)
        st.subheader("🕵️ Hidden Data Detection")
        hidden_result = detect_hidden_data(file_bytes)
        st.write(hidden_result)
        
        # JavaScript detection
        st.subheader("🛡 JavaScript Detection")
        js_status = detect_js_objects(doc)
        st.write(js_status)
        
        # XMP Metadata Analysis
        st.subheader("📑 XMP Metadata Analysis")
        xmp_status = extract_xmp_metadata(doc)
        st.write(xmp_status)

if __name__ == "__main__":
    main()
