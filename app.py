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
import openai  # Ensure you have openai>=1.0.0 installed

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
    pdf_version = getattr(doc, "pdf_version", None)
    if pdf_version is not None and pdf_version != 0:
        pdf_version_str = f"{pdf_version:.1f}"
    else:
        try:
            header = file_bytes[:20].decode("latin1", errors="replace")
            m = re.search(r"%PDF-(\d\.\d)", header)
            if m:
                pdf_version_str = m.group(1)
            else:
                meta_format = (doc.metadata or {}).get("format", "Unknown")
                pdf_version_str = meta_format.upper().replace("PDF ", "").strip()
        except Exception:
            pdf_version_str = "Unknown"

    version_years = {
        "1.4": 2001,
        "1.5": 2003,
        "1.6": 2004,
        "1.7": 2006
    }
    release_year = version_years.get(pdf_version_str, "Unknown")
    if release_year != "Unknown" and release_year < 2007:
        version_status = "❌ Severely Outdated"
    else:
        version_status = "✅ Good"

    if "encryption" in (doc.metadata or {}):
        encryption_status = "❌ Content is encrypted, but signatures are missing"
    else:
        encryption_status = "✅ No Encryption"

    compliance_status = "❌ Not PDF/A Compliant"
    metadata_dict = doc.metadata or {}

    creation_date = metadata_dict.get("creationDate", "")
    if not creation_date or creation_date.strip() == "":
        creation_date = "⚠️ Sanitized by PDF source"

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

def detect_16bit_encoded_text(file_bytes, display_limit=1000):
    """
    Attempt to detect hidden JavaScript or suspicious strings in various 16-bit encodings.
    Also converts the file to hex and binary for analysis, but only displays a truncated snippet.
    """
    results = []
    encodings = ["utf-16", "utf-16le", "utf-16be", "utf-8"]
    for encoding in encodings:
        try:
            text = file_bytes.decode(encoding, errors="replace").strip()
            if text:
                normalized_text = get_display(unicodedata.normalize("NFKC", text))
                js_patterns = re.findall(
                    r"(?i)(eval\(|document\.|window\.|script>|onload=|setTimeout\()",
                    normalized_text
                )
                pattern_msg = ""
                if js_patterns:
                    pattern_msg = f"\n🚨 Hidden JavaScript detected: {', '.join(set(js_patterns))}"
                truncated_text = normalized_text[:display_limit] + "..." if len(normalized_text) > display_limit else normalized_text
                results.append(f"--- Decoded with {encoding} ---\n{truncated_text}{pattern_msg}")
        except Exception:
            continue

    try:
        hex_data = binascii.hexlify(file_bytes).decode("utf-8").lower()
        truncated_hex = hex_data[:display_limit] + "..." if len(hex_data) > display_limit else hex_data
        hex_alert = ""
        if "6576616c28" in hex_data:
            hex_alert = "\n🚨 Found 'eval(' in hex representation!"
        results.append(f"--- Hexadecimal (truncated) ---\n{truncated_hex}{hex_alert}")
    except Exception as e:
        results.append(f"\nError converting file to hex: {str(e)}")

    try:
        bin_data = bin(int(binascii.hexlify(file_bytes), 16))[2:]
        truncated_bin = bin_data[:display_limit] + "..." if len(bin_data) > display_limit else bin_data
        results.append(f"--- Binary (truncated) ---\n{truncated_bin}")
    except Exception as e:
        results.append(f"\nError converting file to binary: {str(e)}")

    final_output = "\n\n".join(results).strip()
    return final_output if final_output else None

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

def search_fraud_markers(text):
    """
    Search the provided text for potential fraud markers using regex patterns.
    Returns a dictionary of marker types and the matches found.
    """
    markers = {
        "T-Numbers": r"\bT-?\d{6,9}\b",
        "Certificate of Title Numbers": r"Certificate\s*No[:.\s]*\d{6,9}",
        "APN": r"\b\d{3}[-\s]?\d{2,3}[-\s]?\d{2,3}\b",
        "PDF Timestamps": r"D:\d{14}",
        "Alternative Date (YYYY-MM-DD)": r"\b\d{4}-\d{2}-\d{2}\b",
        "Raw 8-digit Date": r"\b\d{8}\b",
        "Unix Timestamp": r"\b\d{10}\b"
    }
    results = {}
    for marker, pattern in markers.items():
        matches = re.findall(pattern, text)
        if matches:
            results[marker] = matches
    return results

def analyze_with_openai(prompt, api_key):
    """
    Use OpenAI's ChatCompletion API (gpt-3.5-turbo) to analyze the provided prompt.
    This uses the new interface with a system message for context.
    """
    try:
        openai.api_key = api_key
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a forensic analyst specializing in PDF fraud detection. Analyze the following text snippet for potential fraud markers or obfuscated JavaScript."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.2,
            top_p=1,
            frequency_penalty=0,
            presence_penalty=0
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error calling OpenAI API: {str(e)}"

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
        metadata = extract_metadata(doc, file_bytes)
        for key, value in metadata.items():
            st.write(f"**{key}:** {value}")

        # Extract text (try direct extraction, else OCR)
        extracted_text = extract_text_from_pdf(file_bytes)
        if "⚠️" in extracted_text:
            extracted_text = extract_text_with_ocr(file_bytes)
        st.text_area("Extracted Text:", extracted_text, height=200)

        # 16-bit/Unicode detection with expander for full text
        st.subheader("🔎 16-bit/Unicode Text Analysis")
        unicode_result = detect_16bit_encoded_text(file_bytes)
        if unicode_result:
            truncated_result = unicode_result[:1000] + "..." if len(unicode_result) > 1000 else unicode_result
            st.write(truncated_result)
            with st.expander("Show Full Decoded Text"):
                st.text_area("Full Decoded Text", unicode_result, height=300)
        else:
            st.write("✅ No suspicious 16-bit encoded text found.")

        # Hidden data detection (after EOF)
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

        # Fraud Marker Analysis
        st.subheader("🔍 Fraud Marker Analysis")
        fraud_markers = search_fraud_markers(extracted_text)
        if fraud_markers:
            for marker, matches in fraud_markers.items():
                st.write(f"**{marker}:** {', '.join(matches)}")
        else:
            st.write("✅ No fraud markers detected.")

        # Optional: OpenAI Analysis
        if "openai_api_key" in st.secrets:
            st.subheader("🤖 OpenAI Analysis")
            # Use the first 1000 characters of the extracted text as context
            prompt = ("Analyze the following snippet from a PDF file for potential fraud markers or suspicious obfuscation techniques:\n\n" +
                      extracted_text[:1000])
            openai_response = analyze_with_openai(prompt, st.secrets["openai_api_key"])
            st.text_area("OpenAI Analysis", openai_response, height=200)
        else:
            st.write("⚠️ OpenAI API key not found in secrets. Skipping OpenAI analysis.")

if __name__ == "__main__":
    main()
