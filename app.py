import fitz  # PyMuPDF
import pdfplumber
import streamlit as st
import unicodedata
import chardet
import io
import binascii
import re
from deep_translator import GoogleTranslator
from PIL import Image

# Function to extract hidden Unicode text from PDFs
def extract_hidden_unicode_text(pdf_document):
    hidden_text = []
    for page in pdf_document:
        try:
            text_dict = page.get_text("dict")  # Extracts text along with encoding info
            extracted_text = " ".join([block["text"] for block in text_dict["blocks"] if "text" in block])
            if extracted_text.strip():
                hidden_text.append(extracted_text)
        except Exception as e:
            hidden_text.append(f"⚠️ Error extracting text from page: {str(e)}")
    
    return "\n\n".join(hidden_text) if hidden_text else "⚠️ No extractable hidden Unicode text found."

# Function to fix Unicode issues
def decode_unicode_text(text):
    detected_encoding = chardet.detect(text.encode())["encoding"]
    try:
        return text.encode("latin1").decode(detected_encoding) if detected_encoding else text
    except:
        return unicodedata.normalize("NFKC", text)  # Normalize weird Unicode characters

# Function to detect and extract hidden hex data
def extract_hex_data(text):
    hex_data = binascii.hexlify(text.encode()).decode()
    return hex_data if hex_data else "No hidden hex data detected."

# Function to convert hex back to text and check for hidden content
def hex_to_text(hex_string):
    try:
        return bytes.fromhex(hex_string).decode("utf-8", errors="ignore")
    except:
        return "⚠️ Could not decode hex text"

# Function to check if the year 1999 appears in the extracted text
def check_for_1999(text):
    return "1999 found in extracted text!" if "1999" in text else "1999 not found."

# Function to extract extra bytes after EOF
def extract_extra_bytes(pdf_bytes):
    eof_index = pdf_bytes.rfind(b'%%EOF')
    if eof_index != -1:
        extra_data = pdf_bytes[eof_index + 5:]  # Capture bytes after EOF
        return extra_data.hex() if extra_data else "No extra bytes found."
    return "No EOF marker found."

# Function to extract object streams from PDFs
def extract_compressed_objects(pdf_document):
    suspicious_objects = []
    for obj in range(pdf_document.xref_length()):
        try:
            obj_str = pdf_document.xref_object(obj)
            if "/ObjStm" in obj_str:
                suspicious_objects.append(obj_str)
        except:
            continue
    return suspicious_objects if suspicious_objects else "No compressed object streams found."

# Function to detect mixed Unicode encodings
def detect_mixed_unicode(text):
    encodings = ["utf-8", "utf-16le", "utf-16be", "utf-32"]
    detected_variants = []
    
    for encoding in encodings:
        try:
            decoded_text = text.encode("latin1").decode(encoding)
            if decoded_text.strip():
                detected_variants.append(f"{encoding}: {decoded_text[:50]}...")
        except:
            continue

    return detected_variants if detected_variants else "No mixed Unicode detected."

# Function to detect suspicious metadata patterns
def detect_suspicious_metadata(metadata):
    suspicious_fields = {}
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    base64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
    url_pattern = re.compile(r'https?://[^\s]+')  # Detects hidden URLs

    for key, value in metadata.items():
        if isinstance(value, list):  # Convert lists to strings
            value = " ".join(map(str, value))
        if value is None:  # Skip None values
            continue
        value = str(value)  # Ensure it's a string

        if hex_pattern.match(value) or base64_pattern.match(value) or url_pattern.search(value):
            suspicious_fields[key] = value

    return suspicious_fields if suspicious_fields else "No hidden metadata detected."

# Streamlit UI
st.title("🔍 Forensic PDF Analyzer & Unicode Detector")

uploaded_file = st.file_uploader("Upload a PDF file", type="pdf")

if uploaded_file is not None:
    pdf_bytes = uploaded_file.read()
    pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")

    # Extract hidden Unicode text
    extracted_hidden_text = extract_hidden_unicode_text(pdf_document)
    cleaned_text = decode_unicode_text(extracted_hidden_text)

    # Check for 1999 in extracted text
    found_1999 = check_for_1999(cleaned_text)

    # Extract hidden hex data
    hex_data = extract_hex_data(cleaned_text)
    decoded_hex_text = hex_to_text(hex_data)

    # Extract extra bytes after EOF
    extra_bytes = extract_extra_bytes(pdf_bytes)

    # Extract compressed object streams
    compressed_objects = extract_compressed_objects(pdf_document)

    # Detect mixed Unicode encodings
    mixed_unicode_results = detect_mixed_unicode(cleaned_text)

    # Extract metadata and detect suspicious fields
    metadata = extract_pdf_metadata(pdf_document)
    suspicious_metadata = detect_suspicious_metadata(metadata)

    # Display extracted text
    word_count = len(cleaned_text.split())
    st.subheader("📄 Extracted Hidden Unicode Text")
    st.write(f"**Word Count:** {word_count}")
    st.text_area("Extracted Text", cleaned_text, height=300)
    
    # Display 1999 detection results
    st.subheader("🔎 Check for 1999 in Extracted Text")
    st.write(found_1999)

    # Show extracted hex data
    st.subheader("🔎 Extracted Hidden Hex Data")
    st.text_area("Hex Data", hex_data, height=150)
    
    # Show decoded hex text
    st.subheader("🔎 Decoded Hex Data (Converted Back to Text)")
    st.text_area("Decoded Hex Text", decoded_hex_text, height=150)
    
    # Show extra bytes after EOF
    st.subheader("🔎 Extra Bytes After EOF")
    st.text_area("Extra EOF Data", extra_bytes, height=150)
    
    # Show extracted compressed object streams
    st.subheader("🔎 Compressed Object Streams")
    st.text_area("Compressed Objects", str(compressed_objects), height=150)
    
    # Show mixed Unicode detection results
    st.subheader("🔎 Mixed Unicode Encoding Detection")
    st.text_area("Mixed Unicode", str(mixed_unicode_results), height=150)
    
    # Show metadata and suspicious fields
    st.subheader("📑 PDF Metadata")
    st.json(metadata)
    
    st.subheader("🚨 Suspicious Metadata Fields (Including Hidden URLs)")
    st.json(suspicious_metadata)
    
    # Provide a download option for extracted text
    st.download_button(
        label="📥 Download Extracted Text",
        data=cleaned_text,
        file_name="extracted_text.txt",
        mime="text/plain"
    )
