import fitz  # PyMuPDF
import pdfplumber
import streamlit as st
import unicodedata
import chardet
import pytesseract
import io
from deep_translator import GoogleTranslator
from PIL import Image

# Function to extract hidden Unicode text
def extract_hidden_unicode_text(pdf_document):
    hidden_text = []
    for page in pdf_document:
        raw_text = page.get_text("raw")  # Extracts hidden Unicode text
        if raw_text.strip():
            hidden_text.append(raw_text)
    return "\n\n".join(hidden_text) if hidden_text else None

# Function to fix Unicode issues
def decode_unicode_text(text):
    detected_encoding = chardet.detect(text.encode())["encoding"]
    try:
        return text.encode("latin1").decode(detected_encoding) if detected_encoding else text
    except:
        return unicodedata.normalize("NFKC", text)  # Normalize weird Unicode characters

# Function to extract metadata
def extract_pdf_metadata(pdf_document):
    metadata = pdf_document.metadata
    id_values = pdf_document.xref_get_key(1, "ID")  # Extracts unique PDF document ID
    return {
        "Title": metadata.get("title", ""),
        "Author": metadata.get("author", ""),
        "Producer": metadata.get("producer", ""),
        "CreationDate": metadata.get("creationDate", ""),
        "ModDate": metadata.get("modDate", ""),
        "DocumentID": id_values
    }

# Function to detect suspicious PDF generators
def detect_suspicious_pdf_generator(pdf_document):
    producer = pdf_document.metadata.get("producer", "").lower()
    
    if "abcpdf" in producer:
        return "⚠️ ABCpdf detected—Possible fraudulent modification!"
    elif "big faceless" in producer or "bfo" in producer:
        return "⚠️ BFO PDF Library detected—Check for hidden text!"
    elif "itext" in producer and "2.17" in producer:
        return "⚠️ iText 2.17 detected—Known forgery tool!"
    elif "wci" in producer:
        return "⚠️ WCI (West Central Indexing) detected—Check metadata manipulation!"
    elif "chromium" in producer:
        return "⚠️ Chromium-generated PDF detected—Possible screenshot-based forgery!"
    elif "libtiff" in producer or "tiff2pdf" in producer:
        return "⚠️ TIFF-to-PDF Conversion Detected—Possible attempt to hide original text!"
    elif "pic" in producer:
        return "⚠️ PIC-generated PDF detected—Check for suspicious patterns!"
    return "✅ No suspicious PDF software detected."

# Streamlit UI
st.title("🔍 Forensic PDF Analyzer & Unicode Detector")

uploaded_file = st.file_uploader("Upload a PDF file", type="pdf")

if uploaded_file is not None:
    pdf_bytes = uploaded_file.read()
    pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")

    # Extract hidden Unicode text
    extracted_hidden_text = extract_hidden_unicode_text(pdf_document)
    cleaned_text = decode_unicode_text(extracted_hidden_text)

    # Extract metadata and detect suspicious PDF software
    metadata = extract_pdf_metadata(pdf_document)
    suspicious_pdf_alert = detect_suspicious_pdf_generator(pdf_document)

    # Display extracted text
    word_count = len(cleaned_text.split())
    st.subheader("📄 Extracted Hidden Unicode Text")
    st.write(f"**Word Count:** {word_count}")
    st.text_area("Extracted Text", cleaned_text, height=300)

    # Show metadata
    st.subheader("📑 PDF Metadata")
    st.json(metadata)
    
    # Show fraud detection results
    st.subheader("🚨 Suspicious PDF Generator Check")
    st.write(suspicious_pdf_alert)
    
    # Provide a download option for extracted text
    st.download_button(
        label="📥 Download Extracted Text",
        data=cleaned_text,
        file_name="extracted_text.txt",
        mime="text/plain"
    )
