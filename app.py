import fitz  # PyMuPDF
import streamlit as st
import requests
from google.cloud import translate_v2 as translate
import os
import re

# Set up Google Cloud Translation API key
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "path/to/your/google-credentials.json"

# Initialize Google Translate Client
translate_client = translate.Client()

# Function to extract text from a PDF
def extract_text_from_pdf(pdf_document):
    extracted_text = ""
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        extracted_text += page.get_text()
    return extracted_text

# Function to translate text using Google Translate API
def translate_text(text, target_lang='en'):
    if not text.strip():
        return "No text found to translate."

    try:
        result = translate_client.translate(text, target_language=target_lang)
        return result['translatedText']
    except Exception as e:
        st.error(f"Translation failed: {str(e)}")
        return None

# Function to check if a PDF contains JavaScript (better alternative to get_js)
def detect_javascript_in_pdf(pdf_document):
    js_keywords = ["/JavaScript", "/JS", "/Action", "/OpenAction"]

    # Scan the entire document for JavaScript references
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)

        # Check for JavaScript annotations
        for annot in page.annots():
            if annot.type[0] == 15:  # 'Rich Media' annotation
                return True

        # Scan page text for potential JavaScript
        raw_text = page.get_text("text")
        if any(keyword in raw_text for keyword in js_keywords):
            return True

    return False

# Function to check for embedded files
def detect_embedded_files(pdf_document):
    return pdf_document.embeddedFileNames()

# Streamlit App UI
st.title("🔍 Forensic PDF Analyzer")

uploaded_file = st.file_uploader("Upload a PDF file", type="pdf")

if uploaded_file is not None:
    pdf_document = fitz.open(stream=uploaded_file.read(), filetype="pdf")

    # Detect JavaScript
    has_javascript = detect_javascript_in_pdf(pdf_document)
    if has_javascript:
        st.warning("🚨 Warning: This PDF contains JavaScript, which may pose security risks.")
    else:
        st.info("✅ No JavaScript detected in the PDF.")

    # Detect Embedded Files
    embedded_files = detect_embedded_files(pdf_document)
    if embedded_files:
        st.warning("🚨 Warning: This PDF contains embedded files:")
        for file in embedded_files:
            st.write(f"- {file}")
    else:
        st.info("✅ No embedded files detected in the PDF.")

    # Extract and display text
    extracted_text = extract_text_from_pdf(pdf_document)
    st.text_area("Extracted Text", extracted_text, height=300)

    # Translate text
    if st.button("Translate to English"):
        translated_text = translate_text(extracted_text)
        if translated_text:
            st.text_area("Translated Text", translated_text, height=300)
