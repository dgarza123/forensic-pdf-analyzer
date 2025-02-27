import fitz  # PyMuPDF
import streamlit as st
from google.cloud import translate_v2 as translate
import os
import json

# Load Google Cloud credentials from Streamlit secrets
if "GOOGLE_APPLICATION_CREDENTIALS" in st.secrets:
    credentials_json = st.secrets["GOOGLE_APPLICATION_CREDENTIALS"]

    # Save the credentials to a temporary file
    temp_credentials_path = "/tmp/gcp_credentials.json"
    with open(temp_credentials_path, "w") as f:
        json.dump(credentials_json, f)

    # Set the environment variable to use the temporary credentials file
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = temp_credentials_path

# Initialize Google Translate Client
translate_client = translate.Client()

# Function to extract text from PDF
def extract_text_from_pdf(pdf_document):
    extracted_text = ""
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        extracted_text += page.get_text()
    return extracted_text

# Function to translate text using Google Cloud Translation API
def translate_text(text, target_lang='en'):
    if not text.strip():
        return "No text found to translate."

    try:
        result = translate_client.translate(text, target_language=target_lang)
        return result['translatedText']
    except Exception as e:
        st.error(f"Translation failed: {str(e)}")
        return None

# Function to detect JavaScript in the PDF (security check)
def detect_javascript_in_pdf(pdf_document):
    js_keywords = ["/JavaScript", "/JS", "/Action", "/OpenAction"]

    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)

        # Check annotations for JavaScript actions
        for annot in page.annots():
            if annot.type[0] == 15:  # Rich Media annotation (potential JavaScript)
                return True

        # Scan page text for JavaScript keywords
        raw_text = page.get_text("text")
        if any(keyword in raw_text for keyword in js_keywords):
            return True

    return False

# Function to check for embedded files (security check)
def detect_embedded_files(pdf_document):
    return pdf_document.embeddedFileNames()

# Streamlit UI
st.title("🔍 Forensic PDF Analyzer with Secure Google Translation")

uploaded_file = st.file_uploader("Upload a PDF file", type="pdf")

if uploaded_file is not None:
    pdf_document = fitz.open(stream=uploaded_file.read(), filetype="pdf")

    # Detect JavaScript security risks
    has_javascript = detect_javascript_in_pdf(pdf_document)
    if has_javascript:
        st.warning("🚨 Warning: This PDF contains JavaScript, which may pose security risks.")
    else:
        st.info("✅ No JavaScript detected in the PDF.")

    # Detect Embedded Files (potential security risk)
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

    # Translate text to English
    if st.button("Translate to English"):
        translated_text = translate_text(extracted_text)
        if translated_text:
            st.text_area("Translated Text", translated_text, height=300)
