import fitz  # PyMuPDF
import streamlit as st
import requests
import os

# Function to extract text from PDF
def extract_text_from_pdf(pdf_document):
    extracted_text = ""
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        extracted_text += page.get_text()
    return extracted_text

# Function to translate text using DeepL API
def translate_text(text, target_lang='EN'):
    api_key = os.getenv('DEEPL_API_KEY')  # Ensure your API key is set as an environment variable
    if not api_key:
        st.error("DeepL API key not found. Please set the DEEPL_API_KEY environment variable.")
        return None

    response = requests.post(
        'https://api-free.deepl.com/v2/translate',
        data={
            'auth_key': api_key,
            'text': text,
            'target_lang': target_lang
        }
    )

    if response.status_code == 200:
        return response.json()['translations'][0]['text']
    else:
        st.error(f"Translation failed: {response.status_code} - {response.text}")
        return None

# Streamlit app
st.title("Forensic Analyzer App")

uploaded_file = st.file_uploader("Upload a PDF file", type="pdf")
if uploaded_file is not None:
    pdf_document = fitz.open(stream=uploaded_file.read(), filetype="pdf")

    # Check for JavaScript
    has_javascript = any(page.get_js() for page in pdf_document)
    if has_javascript:
        st.warning("Warning: This PDF contains JavaScript, which may pose security risks.")
    else:
        st.info("No JavaScript detected in the PDF.")

    # Check for embedded files
    embedded_files = pdf_document.embeddedFileNames()
    if embedded_files:
        st.warning("Warning: This PDF contains embedded files:")
        for file in embedded_files:
            st.write(f"- {file}")
    else:
        st.info("No embedded files detected in the PDF.")

    # Check for actions in annotations
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        for annot in page.annots():
            if annot.action:
                st.warning(f"Action detected on page {page_num + 1}: {annot.action}")

    # Extract text
    extracted_text = extract_text_from_pdf(pdf_document)
    st.text_area("Extracted Text", extracted_text, height=300)

    # Translate text
    if st.button("Translate to English"):
        translated_text = translate_text(extracted_text)
        if translated_text:
            st.text_area("Translated Text", translated_text, height=300)
