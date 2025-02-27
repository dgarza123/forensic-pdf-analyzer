import fitz  # PyMuPDF
import pdfplumber
import streamlit as st
import unicodedata
import chardet
import pytesseract
import io
from deep_translator import GoogleTranslator
from PIL import Image

# Function to extract text using PyMuPDF
def extract_text_pymupdf(pdf_document):
    extracted_text = []
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        text = page.get_text("text")
        if text.strip():
            extracted_text.append(text)
    return "\n\n".join(extracted_text) if extracted_text else None

# Function to extract text using PDFPlumber (fallback)
def extract_text_pdfplumber(pdf_bytes):
    extracted_text = []
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                extracted_text.append(text)
    return "\n\n".join(extracted_text) if extracted_text else None

# Function to apply OCR (without pdf2image)
def extract_text_ocr(pdf_bytes):
    extracted_text = []
    pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
    
    for page in pdf_document:
        pix = page.get_pixmap()  # Convert page to an image
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        text = pytesseract.image_to_string(img)

        # 🚨 Remove common unwanted words like "Preview"
        filtered_text = "\n".join(
            line for line in text.split("\n") if "preview" not in line.lower()
        )

        if filtered_text.strip():
            extracted_text.append(filtered_text)
    
    return "\n\n".join(extracted_text) if extracted_text else None

# Function to fix Unicode issues
def fix_unicode_text(text):
    if not text:
        return ""
    normalized_text = unicodedata.normalize("NFKC", text)
    detected_encoding = chardet.detect(text.encode())["encoding"]
    try:
        return text.encode("latin1").decode(detected_encoding) if detected_encoding else normalized_text
    except:
        return normalized_text

# Function to translate text (uses GoogleTranslator without API key)
def translate_text(text, target_lang="en"):
    if not text.strip():
        return "⚠️ No text to translate."
    try:
        return GoogleTranslator(source="auto", target=target_lang).translate(text)
    except Exception as e:
        return f"Translation failed: {str(e)}"

# Streamlit UI
st.title("🔍 Forensic PDF Text Extractor & Translator")

uploaded_file = st.file_uploader("Upload a PDF file", type="pdf")

if uploaded_file is not None:
    pdf_bytes = uploaded_file.read()
    pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")

    # Extract text from hidden text layers before OCR
    extracted_text = extract_text_pymupdf(pdf_document)

    # If the extracted text only says "Preview," check for hidden text
    if extracted_text and extracted_text.strip().lower() in ["preview", "preview preview"]:
        extracted_text = "\n".join(
            page.get_text("text") for page in pdf_document if page.get_text("text").strip()
        )

    # If PyMuPDF fails, try PDFPlumber
    if not extracted_text:
        extracted_text = extract_text_pdfplumber(pdf_bytes)

    # If extracted text is missing or just says "Preview," apply OCR
    if not extracted_text or extracted_text.strip().lower() in ["preview", "preview preview"]:
        extracted_text = extract_text_ocr(pdf_bytes)

    # Fix Unicode issues in extracted text
    cleaned_text = fix_unicode_text(extracted_text)

    # Show extracted text
    word_count = len(cleaned_text.split())
    st.subheader("📄 Extracted Text")
    st.write(f"**Word Count:** {word_count}")
    st.text_area("Extracted Text", cleaned_text, height=300)

    # Translate text to English
    if st.button("Translate to English"):
        translated_text = translate_text(cleaned_text)
        st.subheader("🌍 Translated Text (English)")
        st.text_area("Translated Text", translated_text, height=300)

    # Provide a download option for extracted text
    st.download_button(
        label="📥 Download Extracted Text",
        data=cleaned_text,
        file_name="extracted_text.txt",
        mime="text/plain"
    )
