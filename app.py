import fitz  # PyMuPDF
import streamlit as st

# Function to extract text from PDF
def extract_text_from_pdf(pdf_document):
    extracted_text = ""
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        extracted_text += page.get_text()
    return extracted_text

# Function to detect JavaScript in the PDF (security check)
def detect_javascript_in_pdf(pdf_document):
    js_keywords = ["/JavaScript", "/JS", "/Action", "/OpenAction"]

    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)

        # Check annotations for JavaScript actions
        for annot in page.annots():
            if annot and annot.type[0] == 15:  # Rich Media annotation (potential JavaScript)
                return True

        # Scan page text for JavaScript keywords
        raw_text = page.get_text("text")
        if any(keyword in raw_text for keyword in js_keywords):
            return True

    return False

# Function to check for embedded files (security check)
def detect_embedded_files(pdf_document):
    embedded_files = []
    
    # Check if there are embedded files
    if pdf_document.embfile_count > 0:
        for i in range(int(pdf_document.embfile_count)):  # Ensure it's an integer
            info = pdf_document.embfile_info(i)
            embedded_files.append(info["filename"])

    return embedded_files

# Streamlit UI
st.title("🔍 Forensic PDF Analyzer")

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
