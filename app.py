import streamlit as st
import fitz  # PyMuPDF
import hashlib
import difflib
import os
import subprocess

# Set up Streamlit UI
st.set_page_config(page_title="Forensic PDF Analyzer", layout="wide")
st.title("📄 Forensic PDF Analyzer")
st.write("Upload a PDF to check for metadata anomalies, hidden JavaScript, version mismatches, and silent modifications.")

# Upload PDF file
uploaded_file = st.file_uploader("Upload a PDF", type=["pdf"])

def extract_metadata(pdf_file):
    """Extract metadata and detect suspicious producer strings."""
    doc = fitz.open(pdf_file)
    metadata = doc.metadata
    results = []

    # Check PDF version
    pdf_version = metadata.get("format", "Unknown")
    results.append(f"📄 Reported PDF Version: {pdf_version}")

    # Detect suspicious producers (West Central Indexing, ABCpdf, iText, Sysoft)
    producers = ["ABCpdf", "1T3XT", "iText", "West Central Indexing", "Sysoft", "WCI"]
    for key, value in metadata.items():
        if any(prod in str(value) for prod in producers):
            results.append(f"🚨 Suspicious Producer Detected: {value}")

    # Check for modification inconsistencies
    creation_date = metadata.get("creationDate", "Unknown")
    mod_date = metadata.get("modDate", "Unknown")
    if mod_date < creation_date:
        results.append("🚨 WARNING: Modification date is earlier than creation date – possible metadata manipulation!")

    return "\n".join(results)

def detect_hidden_javascript(pdf_path):
    """Use PDFiD to check for hidden JavaScript or embedded objects."""
    try:
        result = subprocess.run(["pdfid.py", pdf_path], capture_output=True, text=True)
        if "/JS" in result.stdout:
            return "🚨 Hidden JavaScript Detected!"
        return "✅ No JavaScript Found."
    except Exception as e:
        return f"⚠️ Error checking for JavaScript: {str(e)}"

def generate_hash(pdf_file):
    """Generate SHA-256 hash of the file to detect silent modifications."""
    hasher = hashlib.sha256()
    while chunk := pdf_file.read(4096):
        hasher.update(chunk)
    return hasher.hexdigest()

def compare_pdfs(pdf1, pdf2):
    """Compare the text content of two PDFs to detect changes."""
    def extract_text(pdf):
        doc = fitz.open(pdf)
        return "\n".join([page.get_text("text") for page in doc]).splitlines()

    text1, text2 = extract_text(pdf1), extract_text(pdf2)
    diff = list(difflib.unified_diff(text1, text2, lineterm=""))
    return "\n".join(diff) if diff else "✅ No differences detected."

if uploaded_file:
    # Save PDF temporarily
    pdf_path = f"temp_{uploaded_file.name}"
    with open(pdf_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # Run forensic checks
    st.subheader("📊 Forensic Analysis Results")
    st.text(extract_metadata(pdf_path))
    st.text(detect_hidden_javascript(pdf_path))
    st.text(f"🔍 File Hash: {generate_hash(uploaded_file)}")

    # Option to compare two PDFs
    st.subheader("🔎 Compare Two PDFs")
    uploaded_file2 = st.file_uploader("Upload another PDF to compare", type=["pdf"])
    if uploaded_file2:
        pdf_path2 = f"temp_{uploaded_file2.name}"
        with open(pdf_path2, "wb") as f:
            f.write(uploaded_file2.getbuffer())
        st.text(compare_pdfs(pdf_path, pdf_path2))

    # Clean up temporary files
    os.remove(pdf_path)
    if uploaded_file2:
        os.remove(pdf_path2)
