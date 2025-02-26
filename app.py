import streamlit as st
import fitz  # PyMuPDF
import hashlib

st.title("🔍 Forensic PDF Analyzer")

uploaded_file = st.file_uploader("Upload a PDF file", type=["pdf"])

if uploaded_file is not None:
    st.subheader("📄 File Details")
    
    # Read the PDF
    pdf_bytes = uploaded_file.read()
    
    # Display basic info
    st.write(f"**Filename:** {uploaded_file.name}")
    st.write(f"**File Size:** {len(pdf_bytes)} bytes")

    # Generate SHA-256 hash (helps detect silent modifications)
    file_hash = hashlib.sha256(pdf_bytes).hexdigest()
    st.write(f"**SHA-256 Hash:** `{file_hash}`")

    # Open the PDF with PyMuPDF
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    # Extract Metadata
    metadata = doc.metadata
    st.subheader("📋 PDF Metadata")
    if metadata:
        for key, value in metadata.items():
            st.write(f"**{key}:** {value}")
    else:
        st.write("No metadata found.")

    # Check for JavaScript in the PDF
    st.subheader("⚠️ JavaScript Detection")
    js_scripts = [page.get_text("text") for page in doc if "JavaScript" in page.get_text("text")]
    if js_scripts:
        st.warning("🚨 JavaScript detected in the document!")
        for script in js_scripts:
            st.code(script, language="javascript")
    else:
        st.success("✅ No JavaScript found in this PDF.")

    # Extract and Display Text from the First Page
    st.subheader("📜 Extracted Text (First Page)")
    first_page_text = doc[0].get_text("text") if doc.page_count > 0 else "No text found."
    st.text_area("Extracted Text", first_page_text, height=200)

    # Display the number of pages
    st.write(f"**Total Pages:** {doc.page_count}")
