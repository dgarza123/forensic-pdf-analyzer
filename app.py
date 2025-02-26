import streamlit as st
import fitz  # PyMuPDF
import hashlib

st.title("🔍 Forensic PDF Analyzer")

# Upload PDF file
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

    # Extract Standard Metadata
    st.subheader("📋 PDF Metadata")
    metadata = doc.metadata
    if metadata:
        for key, value in metadata.items():
            st.write(f"**{key.capitalize()}:** {value if value else 'Not Available'}")
    else:
        st.write("No metadata found.")

    # Extract XMP Metadata (Hidden Metadata)
    try:
        xmp = doc.xref_get_key(1, "XMP")
        if xmp:
            st.subheader("📂 XMP Metadata (Hidden)")
            st.code(xmp, language="xml")
    except:
        st.write("No XMP metadata found.")

    # Check for JavaScript in the PDF
    st.subheader("⚠️ Advanced JavaScript Detection")
    js_found = False
    for page_num, page in enumerate(doc):
        js_text = page.get_text("text")
        if "JavaScript" in js_text or "/JS" in js_text:
            js_found = True
            st.warning(f"🚨 JavaScript detected on **Page {page_num + 1}**!")
            st.code(js_text, language="javascript")

    if not js_found:
        st.success("✅ No JavaScript found in this PDF.")

    # Extract and Display Text from the First Page
    st.subheader("📜 Extracted Text (First Page)")
    if doc.page_count > 0:
        first_page = doc[0]
        extracted_text = first_page.get_text("text").strip()
        st.text_area("Extracted Text", extracted_text if extracted_text else "No visible text found.", height=200)
    else:
        st.warning("No pages found in this document.")

    # Display the number of pages
    st.write(f"**Total Pages:** {doc.page_count}")

    # Hidden Object Detection
    st.subheader("🕵️ Hidden Elements Detection")

    # Count Images
    image_count = sum(1 for page in doc for img in page.get_images(full=True))
    st.write(f"🔍 **Images Found:** {image_count}")

    # Count Annotations (Comments, Edits)
    annot_count = sum(1 for page in doc for annot in page.annots() or [])
    st.write(f"📝 **Annotations Found:** {annot_count}")

    # Check for Embedded Files
    embedded_files = doc.embfile_names()
    if embedded_files:
        st.write("📎 **Embedded Files Found:**")
        for file in embedded_files:
            st.write(f"📂 {file}")
    else:
        st.write("✅ No embedded files detected.")
