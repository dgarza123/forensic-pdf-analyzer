import streamlit as st
import fitz  # PyMuPDF
import hashlib
import chardet  # Detects encoding

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
            if value and value.strip():
                st.write(f"**{key.capitalize()}:** {value}")
            else:
                st.write(f"**{key.capitalize()}:** Not Found")
    else:
        st.write("No metadata found.")

    # Extract XMP Metadata (Hidden Metadata)
    st.subheader("📂 XMP Metadata (Hidden)")
    try:
        xmp = doc.xref_get_key(1, "XMP")
        if xmp and xmp != ('null', 'null'):
            st.code(xmp, language="xml")
        else:
            st.write("No XMP metadata found.")
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

    # Extract and Display Text from the First Page with Encoding Detection
    st.subheader("📜 Extracted Text (First Page)")

    extracted_text = ""
    if doc.page_count > 0:
        first_page = doc[0]
        extracted_text = first_page.get_text("text").strip()

        # Detect encoding
        detected_encoding = chardet.detect(extracted_text.encode())['encoding']

        if detected_encoding and detected_encoding.lower() not in ["ascii", "utf-8"]:
            try:
                extracted_text = extracted_text.encode().decode(detected_encoding, errors="ignore")
            except:
                extracted_text = "Error decoding text."

        st.text_area("Extracted Text", extracted_text if extracted_text else "No visible text found.", height=200)
        st.write(f"🔎 **Detected Encoding:** {detected_encoding if detected_encoding else 'Unknown'}")
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
    annot_count = sum(1 for page in doc for annot in (page.annots() or []))
    st.write(f"📝 **Annotations Found:** {annot_count}")

    # Check for Embedded Files
    embedded_files = doc.embfile_names()
    if embedded_files:
        st.write("📎 **Embedded Files Found:**")
        for file in embedded_files:
            st.write(f"📂 {file}")
    else:
        st.write("✅ No embedded files detected.")
