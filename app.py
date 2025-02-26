import streamlit as st
import fitz  # PyMuPDF
import hashlib
import chardet  # Detects encoding
import numpy as np
from scipy.stats import chisquare  # Chi-Square test for anomalies

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
    metadata_empty = True  
    metadata_generic = False  

    generic_terms = ["PIC", "Unknown", "Untitled", "Not Available", "N/A"]

    if metadata:
        for key, value in metadata.items():
            if value and value.strip():
                metadata_empty = False
                if value in generic_terms or len(value) < 3:  
                    metadata_generic = True
                st.write(f"**{key.capitalize()}:** {value}")
            else:
                st.write(f"**{key.capitalize()}:** Not Found")

    if metadata_empty:
        st.error("⚠️ No metadata detected! This could indicate metadata stripping, redaction, or forgery.")

    if metadata_generic:
        st.warning("⚠️ This metadata appears generic or possibly fake. Some fraudsters modify metadata to mask document origins.")

    # Deep Metadata Analysis - Searching for old metadata remnants
    st.subheader("📂 Deep Metadata Scan")
    hidden_metadata = [line for line in pdf_bytes.split(b'\n') if b'/' in line]
    if hidden_metadata:
        st.code(hidden_metadata[:10], language="plaintext")  # Show first 10 metadata entries
        st.warning("⚠️ Possible hidden metadata remnants detected.")
    else:
        st.success("✅ No hidden metadata remnants found.")

    # Extract XMP Metadata
    st.subheader("📂 XMP Metadata (Hidden)")
    try:
        xmp = doc.xref_get_key(1, "XMP")
        if xmp and xmp != ('null', 'null'):
            st.code(xmp, language="xml")
        else:
            st.write("No XMP metadata found.")
    except:
        st.write("No XMP metadata found.")

    # JavaScript Detection
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

    # Extract and Display Text from First Page with Encoding Detection
    st.subheader("📜 Extracted Text (First Page)")

    extracted_text = ""
    detected_encoding = "Unknown"
    mixed_encoding_flag = False

    if doc.page_count > 0:
        first_page = doc[0]
        extracted_text = first_page.get_text("text").strip()

        # Detect encoding
        encoding_result = chardet.detect(extracted_text.encode())
        detected_encoding = encoding_result['encoding']

        # Detect mixed encodings (basic check)
        if extracted_text and len(set(detected_encoding)) > 1:
            mixed_encoding_flag = True

        # Attempt to decode non-standard encodings
        if detected_encoding and detected_encoding.lower() in ["utf-16", "utf-16le", "utf-16be"]:
            try:
                extracted_text = extracted_text.encode().decode(detected_encoding, errors="ignore")
            except:
                extracted_text = "Error decoding 16-bit text."

        if not extracted_text.strip():
            st.warning("⚠️ No readable text found on the first page. This could indicate hidden or image-based text.")

        st.text_area("Extracted Text", extracted_text if extracted_text else "No visible text found.", height=200)
        st.write(f"🔎 **Detected Encoding:** {detected_encoding if detected_encoding else 'Unknown'}")

        if mixed_encoding_flag:
            st.error("🚨 Multiple encodings detected! This may indicate manipulation or hidden data.")

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

    # Steganography Detection: EOF Analysis
    st.subheader("📌 **EOF (End of File) Check** (Detects hidden data at the end of PDFs)")
    
    pdf_eof_index = pdf_bytes.rfind(b'%%EOF')
    if pdf_eof_index == -1:
        st.error("🚨 No EOF marker found! This could indicate file corruption or tampering.")
    else:
        extra_data = pdf_bytes[pdf_eof_index + 5:]  # Extract bytes after EOF
        extra_data_size = len(extra_data)

        st.write(f"📏 **Bytes After EOF:** {extra_data_size}")

        if extra_data_size > 0:
            st.error(f"🚨 **Suspicious extra data found ({extra_data_size} bytes) after EOF!** Possible steganography or hidden content.")
            st.code(extra_data.hex(), language="plaintext")  # Show hex of extra data
        else:
            st.success("✅ No extra data detected after EOF.")
