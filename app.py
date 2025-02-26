import streamlit as st
import fitz  # PyMuPDF
import hashlib
import chardet  # Detects encoding
import numpy as np
from scipy.stats import chisquare

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
    metadata_empty = True  # Track if all metadata fields are missing

    if metadata:
        for key, value in metadata.items():
            if value and value.strip():
                metadata_empty = False
                st.write(f"**{key.capitalize()}:** {value}")
            else:
                st.write(f"**{key.capitalize()}:** Not Found")

    if metadata_empty:
        st.error("⚠️ No metadata detected! This could indicate metadata stripping, redaction, or forgery.")

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

    # Extract and Display Text from the First Page with 16-Bit Encoding Detection
    st.subheader("📜 Extracted Text (First Page)")

    extracted_text = ""
    detected_encoding = "Unknown"

    if doc.page_count > 0:
        first_page = doc[0]
        extracted_text = first_page.get_text("text").strip()

        # Detect encoding
        encoding_result = chardet.detect(extracted_text.encode())
        detected_encoding = encoding_result['encoding']

        # Attempt to decode non-standard encodings
        if detected_encoding and detected_encoding.lower() in ["utf-16", "utf-16le", "utf-16be"]:
            try:
                extracted_text = extracted_text.encode().decode(detected_encoding, errors="ignore")
            except:
                extracted_text = "Error decoding 16-bit text."

        # If extracted text is empty, warn the user
        if not extracted_text.strip():
            st.warning("⚠️ No readable text found on the first page. This could indicate hidden or image-based text.")

        # Check if the page contains images (possible image-based text)
        images_on_first_page = len(first_page.get_images(full=True))
        if images_on_first_page > 0 and not extracted_text.strip():
            st.error("🚨 This page contains images but no text! The document might use image-based text, requiring OCR.")

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

    # Steganography Detection: Chi-Square Analysis & EOF Data
    st.subheader("🔍 Steganography Analysis")

    # Chi-Square Test for Byte Distribution
    st.write("📊 **Chi-Square Analysis** (Detects unusual byte distributions)")
    
    byte_freq = np.zeros(256, dtype=int)
    for byte in pdf_bytes:
        byte_freq[byte] += 1

    expected_freq = np.full(256, len(pdf_bytes) / 256)  # Expected uniform distribution
    chi_stat, p_value = chisquare(byte_freq, expected_freq)

    st.write(f"📉 **Chi-Square Statistic:** {chi_stat:.2f}")
    st.write(f"📊 **P-Value:** {p_value:.6f}")

    if p_value < 0.01:
        st.error("🚨 **Possible anomaly detected!** Byte distribution is unusual—potential hidden data.")
    else:
        st.success("✅ No significant anomalies detected in byte distribution.")

    # EOF Analysis: Detect Unexpected Extra Data
    st.write("📌 **EOF (End of File) Check** (Detects hidden data at the end of PDFs)")
    
    pdf_eof_index = pdf_bytes.rfind(b'%%EOF')
    if pdf_eof_index == -1:
        st.error("🚨 No EOF marker found! This could indicate file corruption or tampering.")
    else:
        extra_data = len(pdf_bytes) - (pdf_eof_index + 5)
        st.write(f"📏 **Bytes After EOF:** {extra_data}")

        if extra_data > 0:
            st.error(f"🚨 **Suspicious extra data found ({extra_data} bytes) after EOF!** Possible steganography or hidden content.")
        else:
            st.success("✅ No extra data detected after EOF.")
