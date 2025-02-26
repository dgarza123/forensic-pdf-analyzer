import streamlit as st
import fitz  # PyMuPDF
import hashlib
import chardet  # Detects encoding
import numpy as np
from scipy.stats import chisquare  # Chi-Square test for anomalies
from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits  # diStorm64 for binary analysis

st.title("🔍 Forensic PDF Analyzer - ABCpdf & WCI Focus")

# Upload PDF file
uploaded_file = st.file_uploader("Upload a PDF file", type=["pdf"])

if uploaded_file is not None:
    st.subheader("📄 File Details")
    
    # Read the PDF
    pdf_bytes = uploaded_file.read()
    
    # Display basic info
    st.write(f"**Filename:** {uploaded_file.name}")
    st.write(f"**File Size:** {len(pdf_bytes)} bytes")

    # Generate SHA-256 hash
    file_hash = hashlib.sha256(pdf_bytes).hexdigest()
    st.write(f"**SHA-256 Hash:** `{file_hash}`")

    # Open the PDF with PyMuPDF
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    # Extract Standard Metadata
    st.subheader("📋 PDF Metadata")
    metadata = doc.metadata
    metadata_empty = True  

    if metadata:
        for key, value in metadata.items():
            if value and value.strip():
                metadata_empty = False
                st.write(f"**{key.capitalize()}:** {value}")
            else:
                st.write(f"**{key.capitalize()}:** Not Found")

    if metadata_empty:
        st.error("⚠️ No metadata detected! This could indicate metadata stripping, redaction, or forgery.")

    # ABCpdf & WCI Metadata Detection
    st.subheader("📂 ABCpdf & WCI Metadata Detection")

    abc_metadata_keys = ["ABCpdf", "WebSupergoo", "BFO", "West Central Indexing", "WCI"]
    detected_abc_metadata = []

    for key, value in metadata.items():
        if any(marker in str(value) for marker in abc_metadata_keys):
            detected_abc_metadata.append(f"**{key}:** {value}")

    if detected_abc_metadata:
        st.warning("🚨 **ABCpdf or West Central Indexing metadata detected!**")
        for entry in detected_abc_metadata:
            st.write(entry)
    else:
        st.success("✅ No ABCpdf or WCI metadata found.")

    # Extract Object References
    st.subheader("🔎 ABCpdf & WCI Object References")

    abc_object_patterns = [b'/EmbeddedFileStreamElement', b'/Names', b'/JavaScript', b'/OpenAction', b'/FormFieldElement']
    abc_objects_found = []

    for obj in abc_object_patterns:
        if obj in pdf_bytes:
            abc_objects_found.append(obj.decode(errors="ignore"))

    if abc_objects_found:
        st.error("🚨 **Suspicious ABCpdf object references found!** These could indicate hidden embedded files or automated script actions.")
        for obj in abc_objects_found:
            st.write(f"🔍 Found: `{obj}`")
    else:
        st.success("✅ No ABCpdf object references detected.")

    # JavaScript & OpenAction Detection
    st.subheader("⚠️ JavaScript & OpenAction Detection")

    js_like_patterns = [b'/JavaScript', b'/JS', b'/OpenAction']
    js_found = False

    for pattern in js_like_patterns:
        if pattern in pdf_bytes:
            js_found = True
            st.warning(f"🚨 JavaScript/OpenAction reference found: `{pattern.decode(errors='ignore')}`")

    if not js_found:
        st.success("✅ No suspicious JavaScript or OpenAction elements detected.")

    # Encoding Per Page Analysis
    st.subheader("📜 Encoding Analysis Per Page")
    encoding_map = {}

    for i, page in enumerate(doc):
        text = page.get_text("text")
        encoding_result = chardet.detect(text.encode())
        detected_encoding = encoding_result['encoding']

        if detected_encoding:
            encoding_map[f"Page {i+1}"] = detected_encoding

    for page, enc in encoding_map.items():
        st.write(f"**{page}:** {enc}")

    if len(set(encoding_map.values())) > 1:
        st.error("🚨 Multiple encodings detected across pages! Possible manipulation or hidden data.")

    # Display the number of pages
    st.write(f"**Total Pages:** {doc.page_count}")

    # Hidden Object Detection
    st.subheader("🕵️ Hidden Elements Detection")

    image_count = sum(1 for page in doc for img in page.get_images(full=True))
    st.write(f"🔍 **Images Found:** {image_count}")

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

    # EOF Analysis
    st.subheader("📌 **EOF (End of File) Check**")

    pdf_eof_index = pdf_bytes.rfind(b'%%EOF')
    if pdf_eof_index == -1:
        st.error("🚨 No EOF marker found! This could indicate file corruption or tampering.")
    else:
        extra_data = pdf_bytes[pdf_eof_index + 5:]
        extra_data_size = len(extra_data)

        st.write(f"📏 **Bytes After EOF:** {extra_data_size}")

        if extra_data_size > 0:
            st.error(f"🚨 **Suspicious extra data found ({extra_data_size} bytes) after EOF!** Possible steganography or hidden content.")
            st.code(extra_data.hex(), language="plaintext")

    # diStorm64 Binary Analysis
    st.subheader("🔍 Binary Code Analysis with diStorm64")
    
    disassembled_code = Decode(0, pdf_bytes[:512], Decode32Bits)
    found_suspicious_code = False

    for offset, size, instruction, hexdump in disassembled_code:
        if "CALL" in instruction or "JMP" in instruction or "PUSH" in instruction:
            st.error(f"🚨 Suspicious binary operation: {instruction} at offset {offset}")
            found_suspicious_code = True

    if not found_suspicious_code:
        st.success("✅ No suspicious binary operations detected.")
