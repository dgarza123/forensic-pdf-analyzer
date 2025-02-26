import streamlit as st
import fitz  # PyMuPDF
import hashlib
import chardet  # Detects encoding
import numpy as np
from scipy.stats import chisquare  # Chi-Square test for anomalies
from distorm3 import Decode, Decode32Bits  # diStorm64 for binary analysis

st.title("🔍 Forensic PDF Analyzer - ABCpdf, WCI & Ghostscript Focus")

# Limit file size to 4MB
MAX_FILE_SIZE = 4 * 1024 * 1024  # 4MB

# Upload PDF file
uploaded_file = st.file_uploader("Upload a PDF file (Max: 4MB)", type=["pdf"])

if uploaded_file is not None:
    if len(uploaded_file.getvalue()) > MAX_FILE_SIZE:
        st.error("🚨 File too large! Please upload a PDF smaller than 4MB.")
    else:
        st.subheader("📄 File Details")
        pdf_bytes = uploaded_file.read()
        st.write(f"**Filename:** {uploaded_file.name}")
        st.write(f"**File Size:** {len(pdf_bytes)} bytes")
        file_hash = hashlib.sha256(pdf_bytes).hexdigest()
        st.write(f"**SHA-256 Hash:** `{file_hash}`")

        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        
        # Extract Metadata
        st.subheader("📋 PDF Metadata")
        metadata = doc.metadata or {}
        for key, value in metadata.items():
            st.write(f"**{key.capitalize()}:** {value if value else 'Not Found'}")
        
        # Ghostscript Detection
        st.subheader("📂 Ghostscript Metadata Detection")
        ghostscript_markers = ["Ghostscript", "pdf_rbld", "pdf_sec"]
        detected_ghostscript = [key for key, value in metadata.items() if any(marker in str(value) for marker in ghostscript_markers)]
        if detected_ghostscript:
            st.warning("🚨 Ghostscript processing detected! This PDF may have been altered or rebuilt.")
            for entry in detected_ghostscript:
                st.write(f"🔍 Found: `{entry}`")
        else:
            st.success("✅ No Ghostscript metadata found.")
        
        # Extract OpenAction JavaScript
        st.subheader("⚠️ JavaScript & OpenAction Detection")
        if b'/OpenAction' in pdf_bytes:
            st.error("🚨 OpenAction found! Possible automated script execution.")
            openaction_content = pdf_bytes.split(b'/OpenAction')[1][:200]
            st.code(openaction_content, language="plaintext")
        else:
            st.success("✅ No OpenAction detected.")
        
        # EOF Pattern Matching
        st.subheader("📌 EOF (End of File) Check")
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
        
        # diStorm64 Binary Analysis (1024 bytes)
        st.subheader("🔍 Binary Code Analysis with diStorm64")
        disassembled_code = Decode(0, pdf_bytes[:1024], Decode32Bits)
        found_suspicious_code = False
        for offset, size, instruction, hexdump in disassembled_code:
            if "CALL" in instruction or "JMP" in instruction or "PUSH" in instruction:
                st.error(f"🚨 Suspicious binary operation: {instruction} at offset {offset}")
                found_suspicious_code = True
        if not found_suspicious_code:
            st.success("✅ No suspicious binary operations detected.")
