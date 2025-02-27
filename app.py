import streamlit as st
import subprocess
import fitz  # PyMuPDF
import hashlib
import re
import requests
import pdfplumber
import pytesseract
from pdfminer.high_level import extract_text
from io import BytesIO
import unicodedata
from bidi.algorithm import get_display
from PIL import Image

##########################
#   Helper Functions     #
##########################

def get_git_commit():
    """Return the current git commit hash (short version) or 'unknown' if unavailable."""
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"]).strip().decode("utf-8")
        return commit
    except Exception:
        return "unknown"

def compute_sha256(file_bytes):
    """Compute the SHA-256 hash of the uploaded file."""
    return hashlib.sha256(file_bytes).hexdigest()

def extract_metadata(doc, file_bytes):
    """
    Extract PDF metadata and identify the PDF version.
    Attempts to use:
      1. doc.pdf_version (if available),
      2. The file header from file_bytes,
      3. Finally, falls back to doc.metadata.
    If creation or modification dates are missing, displays a note.
    """
    # Attempt to get doc.pdf_version if it exists
    pdf_version = getattr(doc, "pdf_version", None)
    if pdf_version is not None and pdf_version != 0:
        pdf_version_str = f"{pdf_version:.1f}"
    else:
        # Fallback: read the header from file_bytes (e.g., "%PDF-1.4")
        try:
            header = file_bytes[:20].decode("latin1", errors="replace")
            m = re.search(r"%PDF-(\d\.\d)", header)
            if m:
                pdf_version_str = m.group(1)
            else:
                # Final fallback: try to use metadata field "format"
                meta_format = (doc.metadata or {}).get("format", "Unknown")
                pdf_version_str = meta_format.upper().replace("PDF ", "").strip()
        except Exception:
            pdf_version_str = "Unknown"

    # Mapping known PDF versions to their release years
    version_years = {
        "1.4": 2001,
        "1.5": 2003,
        "1.6": 2004,
        "1.7": 2006
    }
    release_year = version_years.get(pdf_version_str, "Unknown")

    # Mark as severely outdated if known release year is less than 2007
    if release_year != "Unknown" and release_year < 2007:
        version_status = "❌ Severely Outdated"
    else:
        version_status = "✅ Good"

    # Simple encryption check
    if "encryption" in (doc.metadata or {}):
        encryption_status = "❌ Content is encrypted, but signatures are missing"
    else:
        encryption_status = "✅ No Encryption"

    compliance_status = "❌ Not PDF/A Compliant"
    metadata_dict = doc.metadata or {}
    
    # Check for creation and modification dates; if missing, note they were sanitized.
    creation_date = metadata_dict.get("creationDate", "Unknown")
    if creation_date == "Unknown":
        creation_date = "Sanitized by PDF source"
    modification_date = metadata_dict.get("modDate", "Unknown")
    if modification_date == "Unknown":
        modification_date = "Sanitized by PDF source"

    format_str = f"PDF {pdf_version_str} (released {release_year}) {version_status}"

    return {
        "Format": format_str,
        "Encryption": encry
