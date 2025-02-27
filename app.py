import streamlit as st
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
#       FUNCTIONS        #
##########################

def compute_sha256(file_bytes):
    """Compute the SHA-256 hash of the uploaded file."""
    return hashlib.sha256(file_bytes).hexdigest()

def extract_metadata(doc):
    """
    Extract PDF metadata and identify the PDF version.
    Tries doc.pdf_version first (if available), else falls back to doc.metadata.
    """
    # Safely attempt to get doc.pdf_version
    pdf_version = getattr(doc, "pdf_version", None)
    if pdf_version is not None and pdf_version != 0:
        # Convert float to string (e.g., 1.4 -> "1.4")
        pdf_version_str = f"{pdf_version:.1f}"
    else:
        # Fallback to metadata
        meta_format = (doc.metadata or {}).get("format", "Unknown")
        pdf_version_str = meta_format.upper().replace("PDF ", "").strip()

    # Mapping known PDF versions to their release years
    version_years = {
        "1.4": 2001,
        "1.5": 2003,
        "1.6": 2004,
        "1.7": 2006
    }

    # Determine release year
    release_year = version_years.get(pdf_version_str, "Unknown")

    # Mark as severely outdat
