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
    return
