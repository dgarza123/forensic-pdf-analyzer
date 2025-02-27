def detect_16bit_encoded_text(file_bytes, display_limit=1000):
    """
    Attempt to detect hidden JavaScript or suspicious strings in various 16-bit encodings.
    This function decodes the file with multiple encodings and searches for suspicious patterns.
    It also converts the file to hex/binary for analysis, but displays only a truncated snippet
    to avoid slowing down the UI.
    """
    result = []

    # 1) Decode using several encodings
    encodings = ["utf-16", "utf-16le", "utf-16be", "utf-8"]
    for encoding in encodings:
        try:
            text = file_bytes.decode(encoding, errors="replace").strip()
            if text:
                normalized_text = get_display(unicodedata.normalize("NFKC", text))
                # Search for JS patterns
                js_patterns = re.findall(
                    r"(?i)(eval\(|document\.|window\.|script>|onload=|setTimeout\()",
                    normalized_text
                )
                pattern_info = ""
                if js_patterns:
                    pattern_info = (
                        f"\n🚨 Hidden JavaScript detected! Patterns: {', '.join(set(js_patterns))}"
                    )
                # Truncate the displayed text
                truncated_text = (
                    normalized_text[:display_limit] + "..."
                    if len(normalized_text) > display_limit
                    else normalized_text
                )
                result.append(
                    f"--- Decoded with {encoding} ---\n{truncated_text}{pattern_info}"
                )
        except Exception:
            continue

    # 2) Convert the entire file to hex for analysis, but only display a snippet
    try:
        import binascii
        hex_data = binascii.hexlify(file_bytes).decode("utf-8").lower()
        # Check for 'eval(' in hex -> 6576616c28
        hex_pattern_info = ""
        if "6576616c28" in hex_data:
            hex_pattern_info = "\n🚨 Found 'eval(' in hex representation!"

        # Truncate the displayed hex
        truncated_hex = hex_data[:display_limit] + "..." if len(hex_data) > display_limit else hex_data
        result.append(f"--- Hexadecimal (truncated) ---\n{truncated_hex}{hex_pattern_info}")
    except Exception as e:
        result.append(f"\nError converting file to hex: {str(e)}")

    # 3) Convert to binary (optional) but only display a snippet
    try:
        bin_data = bin(int(binascii.hexlify(file_bytes), 16))[2:]
        truncated_bin = bin_data[:display_limit] + "..." if len(bin_data) > display_limit else bin_data
        result.append(f"--- Binary (truncated) ---\n{truncated_bin}")
    except Exception as e:
        result.append(f"\nError converting file to binary: {str(e)}")

    # If no text was produced at all, return None
    final_output = "\n\n".join(result).strip()
    return final_output if final_output else None
