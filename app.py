# Within your analysis section
st.subheader("🔎 16-bit/Unicode Text Analysis")
unicode_result = detect_16bit_encoded_text(file_bytes)
if unicode_result:
    truncated = unicode_result[:1000] + "..." if len(unicode_result) > 1000 else unicode_result
    st.write(truncated)
    with st.expander("Show Full Decoded Text"):
        st.text_area("Full Decoded Text", unicode_result, height=300)
else:
    st.write("✅ No suspicious 16-bit encoded text found.")
