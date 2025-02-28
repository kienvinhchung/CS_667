import streamlit as st
from credibility_checker import CredibilityChecker

checker = CredibilityChecker()

st.title("🌐 Website Credibility Checker")

prompt = st.text_input("🔎 Enter your query (e.g., 'Is climate change real?'):")
url = st.text_input("🌍 Enter a website URL:")

# Submit Button
if st.button("Check Credibility"):
    if prompt and url:
        with st.spinner("Analyzing... Please wait ⏳"):
            result = checker.credibility_score(prompt, url)
        # Display the results
        st.success("✅ Credibility Score Calculated!")
        st.write(f"**Score:** {result['score']} / 100")
        st.write(f"**Ratings:** {result['ratings']}")
        st.write(f"**Explanation:** {result['explanation']}")
    else:
        st.warning("⚠️ Please enter both a query and a URL.")



# View app output screenshot in "app_result_with_explanation.png"