# pip install requests beautifulsoup4 transformers sentence-transformers google-search-results

# IMPORT LIBRARIES:
import requests
from bs4 import BeautifulSoup
from transformers import pipeline
from sentence_transformers import SentenceTransformer, util
from serpapi import GoogleSearch
from datetime import datetime






# LOAD NLP MODELS:
sentiment_analyzer = pipeline("sentiment-analysis", model="cardiffnlp/twitter-roberta-base-sentiment")
similarity_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")






# APIs:

# https://console.cloud.google.com/apis/credentials?inv=1&invt=AboofA&project=cs667-449902&supportedpurview=project
GOOGLE_API_KEY = "YOUR_GOOGLE_API_KEY"
GOOGLE_FACT_CHECK_URL = "https://factchecktools.googleapis.com/v1alpha1/claims:search"
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# https://user.whoisxmlapi.com/products
WHOIS_API_KEY = "YOUR_WHOIS_API_KEY"
WHOIS_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

# https://serpapi.com/dashboard
SERP_API_KEY = "YOUR_SERP_API_KEY"






# DOMAIN TRUST SCORES:

# Google safefy score function:
def get_google_safety_score(url):
    """
    Check Google Safe Browsing API for security risks.
    Return 100 for safe domain, 1 for unsafe domain, and 50 for neutral trust and if request fails.
    """
    payload = {
        "client": {"clientId": "your-client-id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(f"{GOOGLE_SAFE_BROWSING_URL}?key={GOOGLE_API_KEY}", json=payload)
        data = response.json()
        if "matches" in data:
            return 1  # Unsafe domain → Very low trust score
        return 100  # Safe domain → High trust score
    except requests.exceptions.RequestException as e:
        print(f"Safe Browsing API Error: {e}")
        return 50  # Neutral trust if request fails

# WHOISXMLAPI domain age score function:
def get_domain_age_score(url):
    """
    Check domain age using WHOIS API (Older domains are more trustworthy).
    Return score of 0 to 100 where 100 means website has 10+ years of age.
    Return 50 if no data found or request fails.
    """
    try:
        domain = url.split("//")[-1].split("/")[0]  # Extract domain name
        whois_url = f"{WHOIS_URL}?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=json"
        response = requests.get(whois_url)
        data = response.json()
        if "WhoisRecord" in data and "createdDate" in data["WhoisRecord"]:
            created_date = data["WhoisRecord"]["createdDate"]  # e.g., "1997-03-03T05:00:00Z"
            domain_year = int(created_date.split("-")[0])  # Extract the year
            current_year = datetime.now().year
            domain_age = current_year - domain_year
            # Scale domain age score (0 to 100)
            return min(domain_age * 10, 100)  # 10 years or more = max score
        return 50  # Default mid-trust if no data found
    except requests.exceptions.RequestException as e:
        print(f"API Error: {e}")
        return 50  # Return default mid-trust if request fails

# Google search popularity score function:
def get_google_search_popularity(url):
    """
    Check Google search popularity using SerpAPI (Higher presence = higher trust).
    Return score 0 to 100 where 100 means very popular.
    Return 50 for mid-trust and if request fails.
    """
    try:
        domain = url.split("//")[-1].split("/")[0]  # Extract domain name
        # Call SerpAPI to get Google search results
        params = {
            "q": f"site:{domain}",
            "engine": "google",
            "api_key": SERP_API_KEY
        }
        search = GoogleSearch(params)
        results = search.get_dict()
        # Extract search result count
        organic_results = results.get("organic_results", [])
        popularity_score = min(len(organic_results) * 10, 100)
        return popularity_score
    except Exception as e:
        print(f"Error: {e}")
        return 50  # Default mid-trust if API request fails

# Domain trust function by combining scores above:
def get_domain_trust_score(url):
    """
    Combine Google Safe Browsing, Domain Age, and Search Popularity to compute domain trust.
    Return a final combined scores of safety, age, popularity with the weights of 40%, 30%, 30% respectively.
    """
    safety_score = get_google_safety_score(url)
    domain_age_score = get_domain_age_score(url)
    popularity_score = get_google_search_popularity(url)
    final_trust_score = (safety_score * 0.4) + (domain_age_score * 0.3) + (popularity_score * 0.3)
    return round(final_trust_score, 2)






# CONTENT RELEVANCE SCORE:
def get_content_relevance_score(url, query):
    """
    Check content relevance using NLP similarity score.
    Return o to 100 where 100 means it is completely relevant.
    """
    page = requests.get(url)
    soup = BeautifulSoup(page.text, "html.parser")
    text = " ".join([p.get_text() for p in soup.find_all("p")])[:2000]
    embeddings1 = similarity_model.encode(query, convert_to_tensor=True)
    embeddings2 = similarity_model.encode(text, convert_to_tensor=True)
    similarity_score = util.pytorch_cos_sim(embeddings1, embeddings2).item()
    return round(similarity_score*100, 1)






# FACT CHECK SCORE:
def get_fact_check_score(query):
    """
    Check if a claim is factually correct using Google Fact Check API.
    Returns:
    - 100 → Fully True
    - 0 → Fully False
    - 25 → No Fact-Check Available
    """
    params = {"query": query, "key": GOOGLE_API_KEY}
    response = requests.get(GOOGLE_FACT_CHECK_URL, params=params)
    if response.status_code == 200:
        data = response.json()
        if "claims" not in data or len(data["claims"]) == 0:
            return 25  # No fact-check available
        fact_check_scores = []  # Store fact-check results
        for claim in data["claims"]:
            reviews = claim.get("claimReview", [])
            for review in reviews:
                rating = review.get("textualRating", "").lower()
                # Assign binary fact-check scores
                if "true" in rating:
                    fact_check_scores.append(100)
                elif "false" in rating:
                    fact_check_scores.append(0)
        # If multiple fact-checks exist, return the most confident result
        return max(fact_check_scores) if fact_check_scores else 25
    print(f"API Error {response.status_code}: {response.text}")  # Debugging API errors
    return 25  # Default to no fact-check found






# BIAS SCORE:
def get_bias_score(url):
    """
    Analyze text bias using Hugging Face sentiment model.
    Return bias score from 0 to 100.
    """
    try:
        if not url.strip():
            return "Error: URL is empty"
        # Fetch page content
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code != 200:
            return f"Error: Unable to access URL (HTTP {response.status_code})"
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text()
        if len(text) < 100:
            return "Error: Not enough content to analyze"
        # **Fix for Transformer Token Limit (Max 512 Tokens)**
        text = text[:2000]  # Extract the first 1024 characters
        words = text.split()[:500]  # Approximate token limit (~1.5x characters per token)
        truncated_text = " ".join(words)
        # Run sentiment analysis
        sentiment = sentiment_analyzer(truncated_text)[0]
        score = sentiment["score"]
        label = sentiment["label"]
        # Convert negative sentiment into bias score
        if label == "NEGATIVE":
            bias_score = 60 + ((1 - score) * 40)  # Bias starts at 60%, scales up to 100%
        elif label == "POSITIVE":
            bias_score = 40 - (score * 40)  # Bias starts at 40%, scales down to 0%
        else:  # Neutral
            bias_score = 50  # Set a mid-point for neutrality
        return round(score*100, 1)  # Reward neutral/positive content
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"






# CITATION SCORE:
def get_citation_score(query):
    """
    Use SerpAPI to find scholarly references related to the topic.
    Return score range 0-100.
    """
    params = {
        "q": query,
        "engine": "google_scholar",
        "api_key": SERP_API_KEY
    }
    search = GoogleSearch(params)
    results = search.get_dict()  # ✅ Correct method
    # Check if scholarly references exist
    if "organic_results" in results:
        num_results = len(results["organic_results"])
        return min(num_results * 10, 100)  # Each result adds 10 points, max 100
    return 0  # No citations found






# WEIGHTS MAPPING:
WEIGHTS = {
    "domain_trust": 0.275,       # 27.5%
    "content_relevance": 0.275,  # 27.5%
    "fact_check": 0.275,         # 27.5%
    "bias": 0.125,               # 12.5%
    "citation": 0.05             # 05.0%
}






# VALIDATE THE URL WITH FUNCTIONS ABOVE:
def validate_url(prompt, url):
    """
    Main function to rate a source based on multiple credibility factors.

    Each individual score range from 0 to 100.

    Then, weight is applied according to WEIGHTS dict above to calculate the final score.
    """
    domain_trust_score = get_domain_trust_score(url)
    weighted_domain_trust_score = domain_trust_score * WEIGHTS['domain_trust']

    content_relevance_score = get_content_relevance_score(url, prompt)
    weighted_content_relevance_score = content_relevance_score * WEIGHTS['content_relevance']

    fact_check_score = get_fact_check_score(prompt)
    weighted_fact_check_score = fact_check_score * WEIGHTS['fact_check']

    bias_score = get_bias_score(url)
    weighted_bias_score = bias_score * WEIGHTS['bias']

    citation_score = get_citation_score(prompt)
    weighted_citation_score = citation_score * WEIGHTS['citation']

    final_score = (
        weighted_domain_trust_score + 
        weighted_content_relevance_score + 
        weighted_fact_check_score + 
        weighted_bias_score + 
        weighted_citation_score
    )

    return {
        "url": url,
        "domain_trust": domain_trust_score,
        "w_domain_trust": weighted_domain_trust_score,
        "relevance_score": content_relevance_score,
        "w_relevance_score": weighted_content_relevance_score,
        "fact_check": fact_check_score,
        "w_fact_check": weighted_fact_check_score,
        "bias_score": bias_score,
        "w_bias_score": weighted_bias_score,
        "citation_score": citation_score,
        "w_citation_score": weighted_citation_score,
        "final_score": final_score
    }






# CREDIBILITY SCORE:
def credibility_score(prompt, url):
  scores = validate_url(prompt, url)
  credibility_score = scores['final_score']
  explanation = "..." #TEMPORARY
  result = {'score': round(credibility_score, 2), 'explanation': explanation}
  return result






# RESULTS:
user_prompt = "I have just been on an international flight, can i come back home to hold my 1 month old newborn?"
url_ref = "https://www.bhtp.com/blog/when-safe-to-travel-with-newborn/"
print(validate_url(user_prompt, url_ref))
print(credibility_score(user_prompt, url_ref))