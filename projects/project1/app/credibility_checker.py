# For full documentations please see deliverable2.py

import requests
from bs4 import BeautifulSoup
from transformers import pipeline
from sentence_transformers import SentenceTransformer, util
from serpapi import GoogleSearch
from datetime import datetime

import os
from dotenv import load_dotenv

load_dotenv()


class CredibilityChecker:
    # YOUR_GOOGLE_API_KEY
    GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
    # YOUR_WHOIS_API_KEY
    WHOIS_API_KEY = os.environ.get("WHOIS_API_KEY", "")
    # YOUR_SERP_API_KEY
    SERP_API_KEY = os.environ.get("SERP_API_KEY", "")
    # URLs:
    GOOGLE_FACT_CHECK_URL = "https://factchecktools.googleapis.com/v1alpha1/claims:search"
    GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    WHOIS_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    


    WEIGHTS = {
        "domain_trust": 0.275,       # 27.5%
        "content_relevance": 0.275,  # 27.5%
        "fact_check": 0.275,         # 27.5%
        "bias": 0.125,               # 12.5%
        "citation": 0.05             # 05.0%
    }


    def __init__(self):
        self.sentiment_analyzer = pipeline("sentiment-analysis", model="cardiffnlp/twitter-roberta-base-sentiment")
        self.similarity_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")


    def get_google_safety_score(self, url):
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
            response = requests.post(f"{self.GOOGLE_SAFE_BROWSING_URL}?key={self.GOOGLE_API_KEY}", json=payload)
            data = response.json()
            if "matches" in data:
                return 1  # Unsafe domain → Very low trust score
            return 100  # Safe domain → High trust score
        except requests.exceptions.RequestException as e:
            print(f"Safe Browsing API Error: {e}")
            return 50  # Neutral trust if request fails


    def get_domain_age_score(self, url):
        try:
            domain = url.split("//")[-1].split("/")[0]  # Extract domain name
            whois_url = f"{self.WHOIS_URL}?apiKey={self.WHOIS_API_KEY}&domainName={domain}&outputFormat=json"
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


    def get_google_search_popularity(self, url):
        try:
            domain = url.split("//")[-1].split("/")[0]  # Extract domain name
            # Call SerpAPI to get Google search results
            params = {
                "q": f"site:{domain}",
                "engine": "google",
                "api_key": self.SERP_API_KEY
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


    def get_domain_trust_score(self, url):
        safety_score = self.get_google_safety_score(url)
        domain_age_score = self.get_domain_age_score(url)
        popularity_score = self.get_google_search_popularity(url)
        final_trust_score = (safety_score * 0.4) + (domain_age_score * 0.3) + (popularity_score * 0.3)
        return round(final_trust_score, 2)


    def get_content_relevance_score(self, url, query):
        page = requests.get(url)
        soup = BeautifulSoup(page.text, "html.parser")
        text = " ".join([p.get_text() for p in soup.find_all("p")])[:2000]
        embeddings1 = self.similarity_model.encode(query, convert_to_tensor=True)
        embeddings2 = self.similarity_model.encode(text, convert_to_tensor=True)
        similarity_score = util.pytorch_cos_sim(embeddings1, embeddings2).item()
        return round(similarity_score*100, 2)


    def get_fact_check_score(self, query):
        params = {"query": query, "key": self.GOOGLE_API_KEY}
        response = requests.get(self.GOOGLE_FACT_CHECK_URL, params=params)
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


    def get_bias_score(self, url):
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
            sentiment = self.sentiment_analyzer(truncated_text)[0]
            score = sentiment["score"]
            label = sentiment["label"]
            # Convert negative sentiment into bias score
            if label == "NEGATIVE":
                bias_score = 60 + ((1 - score) * 40)  # Bias starts at 60%, scales up to 100%
            elif label == "POSITIVE":
                bias_score = 40 - (score * 40)  # Bias starts at 40%, scales down to 0%
            else:  # Neutral
                bias_score = 50  # Set a mid-point for neutrality
            return round(score*100, 2)  # Reward neutral/positive content
        except requests.exceptions.RequestException as e:
            return f"Error: {str(e)}"


    def get_citation_score(self, query):
        params = {
            "q": query,
            "engine": "google_scholar",
            "api_key": self.SERP_API_KEY
        }
        search = GoogleSearch(params)
        results = search.get_dict()  # ✅ Correct method
        # Check if scholarly references exist
        if "organic_results" in results:
            num_results = len(results["organic_results"])
            return min(num_results * 10, 100)  # Each result adds 10 points, max 100
        return 0  # No citations found


    def validate_url(self, prompt, url):
        domain_trust_score = self.get_domain_trust_score(url)
        weighted_domain_trust_score = round(domain_trust_score * self.WEIGHTS['domain_trust'], 2)

        content_relevance_score = self.get_content_relevance_score(url, prompt)
        weighted_content_relevance_score = round(content_relevance_score * self.WEIGHTS['content_relevance'], 2)

        fact_check_score = self.get_fact_check_score(prompt)
        weighted_fact_check_score = round(fact_check_score * self.WEIGHTS['fact_check'], 2)

        bias_score = self.get_bias_score(url)
        weighted_bias_score = round(bias_score * self.WEIGHTS['bias'], 2)

        citation_score = self.get_citation_score(prompt)
        weighted_citation_score = round(citation_score * self.WEIGHTS['citation'], 2)

        final_score = round(
            weighted_domain_trust_score +
            weighted_content_relevance_score +
            weighted_fact_check_score +
            weighted_bias_score +
            weighted_citation_score
        , 2)

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


    def get_star_ratings(self, score):
        stars = (score / 100) * 5
        full_stars = int(stars)
        half_star = int((stars - full_stars) >= 0.5)
        empty_stars = 5 - full_stars - half_star

        filled = '★' * full_stars
        half = '⯨' * half_star
        empty = '☆' * empty_stars

        star_ratings = filled + half + empty
        return star_ratings
    
    
    def get_explanation(self):
        explanation = "___" # TEMPORARY
        return explanation
    

    def credibility_score(self, prompt, url):
        scores = self.validate_url(prompt, url)
        credibility_score = round(scores['final_score'], 2)
        ratings = self.get_star_ratings(credibility_score)
        explanation = self.get_explanation()
        result = {'score': credibility_score, 'ratings': ratings, 'explanation': explanation}
        return result


# Example
'''
checker = CredibilityChecker()

user_prompt = "I have just been on an international flight, can i come back home to hold my 1 month old newborn?"
url_ref = "https://www.bhtp.com/blog/when-safe-to-travel-with-newborn/"

result = checker.credibility_score(user_prompt, url_ref)
print(result)
'''

# Run file using teminal:
# python credibility_checker.py

# OUTPUT:
# {'score': 63.0, 'ratings': '★★★☆☆', 'explanation': '___'}