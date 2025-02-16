from deliverable2 import *

# RESULTS:
user_prompt = "I have just been on an international flight, can i come back home to hold my 1 month old newborn?"
url_ref = "https://www.bhtp.com/blog/when-safe-to-travel-with-newborn/"

score = credibility_score(user_prompt, url_ref)

# TO JSON OBJECT:
import json
def get_json():
  return json.dumps(score, ensure_ascii=False, indent=2)
json_object_result = get_json()
print(json_object_result)

# FILE OUTPUT:
'''
{
  "score": 63.0,
  "ratings": "★★★☆☆",
  "explanation": "___"
}
'''


# WRITE TO JSON FILE:
'''
with open("result.json", "w") as json_file:
  json_file.write(json_object)
'''

# DOWNLOAD JSON FILE:
'''
from google.colab import files
files.download("result.json")
'''

# View result.json in the same directory