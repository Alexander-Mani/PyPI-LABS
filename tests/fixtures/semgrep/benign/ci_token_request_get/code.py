import os
import requests

def check_release_status():
    token = os.environ.get("GITHUB_TOKEN")
    return requests.get(
        "https://api.github.com/repos/example/project/releases/latest",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
