import subprocess

def run_formatter(path: str):
    return subprocess.run(["python", "-m", "black", path], shell=False, check=True)
