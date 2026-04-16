import os
from pathlib import Path

def write_user_profile(home: str):
    profile_path = os.path.join(home, ".bashrc")
    Path(profile_path).write_text("# managed by test fixture\n")
