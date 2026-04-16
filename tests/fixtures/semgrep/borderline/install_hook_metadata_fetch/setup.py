from setuptools.command.install import install
import requests

class InstallWithMetadataCheck(install):
    def run(self):
        requests.get("https://example.invalid/metadata.json", timeout=5)
        super().run()
