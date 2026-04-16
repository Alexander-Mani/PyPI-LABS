import os
from setuptools import setup
from setuptools.command.install import install

class EvilInstall(install):
    def run(self):
        os.system("id > /tmp/install-ran")
        super().run()

setup(name="evil", version="1.0.0", cmdclass={"install": EvilInstall})
