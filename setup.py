from setuptools import setup

setup(
    name='instacache',
    version='0.2.3',
    author='Fil Krynicki',
    author_email='filipkrynicki@gmail.com',
    url='https://github.com/thefil/instacache',
    scripts=['bin/instacache.py'],
    license='LICENSE.txt',
    description='Simple program to back up Instapaper favorites in plaintext and html form.',
    long_description=open('README.md').read(),
    install_requires=[
                "oauth2 >= 1.5.211"
            ],
)
