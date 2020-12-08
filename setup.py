import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sniffer",
    version="0.1",
    author="Vedernikov Valera",
    author_email="valera808@inbox.ru",
    description="simple sniffer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/OxyEho/Sniffer.git",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3"
    ],
    python_requires='>=3.6',
)
