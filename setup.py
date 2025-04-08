from setuptools import setup, find_packages

setup(
    name="hashium",
    version="1.0.0",
    author="Prog. Kanishk Raj",
    description="Hashium: An advanced cryptography toolkit for secure hashing, encryption, and digital signatures.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ProgrammerKR/Hashium",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography"
    ],
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome",
        "argon2-cffi"
    ],
    include_package_data=True,
)