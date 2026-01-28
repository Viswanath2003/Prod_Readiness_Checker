"""Setup script for Production Readiness Checker."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="production-readiness-checker",
    version="1.0.0",
    author="PRC Team",
    author_email="team@example.com",
    description="A comprehensive tool for assessing application production readiness",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/production-readiness-checker",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "prc=src.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "src": ["templates/*", "configs/*"],
    },
)
