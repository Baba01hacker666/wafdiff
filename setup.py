from setuptools import setup, find_packages

setup(
    name="wafdiff",
    version="1.0.0",
    author="Baba01hacker666",
    description="WAF inconsistency detector and payload differ",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Baba01hacker666/wafdiff",
    packages=find_packages(),
    install_requires=[
        "requests",
        "urllib3",
    ],
    entry_points={
        "console_scripts": [
            "wafdiff=wafdiff.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
