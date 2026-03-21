from setuptools import setup, find_packages

setup(
    name="mini-code-analyzer",
    version="0.1.0",
    description="Mini static code security analyzer",
    author="AbdoWldFiad",
    packages=find_packages(),
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "mini-analyzer = mini_code_analyzer.run:main",
        ]
    },
)