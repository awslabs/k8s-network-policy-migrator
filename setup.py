from setuptools import setup, find_packages

setup(
    name="netpolymigrator",
    version="0.2.0",
    author="Sanjeev Ganjihal",
    description="A tool to migrate Calico and Cilium network policies to Kubernetes native network policies",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache 2.0",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.6",
    install_requires=[
        "kubernetes>=12.0.0",
        "PyYAML>=5.1",
        "click>=7.0",
    ],
    entry_points={
        "console_scripts": [
            "netpolymigrator=netpolymigrator.cli:main"
        ]
    }
)
