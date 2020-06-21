import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyregistry", # Replace with your own username
    version="0.2.0",
    author="Mark Gordon",
    author_email="msg@clinc.com",
    description="Python library for interacting with container image registries",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/clinc/PyRegistry",
    packages=setuptools.find_packages(exclude=["tests"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "requests>=2.0"
    ],
    scripts=[
        "scripts/pyregistry",
    ],
    test_suite="tests",
    python_requires=">=3.5",
)
