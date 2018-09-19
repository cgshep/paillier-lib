import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="paillierlib",
    version="0.0.1",
    author="Carlton Shepherd",
    author_email="carlton@linux.com",
    description="A simple implementation of the Paillier cryptosystem",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/carltonshepherd/paillier-lib",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Intended Audience :: Science/Research",
        "Development Status :: 3 - Alpha"
    ],
    keywords='encryption,decryption,homomorphic,crypto,cryptography,security,privacy',
    install_requires=[
        "gmpy2>=2.0.0",
    ]
)
