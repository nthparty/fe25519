from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name="fe25519",
    version="0.0.0.8",
    packages=["fe25519",],
    install_requires=[],
    license="MIT",
    url="https://github.com/lapets/fe25519",
    author="Andrei Lapets",
    author_email="a@lapets.io",
    description="Native Python implementation of Ed25519 "+\
                "field elements and operations.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    test_suite="nose.collector",
    tests_require=["nose"],
)
