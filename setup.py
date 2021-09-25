from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

# The lines below are parsed by `docs/conf.py`.
name = "fe25519"
version = "0.2.0"

setup(
    name=name,
    version=version,
    packages=["fe25519",],
    install_requires=["parts>=0.2.1","bitlist>=0.3.1","fountains>=0.2.1",],
    license="MIT",
    url="https://github.com/nthparty/fe25519",
    author="Andrei Lapets",
    author_email="a@lapets.io",
    description="Pure Python data structure for working with Ed25519 "+\
                "(and Ristretto) field elements and operations.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    test_suite="nose.collector",
    tests_require=["nose"],
)
