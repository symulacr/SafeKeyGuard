"""
SafeKeyGuard - Setup Configuration

This file contains the setup configuration for SafeKeyGuard, including package information and dependencies.

"""

from setuptools import setup, find_packages

setup(
    name='SafeKeyGuard',
    version='1.0.0',
    description='A secure key management tool for encrypting and decrypting sensitive data',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='symulacr',
    author_email='mail@symulacr.com',
    url='https://github.com/symulacr/SafeKeyGuard',
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'requests',
        # Add any other dependencies here
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)
