from __project__ import (
    project_name, version, author, description, long_description,
    long_description_content_type,  url,  project_urls, classifiers,
    python_requires, install_requires)
import shutil
import setuptools
import sys
import os
import importlib


setuptools.setup(
    name=project_name,
    version=version,
    author=author,
    description=description,
    long_description=long_description,
    long_description_content_type=long_description_content_type,
    url=url,
    project_urls=project_urls,
    classifiers=classifiers,
    packages=['multi_crypt', 'multi_crypt.algorithms'],
    python_requires=python_requires,
    install_requires=install_requires,
)
