# Always prefer setuptools over distutils
from setuptools import setup, find_packages

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

long_description = "Readme: https://github.com/equinor/lcoe-azure-ad"

setup(
    name='lcoe-azure-ad',


    version='1.0.0',

    description='LCoE azure ad',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/equinor/lcoe-azure-ad',

    # Author details
    author='Mats Grønning Andersen',
    author_email='mgand@equinor.com',

    # Choose your license
    license='MIT',

    py_modules=['azure_ad'],
    # download_url="https://github.com/equinor/lcoe-azure-ad",
)
