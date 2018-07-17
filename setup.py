from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='imperva-sdk',
    version='0.1.9',
    description='SDK for Imperva SecureSphere Open API',
    long_description=long_description,
    url='https://imperva.github.io/imperva-sdk-python/',
    author='Imperva Inc.',
    author_email='opensource-dev@imperva.com',
    license='Proprietary',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: Other/Proprietary License',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.6'
    ],
    keywords='security api imperva securesphere mx waf',

    #packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    py_modules=["imperva_sdk"],
    install_requires=['requests'],

    #extras_require={
    #    'dev': ['check-manifest'],
    #    'test': ['coverage'],
    #},
    #package_data={
    #    'sample': ['package_data.dat'],
    #},
    #data_files=[('my_data', ['data/data_file'])],

    #entry_points={
    #    'console_scripts': [
    #        'sample=sample:main',
    #    ],
    #},
)
