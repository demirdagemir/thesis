# -*- coding: utf-8 -*-

# Learn more: https://github.com/kennethreitz/setup.py

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='src',
    version='0.1.0',
    description='Master Thesis for TUM Software Engineering 2017/2018',
    long_description=readme,
    author='Emir Demirdag',
    author_email='emirdemirdag@gmail.com',
    url='https://github.com/demirdagemir/thesis',
    license=license,
    packages=find_packages(exclude=('tests', 'docs')),
    dependency_links=['https://github.com/demirdagemir/aion'],
    install_requires=['Aion']
)

