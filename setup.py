#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='django-graphql-oauth2',
    version='0.1.2',
    description='Provide OAuth2 access to your app (fork of django-oauth2)',
    long_description=open('README.rst').read(),
    author='Mohammad',
    url='https://github.com/thisismkh/django-graphql-oauth2',
    packages=find_packages(exclude=('tests*',)),
    license='The MIT License: http://www.opensource.org/licenses/mit-license.php',
    platforms='all',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
    ],
    install_requires=[
        "Django>=2.0",
        "graphene-django>=3.0.0b1",
        "shortuuid>=0.4",
        "six>=0.11.0",
        "sqlparse>=0.2.4",
    ],
    include_package_data=True,
    zip_safe=False,
)
