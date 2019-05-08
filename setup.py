from setuptools import setup, find_packages

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='manticoremap',

    version='0.0.1',

    description='Provides a roadmap for supporting a target program in Manticore',

    long_description=long_description,

    long_description_content_type='text/markdown',

    url='https://github.com/trailofbits/manticore-roadmap',

    author='Eric Hennenfent',

    author_email='eric.hennenfent@trailofbits.com',

    keywords='manticore',

    packages=find_packages(exclude=['docs', 'tests']),

    python_requires='>=3.6',

    install_requires=['manticore[native]', 'pyyaml', 'lark-parser', 'wrapt', 'termcolor'],

    entry_points={
        'console_scripts': [
            'manticore-roadmap=manticoremap.main:main',
        ],
    },
)
