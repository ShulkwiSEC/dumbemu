from setuptools import setup, find_packages

setup(
    name='dumbemu',
    version='0.1',
    packages=find_packages(),
    author='Diefunction',
    description='A lightweight, minimal-dependency PE file emulator built on top of Unicorn Engine.',
    url='https://github.com/Diefunction/dumbemu',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
    python_requires='>=3.6',
)