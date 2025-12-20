from setuptools import setup, find_packages

setup(
    name='dlmap-package',
    version='1.0', 
    author='Lega', # <--- تم تعديل هذا السطر
    description='Ultimate Static Analysis Tool for Security',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(),
    install_requires=[
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'dlmap = dlmap_package.dlmap_cli:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires='>=3.6',
)

