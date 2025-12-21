from setuptools import setup, find_packages

setup(
    name='DLMap',
    version='1.0.0',
    description='Nmap-style Static Analysis Security Tool for Mobile Applications',
    author='lega',
    url='https://github.com/lega/DLMap', 
    packages=find_packages(),
    
    scripts=['dlmap'], # Treat dlmap as a standalone executable script
    
    install_requires=[
        # Add any external dependencies here, e.g., 'lxml' or 'requests'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
    ],
    python_requires='>=3.6',
)

