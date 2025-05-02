# Import setup tools for packaging and distribution
from setuptools import setup, find_packages

# Configure the package metadata and options
setup(
    name='check-tls',  # Name of the package
    version='1.0.1',  # Initial release version
    author='Grégoire Compagnon (obeone)',  # Author information
    url='https://github.com/obeone/check-tls',  # Project URL
    license='MIT',  # License type
    packages=find_packages(where='src'),  # Automatically find all packages in 'src'
    package_dir={'': 'src'},  # Root package directory is 'src'
    install_requires=[
        'cryptography',   # For cryptographic operations
        'coloredlogs',    # For colored logging output
        'flask'           # For the web server interface
    ],
    entry_points={
        'console_scripts': [
            # Expose a CLI command 'check-tls' that runs the main() function
            'check-tls = check_tls.main:main',
        ],
    },
)
