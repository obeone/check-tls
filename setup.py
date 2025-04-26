from setuptools import setup, find_packages

setup(
    name='check-tls',
    version='1.0.0',
    author='Grégoire Compagnon (obeone)',
    url='https://github.com/obeone/check-tls',
    license='MIT',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'cryptography',
        'coloredlogs',
        'flask'
    ],
    entry_points={
        'console_scripts': [
            'check-tls = check_tls.main:main',
        ],
    },
)
