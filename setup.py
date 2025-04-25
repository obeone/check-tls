from setuptools import setup

setup(
    name='check-tls',
    version='1.0.0',
    author='Grégoire Compagnon (obeone)',
    url='https://github.com/obeone/check-tls',
    license='MIT',
    py_modules=['check_tls'],
    install_requires=[
        'cryptography',
        'coloredlogs',
        'flask'
    ],
    entry_points={
        'console_scripts': [
            'check-tls = check_tls:main',
        ],
    },
)
