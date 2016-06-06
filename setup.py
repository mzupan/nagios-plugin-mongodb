from setuptools import setup, find_packages

entry_points = '''
[console_scripts]
check_mongodb = check_mongodb:main
'''

setup(
    name='check_mongodb',
    version='0',
    install_requires=['pymongo'],
    package_dir={'': '.'},
    py_modules=['check_mongodb'],
    description='Check mongodb',
    zip_safe=False,
    entry_points=entry_points
    )
