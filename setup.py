from setuptools import setup
import sys

requirements = [
    'Flask>=0.10.1',
    'Werkzeug>=0.9',
    'requests>=2.3.0',
]
if sys.version_info < (3, 3):
    requirements.append('ipaddress>=1.0.6')

setup(
    name='flask-hookserver',
    version='0.1.3',
    url='https://github.com/nickfrostatx/flask-hookserver',
    download_url='https://github.com/nickfrostatx/flask-hookserver/tarball/v0.1.3',
    author='Nick Frost',
    author_email='nickfrostatx@gmail.com',
    description='Server for GitHub webhooks using Flask',
    license='MIT',
    py_modules=['hookserver'],
    install_requires=requirements,
    keywords = ['github', 'webhooks', 'flask'],
    classifiers = [
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development',
    ],
)
