imperva-sdk
===========

imperva-sdk is an Imperva SecureSphere Open API SDK for Python, which allows Python developers to write software that communicates with the SecureSphere MX. imperva-sdk provides an easy to use, object-oriented API in addition to JSON export/import capabilities.

[Download latest package](https://imperva.github.io/imperva-sdk-python/quickstart.html#downloads)

[Documentation](https://imperva.github.io/imperva-sdk-python/)

To use the SDK: follow [Quick start](https://imperva.github.io/imperva-sdk-python/quickstart.html) instructions.

To push changes as a contributer:
1. fork https://github.com/imperva/imperva-sdk-python
2. git clone from your forked project
3. cd imperva-sdk-python
4. do your changes and test them
5. git push
6. create a pull request from your fork to imperva. 

To pack and publish as product owner:
1. git pull imperva/imperva.github.io
2. git pull imperva/imperva-sdk-python 
4. pip install setuptools wheel
6. python setup.py sdist bdist_wheel
   Output binary is saved under dist/imperva-sdk-0.2.0.tar.gz
7. Copy imperva-sdk-python/dist/imperva-sdk-0.2.0.tar.gz and rename it into imperva.github.io/imperva-sdk-python/_downloads/imperva-sdk-latest-wip.tar.gz
8. git push