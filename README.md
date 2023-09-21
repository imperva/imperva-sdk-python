imperva-sdk
===========

imperva-sdk is an Imperva SecureSphere Open API SDK for Python, which allows Python developers to write software that communicates with the SecureSphere MX. imperva-sdk provides an easy to use, object-oriented API in addition to JSON export/import capabilities.

[Download latest package](https://imperva.github.io/imperva-sdk-python/quickstart.html#downloads)

[Documentation](https://imperva.github.io/imperva-sdk-python/)

To use the SDK: follow [Quick start](https://imperva.github.io/imperva-sdk-python/quickstart.html) instructions.

To push changes as a contributer:
1. fork https://github.com/imperva/imperva-sdk-python
2. ``git clone`` from your forked project
3. ``cd imperva-sdk-python``
4. do your changes and test them. See tests/ImpervaSdkSanity.py
5. ``git commit`` and then ``git push``
6. create a pull request from your fork to imperva. 

To pack and publish as product owner:
1. ``git clone https://github.com/imperva/imperva.github.io.git``
2. ``git clone https://github.com/imperva/imperva-sdk-python.git``
3. ``cd imperva-sdk-python``
4. ``pip install setuptools wheel sphinx_glpi_theme``
5. To pack: ``python setup.py sdist bdist_wheel`` Packed output is saved under dist/imperva-sdk-0.2.2.tar.gz
6. ``cp dist/imperva-sdk-0.2.2.tar.gz ../imperva.github.io/versions/imperva-sdk-latest-wip.tar.gz``
7. ``rm -Rf ../imperva.github.io.git/imperva-sdk-python``
8. To generate documentation site: ``sphinx-build -b html -c . docs ../imperva.github.io/imperva-sdk-python``
9. ``cd ../imperva.github.io``
10. git commit changes and push
