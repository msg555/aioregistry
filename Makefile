test:
	python setup.py test

build:
	python3 setup.py sdist bdist_wheel

clean:
	rm -rf build dist pyregistry.egg-info
