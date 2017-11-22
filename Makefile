TWINE = python -m twine
GPG := $(shell which gpg)
TARGET := $(shell pwd)/dist
BUILD_DEPS = oscrypto certvalidator asn1crypto ocspbuilder

.PHONY: default
default: all;

.PHONY: install
install:
	python setup.py install

.PHONY: deps ${BUILD_DEPS}
deps: ${BUILD_DEPS}

${BUILD_DEPS}:
	mkdir -p "$(TARGET)"
	@echo Building $@
	mkdir -p build_deps/tmp/${@}
	rm -rf build_deps/tmp/${@}/*
	cd build_deps/tmp/${@}
	pypi-download --verbose=2 $@
	py2dsc-deb \
		--with-python2=True \
		--with-python3=True \
		--dist-dir=build_deps/tmp/${@}/deb_dist \
		${@}*.tar.gz

.PHONY: sdist
sdist:
	python setup.py sdist

.PHONY: bdist
bdist:
	python setup.py bdist --formats=gztar,bztar

.PHONY: wheel
wheel:
	python setup.py bdist_wheel

.PHONY: rpm
rpm:
	python setup.py bdist --formats=rpm -u root -g root

.PHONY: deb-src
deb-src:
	python setup.py --command-packages=stdeb.command sdist_dsc \
	 				--with-python2=True --with-python3=True

.PHONY: deb
deb: deb-src
	python setup.py --command-packages=stdeb.command sdist_dsc \
	 				--with-python2=True --with-python3=True bdist_deb
	@echo "Moving binary packages from 'deb_dist' to 'dist'."
	mv deb_dist/ocspd*.deb dist/
	rm -rfv deb_dist

.PHONY: all
all: sdist bdist wheel rpm deb #build-deps

.PHONY: distribute
distribute:
	gpg --detach-sign -a dist/package-1.0.1.tar.gz
	python -m twine upload dist/package-1.0.1.tar.gz package-1.0.1.tar.gz.asc

.PHONY: clean
clean:
	python setup.py clean
	make -f $(CURDIR)/debian/rules override_dh_auto_clean
	rm -rf deb_dist dist *.egg-info .pybuild
	rm -rf build_deps
	find . -name '*.pyc' -delete
