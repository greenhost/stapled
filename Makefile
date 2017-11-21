PYTHON=`which python`
TWINE=python -m twine
GPG=`which gpg`

.PHONY: install
install:
	python setup.py install

.PHONY: build-deps
build-deps:
	for PACKAGE in certvalidator oscrypto asn1crypto ocspbuilder ; do \
		pypi-download $(PACKAGE); \
		py2dsc-deb \
			--with-python2=True \
			--with-python3=True \
			$(PACKAGE)*.tar.gz; \
	done

.PHONY: build-sdist
build-sdist:
	python setup.py sdist

.PHONY: build-bdist
build-bdist:
	python setup.py bdist --formats=gztar,bztar

.PHONY: build-wheel
build-wheel:
	python setup.py bdist_wheel

.PHONY: build-rpm
build-rpm:
	python setup.py bdist --formats=rpm -u root -g root

.PHONY: build-deb-src
build-deb-src:
	python setup.py --command-packages=stdeb.command sdist_dsc \
	 				   --with-python2=True --with-python3=True

.PHONY: build-deb
build-deb:
	make build-deb-src
	python setup.py --command-packages=stdeb.command bdist_deb
	echo "Moving binary packages from 'deb_dist' to 'dist'."
	mv deb_dist/python*-ocspd_*.deb dist/
	rm -rfv deb_dist

.PHONY: build
build:
	make build-deps
	make build-sdist
	make build-bdist
	make build-wheel
	make build-rpm
	make build-deb

.PHONY: distribute
distribute:
	gpg --detach-sign -a dist/package-1.0.1.tar.gz
	python -m twine upload dist/package-1.0.1.tar.gz package-1.0.1.tar.gz.asc

.PHONY: clean
clean:
	python setup.py clean
	make -f $(CURDIR)/debian/rules override_dh_auto_clean
	rm -rf deb_dist dist *.egg-info .pybuild
	rm -rf build-deps
	find . -name '*.pyc' -delete
