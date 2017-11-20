PYTHON=`which python`
DESTDIR=/
VERSION=`head -n1 .version`
PROJECT=`sed '2q;d' .version`
BUILDIR=$(CURDIR)/debian/$(PROJECT)



.PHONY: install
install:
	$(PYTHON) setup.py install

.PHONY: build-source
build-source:
	$(PYTHON) setup.py sdist

.PHONY: build-rpm
build-rpm:
	$(PYTHON) setup.py bdist --formats=rpm

.PHONY: build-deb
build-deb:
	$(PYTHON) setup.py sdist
	mv "./dist/$(PROJECT)-$(VERSION).tar.gz" "./dist/$(PROJECT)_$(VERSION).orig.tar.gz"
	dpkg-buildpackage -i -I -rfakeroot -uc -us
	mkdir -p ./build
	mv "./dist/$(PROJECT)-$(VERSION).*" ./build/

.PHONY: clean
clean:
	$(PYTHON) setup.py clean
	$(MAKE) -f $(CURDIR)/debian/rules clean
	rm -rf deb_dist dist *.egg-info .pybuild
	rm -rfv debian/ocspd
	find . -name '*.pyc' -delete
