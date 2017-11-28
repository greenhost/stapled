TWINE = python -m twine
GPG := $(shell which gpg)
TARGET := $(shell pwd)/dist
# BUILD_DEPS = oscrypto certvalidator asn1crypto ocspbuilder

.PHONY: default
default: all;

.PHONY: install
install:
	python setup.py install

#.PHONY: deps ${BUILD_DEPS}
#deps: ${BUILD_DEPS}
#
#${BUILD_DEPS}:
#	mkdir -p "$(TARGET)"
#	@echo Building $@
#	mkdir -p build_deps/tmp/${@}
#	rm -rf build_deps/tmp/${@}/*
#	cd build_deps/tmp/${@}
#	pypi-download --verbose=2 $@
#	py2dsc-deb \
#		--with-python2=True \
#		--with-python3=True \
#		--dist-dir=build_deps/tmp/${@}/deb_dist \
#		${@}*.tar.gz

.PHONY: sdist
sdist:
	python setup.py sdist

.PHONY: bdist
bdist:
	python setup.py bdist --formats=gztar,bztar -u root -g root

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
deb:
	python setup.py --command-packages=stdeb.command sdist_dsc \
	 				--with-python2=True --with-python3=True bdist_deb
	@echo "Moving binary packages from 'deb_dist' to 'dist'."
	mkdir -p dist/
	mv deb_dist/ocspd*.deb dist/
	#rm -rfv deb_dist

.PHONY: all
all: sdist bdist wheel rpm deb

.PHONY: distribute
distribute:
	gpg --detach-sign -a dist/package-1.0.1.tar.gz
	python -m twine upload dist/package-1.0.1.tar.gz package-1.0.1.tar.gz.asc

.PHONY: clean
clean:
	make -f $(CURDIR)/debian/rules override_dh_auto_clean
	rm -rf deb_dist dist *.egg-info .pybuild
	rm -rf build_deps

.PHONY: docker-build
docker-build:
	mkdir -p dist-docker/
	docker build -t build-ocspd .
	docker run -it -d --name ocspd --mount type=bind,source="$$(pwd)/dist-docker/",target=/_dist build-ocspd

.PHONY: docker-compile
docker-compile:
	docker start ocspd
	docker exec -it ocspd rm -rfv "/_dist/*"
	docker exec -it ocspd make clean
	docker exec -it ocspd make
	docker exec -it ocspd bash -c 'mv dist/* /_dist/ || echo nothing to move.'

.PHONY: docker-install
docker-install:
	docker start ocspd
	docker exec -it ocspd bash -c 'apt-get install -y -q  /_dist/ocspd_*all.deb'

.PHONY: docker-run
docker-run:
	docker start ocspd
	docker exec -it ocspd ./refresh_testdata.sh
	docker exec -it ocspd ocspd -d testdata/ --recursive --interactive --no-haproxy-sockets -vvvv
	docker stop ocspd

.PHONY: docker-stop
docker-stop:
	docker stop ocspd

.PHONY: docker-nuke
docker-nuke:
	bash -c 'CONTAINERS=$$(docker container ls --all --filter=name=ocspd -q | xargs); \
    if [ ! -z $$CONTAINERS ]; then \
        echo "Stopping and deleting containers: $${CONTAINERS}"; \
        docker stop $$CONTAINERS; \
        docker container rm $$CONTAINERS; \
    else \
        echo "No matching containers found."; \
    fi; \
    IMAGES=$$(docker images | grep ocspd | awk "{print $$1}"); \
    if [ ! -z $$IMAGES ]; then \
        echo "Deleting images: $${IMAGES}"; \
        echo $$IMAGES | xargs docker rmi; \
    else \
        echo "No matching images found."; \
    fi'

.PHONY: docker-all
docker-all: docker-nuke docker-build docker-compile docker-install docker-stop
