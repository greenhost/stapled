TWINE = python -m twine
GPG := $(shell which gpg)
TARGET := $(shell pwd)/dist
# BUILD_DEPS = oscrypto certvalidator asn1crypto ocspbuilder

.PHONY: default
default: all;

.PHONY: install
install:
	python setup.py install

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
	mv deb_dist/stapled*.deb dist/
	#rm -rfv deb_dist

.PHONY: all
all: sdist bdist wheel rpm deb

# TODO: We need to fill in the variables here before we can upload to pypi.
#.PHONY: distribute
#distribute:
#	gpg --detach-sign -a dist/package-1.0.1.tar.gz
#	python -m twine upload dist/package-1.0.1.tar.gz package-1.0.1.tar.gz.asc

.PHONY: clean
clean:
	make -f $(CURDIR)/debian/rules override_dh_auto_clean
	rm -rf deb_dist dist *.egg-info .pybuild
	rm -rf build_deps

.PHONY: docker-build
docker-build:
	mkdir -p dist-docker/
	docker build -t build-stapled .
	docker run -it -d --name stapled --mount type=bind,source="$$(pwd)/dist-docker/",target=/_dist build-stapled

.PHONY: docker-compile
docker-compile:
	docker start stapled
	docker exec -it stapled rm -rfv "/_dist/*"
	docker exec -it stapled make clean
	docker exec -it stapled make
	docker exec -it stapled bash -c 'mv dist/* /_dist/ || echo nothing to move.'

.PHONY: docker-install
docker-install:
	docker start stapled
	docker exec -it stapled bash -c 'apt-get install -y -q  /_dist/stapled_*all.deb'

.PHONY: docker-run
docker-run:
	docker start stapled
	docker exec -it stapled ./refresh_testdata.sh
	docker exec -it stapled stapled -d testdata/ --recursive --interactive --no-haproxy-sockets -vvvv
	docker stop stapled

.PHONY: docker-stop
docker-stop:
	docker stop stapled

.PHONY: docker-nuke
docker-nuke:
	bash -c 'CONTAINERS=$$(docker container ls --all --filter=name=stapled -q | xargs); \
    if [ ! -z $$CONTAINERS ]; then \
        echo "Stopping and deleting containers: $${CONTAINERS}"; \
        docker stop $$CONTAINERS; \
        docker container rm $$CONTAINERS; \
    else \
        echo "No matching containers found."; \
    fi; \
    IMAGES=$$(docker images | grep stapled | awk "{print $$1}"); \
    if [ ! -z $$IMAGES ]; then \
        echo "Deleting images: $${IMAGES}"; \
        echo $$IMAGES | xargs docker rmi; \
    else \
        echo "No matching images found."; \
    fi'

.PHONY: docker-all
docker-all: docker-nuke docker-build docker-compile docker-install docker-stop
