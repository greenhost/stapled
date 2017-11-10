VERSION=`head -n1 debian/changelog | awk -F '[)(]' '{print $$2}'`

all:
	install -d -m 755 build
	echo "Compiling version $(VERSION)"
	dpkg-buildpackage -us -uc
	mv ../cosmos2d_$(VERSION)* build
