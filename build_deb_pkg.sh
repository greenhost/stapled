#!/bin/bash
set -x
DEPS="asn1crypto oscrypto ocspbuilder certvalidator"
BUILD=$(pwd)/build
DEP_BUILD=$(pwd)/dep_build/

which py2dsc
if [ $? -eq 0 ]; then
    sudo pip install stdeb
fi

which dh_make
if [ $? -eq 0 ]; then
    sudo apt-get install dh-make
fi

which fakeroot
if [ $? -eq 0 ]; then
    sudo apt-get install fakeroot
fi

rm -rfv "$DEP_BUILD"
rm -rfv "$BUILD"
mkdir "$DEP_BUILD"
mkdir "$BUILD"

cd "$DEP_BUILD"

virtualenv ./env
source ./env/bin/activate

for dep in $DEPS; do
    git clone "https://github.com/wbond/${dep}"
    cd "$dep"
    pip2 uninstall $dep
    pip2 install -e ./
    sed -i "s/.*'clean': CleanCommand,.*/        # 'clean': CleanCommand,/" setup.py
    python2 setup.py sdist
    py2dsc dist/${dep}-*.tar.gz
    cd deb_dist/${dep}-*/
    dpkg-buildpackage -rfakeroot -uc -us
    cd ..
    mv python*-${dep}*_all.deb $BUILD
    cd "$DEP_BUILD"
done

python2 setup.py sdist
py2dsc dist/ocspd-*.tar.gz
cd deb_dist/ocspd-*/
dpkg-buildpackage -rfakeroot -uc -us
cd ..
mv python*-ocspd*_all.deb $BUILD
