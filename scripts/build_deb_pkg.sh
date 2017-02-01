#!/bin/bash
###############################################################################
## WARNING: PROVIDED AS IS, DO NOT USE THIS, SERIOUS SIDE EFFECTS GUARANTEED ##
###############################################################################
## This script downloads the master branch of each of the dependencies that  ##
## are not available as a debian package and converts them to a debian       ##
## package. However whatever source code you happen to check out, it won't   ##
## be audited. It may contain lines of code you don't intend to run. You     ##
## will also have to make sure you get updates yourself. More info can be    ##
## found in the documentation: `docs/using.rst`.                             ##
###############################################################################

set -x
REPOS="wbond/asn1crypto wbond/oscrypto wbond/ocspbuilder wbond/certvalidator jlhutch/pylru"
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

for rep in $REPOS; do
    dep=$(echo $rep | cut -d/ -f2)
    git clone "https://github.com/${rep}"
    cd "$dep"
    pip uninstall $dep
    pip install -e ./
    sed -i "s/.*'clean': CleanCommand,.*/        # 'clean': CleanCommand,/" setup.py
    python setup.py sdist
    py2dsc dist/${dep}-*.tar.gz
    cd deb_dist/${dep}-*/
    dpkg-buildpackage -rfakeroot -uc -us
    cd ..
    mv python*-${dep}*_all.deb $BUILD
    cd "$DEP_BUILD"
done

cd ..
python2 setup.py sdist
py2dsc dist/ocspd-*.tar.gz
cd deb_dist/ocspd-*/
dpkg-buildpackage -rfakeroot -uc -us
cd ..
mv python*-ocspd*_all.deb $BUILD
