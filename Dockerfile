FROM debian:buster
RUN apt-get update -qq
RUN apt-get upgrade -y
RUN apt-get install -q -y build-essential python3-cffi libffi-dev \
    python-all python3-all python3-dev python3-setuptools python3-pip \
    rpm tar gzip bzip2 git debhelper
RUN pip3 install --user pip
ADD . ./
RUN pip3 install -r requirements.txt
RUN pip3 install certvalidator ocspbuilder asn1crypto oscrypto
CMD echo Ready for your commands. && /bin/bash
