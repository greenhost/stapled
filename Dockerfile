FROM debian:stretch
RUN apt-get update -qq
RUN apt-get upgrade
RUN apt-get install -q -y build-essential python-cffi python3-cffi libffi-dev \
    python-all python3-all python-dev python3-dev python-setuptools \
    python3-setuptools python-pip python3-pip rpm tar gzip bzip2 git debhelper
RUN pip3 install --user pip
ADD . ./
RUN pip3 install -r requirements.txt
CMD echo Ready for your commands. && /bin/bash
