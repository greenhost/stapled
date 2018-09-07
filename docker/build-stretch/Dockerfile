FROM debian:stretch
RUN apt-get update -qq
RUN apt-get upgrade
RUN apt-get install -q -y build-essential python3-cffi libffi-dev \
    python3-all python3-dev python3-setuptools python3-pip \
    rpm tar gzip bzip2 git debhelper ca-certificates
ADD ./requirements.txt ./requirements.txt
RUN pip3 install --user pip
RUN pip3 install --user -r requirements.txt
