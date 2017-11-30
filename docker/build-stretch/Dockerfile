FROM debian:stretch
RUN apt-get update -qq
RUN apt-get install -q -y build-essential python-cffi python3-cffi libffi-dev \
    python-all python3-all python-dev python3-dev python-setuptools \
    python3-setuptools python-pip python3-pip rpm tar gzip bzip2 git \
    debhelper ca-certificates
ADD ./requirements.txt ./requirements.txt
RUN pip install --user pip
RUN pip install --user -r requirements.txt
