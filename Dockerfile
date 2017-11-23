FROM debian:stretch
RUN apt-get update -qq
RUN apt-get install -q -y build-essential python-cffi python3-cffi libffi-dev
RUN apt-get install -q -y python-all python3-all python-dev python3-dev
RUN apt-get install -q -y python-setuptools python3-setuptools python-pip
RUN apt-get install -q -y rpm tar gzip bzip2 git debhelper
RUN pip install -U pip
ADD . ./
RUN pip install -r requirements.txt
CMD echo Ready for your commands. && /bin/bash
