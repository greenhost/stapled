FROM debian:jessie
RUN echo "deb http://ftp.debian.org/debian jessie-backports main" >> \
    /etc/apt/sources.list
RUN apt-get update -qq
RUN apt-get install -y -t jessie-backports python-configargparse \
    python-daemon python-future python3-configargparse python3-daemon \
    python3-future
RUN apt-get install -y openssl ca-certificates python-six python-cffi \
    python3-six python3-cffi
COPY ./refresh_testdata.sh ./refresh_testdata.sh
