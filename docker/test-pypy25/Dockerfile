FROM debian:pypy2-5
RUN echo "deb http://ftp.debian.org/debian jessie-backports main" >> /etc/apt/sources.list
RUN apt-get update -qq
RUN apt-get install -y -t jessie-backports python-configargparse python-daemon python-future
RUN apt-get install -y openssl ca-certificates python-six python-cffi
