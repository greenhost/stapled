FROM debian:pypy:3-5
RUN echo "deb http://ftp.debian.org/debian jessie-backports main" >> /etc/apt/sources.list
RUN apt-get update -qq
RUN apt-get install -y -t jessie-backports python3-configargparse python3-daemon python3-future
RUN apt-get install -y openssl ca-certificates python3-six python3-cffi
