FROM debian:stretch
RUN apt-get update -qq
RUN apt-get upgrade -y
RUN apt-get install -y openssl ca-certificates python3-cffi \
    python3-configargparse python3-daemon
COPY ./refresh_testdata.sh ./refresh_testdata.sh
