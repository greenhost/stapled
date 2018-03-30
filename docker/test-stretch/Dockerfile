FROM debian:stretch
RUN apt-get update -qq
RUN apt-get install -y openssl ca-certificates python-six python-cffi \
    python3-six python3-cffi python-configargparse python-daemon \
    python-future python3-configargparse python3-daemon python3-future
COPY ./refresh_testdata.sh ./refresh_testdata.sh
