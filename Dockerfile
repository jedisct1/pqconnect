FROM debian:bullseye AS build

USER root


RUN apt-get update && \
apt-get install -y build-essential \
clang wget python3 python3-pip \
python3-venv sudo libssl-dev \
libsodium-dev git valgrind

RUN pip install build

RUN useradd --create-home pqconnect

RUN mkdir /home/pqconnect/python && \
    mkdir /home/pqconnect/keys/


WORKDIR /home/pqconnect/python

ADD Makefile .
ADD scripts .
ADD pyproject.toml .
ADD README.md .
ADD LICENSE .
ADD server.patch .
ADD src .

RUN patch pyproject.toml server.patch

RUN make install
RUN ldconfig

RUN pqconnect-keygen
CMD ["pqconnect-server"]
