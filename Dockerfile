FROM docker.io/library/debian:trixie

RUN (export DEBIAN_FRONTEND='noninteractive' && \
    apt-get update  && \
    apt-get upgrade -y && \
    apt-get install -y sbcl make)

USER root
RUN useradd -ms /bin/bash whistler
USER whistler

ENV work /home/whistler

WORKDIR ${work}
COPY . ${work}
USER root
RUN chown -R whistler:whistler ${work}
USER whistler

RUN cd ${work} && make

ENTRYPOINT [ "/home/whistler/whistler" ]


