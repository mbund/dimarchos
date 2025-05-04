FROM debian

RUN apt-get update && \
    apt-get install -y net-tools curl iproute2 && \
    apt-get clean

CMD [ "tail", "-f", "/dev/null" ]
