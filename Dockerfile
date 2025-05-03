FROM debian

RUN apt-get update && \
    apt-get install -y net-tools && \
    apt-get clean

CMD [ "tail", "-f", "/dev/null" ]
