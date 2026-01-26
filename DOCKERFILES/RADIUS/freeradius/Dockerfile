FROM ubuntu:24.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    freeradius freeradius-mysql mariadb-client ca-certificates && \
    apt clean

CMD ["freeradius","-f"]
