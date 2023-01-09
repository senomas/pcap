FROM golang:1.19.1 AS pcap
WORKDIR /root/app

RUN apt-get update && \
  apt-get -y install git libpcap-dev && \
  rm -rf /var/lib/apt/lists/*

ADD go.mod /root/app/
ADD go.sum /root/app/
RUN GOOS=linux GOARCH=amd64 go mod download

ADD *.go /root/app/
RUN GOOS=linux GOARCH=amd64 go build -o pcap

FROM ubuntu:bionic-20221215

RUN apt-get update && apt-get install -y \
  git build-essential python net-tools curl libasound2 wget unzip libaio1 iputils-ping netcat software-properties-common git libpcap-dev && \
  rm -rf /var/lib/apt/lists/* /var/cache/apt/*

COPY --from=pcap /root/app/pcap /usr/bin/pcap

ENTRYPOINT [ "pcap" ]