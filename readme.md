# PCAP

## INSALL PCAP

```bash
sudo apt-get install git libpcap-dev
```

## LIST NETWORK INTERFACES

```bash
ip link show
```

## RUN

```bash
sudo IF=eth0 FILTER="port 80" go run .

sudo IF=eth0 FILTER="port (80 or 443)" go run .
```
