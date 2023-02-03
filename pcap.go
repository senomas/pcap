package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	dev := os.Getenv("PCAP_DEV")
	filter := os.Getenv("PCAP_FILTER")
	if dev == "" {
		dev = "eth0"
	}
	output := os.Getenv("PCAP_OUTPUT")
	if output == "" {
		output = "/var/log/pcap"
	}
	vs := os.Getenv("PCAP_UID")
	var uid int
	if vs == "" {
		uid = 1000
	} else {
		uid, _ = strconv.Atoi(vs)
	}
	vs = os.Getenv("PCAP_GID")
	var gid int
	if vs == "" {
		gid = uid
	} else {
		gid, _ = strconv.Atoi(vs)
	}
	tlogFormat := os.Getenv("PCAP_LOGTIME")
	if tlogFormat == "" {
		tlogFormat = "2006010215"
	}

	fmt.Printf("CAPTURE %s WITH FILTER '%s' STARTED\n", dev, filter)

	flogFlag := os.O_APPEND | os.O_CREATE | os.O_WRONLY

	tz := time.Now()
	tnext := tz.Truncate(time.Hour).Add(time.Hour)
	fn := fmt.Sprintf("%s-%s.log", output, tz.Format(tlogFormat))
	flog, err := os.OpenFile(fn, flogFlag, 0644)
	if err != nil {
		panic(err)
	}
	defer flog.Close()
	flog.Chown(uid, gid)

	if handle, err := pcap.OpenLive(dev, 65535, true, pcap.BlockForever); err != nil {
		if strings.Contains(err.Error(), "No such device exists") {
			if devs, err := pcap.FindAllDevs(); err != nil {
				panic(err)
			} else {
				fmt.Println("Available devices: ")
				for _, dev := range devs {
					fmt.Printf("\t%v\n", dev.Name)
				}
			}
			return
		}
		panic(err)
	} else if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions.Lazy = true

		conns := make(map[string]int)

		buf := bytes.NewBuffer(make([]byte, 0, 65535))
		for packet := range packetSource.Packets() {
			ip4, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

			// fmt.Printf("\n\n%v\n", packet)
			if ip4 != nil && tcp != nil {
				s1 := fmt.Sprintf("%v:%d-%v:%d", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)

				_, s1c := conns[s1]
				if s1c {
					fmt.Fprintf(buf, "%v %v SEND %d", packet.Metadata().Timestamp.Format("15:04:05.000000"), s1, packet.Metadata().Length)
				} else {
					s2 := fmt.Sprintf("%v:%d-%v:%d", ip4.DstIP, tcp.DstPort, ip4.SrcIP, tcp.SrcPort)
					_, s2c := conns[s2]
					if s2c {
						fmt.Fprintf(buf, "%v %v RECV %d", packet.Metadata().Timestamp.Format("15:04:05.000000"), s2, packet.Metadata().Length)
					} else {
						conns[s1] = 1
						fmt.Fprintf(buf, "%v %v SEND %d", packet.Metadata().Timestamp.Format("15:04:05.000000"), s1, packet.Metadata().Length)
					}
				}

				buf.WriteString(" [")
				for _, c := range ip4.Payload {
					if c == '\r' {
						buf.WriteString("\\r")
					} else if c == '\n' {
						buf.WriteString("\\n")
					} else if c == '\t' {
						buf.WriteString("\\t")
					} else if c == '\\' {
						buf.WriteString("\\\\")
					} else if c >= ' ' && c < 127 {
						buf.WriteByte(c)
					} else {
						fmt.Fprintf(buf, "\\x%02X", c)
					}
				}
				buf.WriteString("]")

				nf := false
				if tcp.FIN {
					if nf {
						fmt.Fprint(buf, ",FIN")
					} else {
						nf = true
						fmt.Fprint(buf, " FIN")
					}
				}
				if tcp.SYN {
					if nf {
						fmt.Fprint(buf, ",SYN")
					} else {
						nf = true
						fmt.Fprint(buf, " SYN")
					}
				}
				if tcp.RST {
					if nf {
						fmt.Fprint(buf, ",RST")
					} else {
						nf = true
						fmt.Fprint(buf, " RST")
					}
				}
				if tcp.ACK {
					if nf {
						fmt.Fprint(buf, ",ACK")
					} else {
						nf = true
						fmt.Fprint(buf, " ACK")
					}
				}
				lpayload := len(tcp.Payload)
				if lpayload > 0 {
					nf = true
					fmt.Fprintf(buf, " %d [", lpayload)
					for _, c := range tcp.Payload {
						if c == '\r' {
							buf.WriteString("\\r")
						} else if c == '\n' {
							buf.WriteString("\\n")
						} else if c == '\t' {
							buf.WriteString("\\t")
						} else if c == '\\' {
							buf.WriteString("\\\\")
						} else if c >= ' ' && c < 127 {
							buf.WriteByte(c)
						} else {
							fmt.Fprintf(buf, "\\x%02X", c)
						}
					}
					buf.WriteString("]")
				}
				if nf {
					tz = time.Now()
					if tz.After(tnext) {
						tnext = tz.Truncate(time.Hour).Add(time.Hour)
						fn := fmt.Sprintf("%s-%s.log", output, tz.Format(tlogFormat))
						flog.Close()

						flog, err = os.OpenFile(fn, flogFlag, 0644)
						if err != nil {
							panic(err)
						}
						flog.Chown(uid, gid)
					}
					fmt.Fprintln(flog, buf.String())
				}
				buf.Reset()
			}
		}
	}
}
