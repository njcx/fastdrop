package main

import (
	"context"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I./headers

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
}

func updateMapKeyV(client *redis.Client, updateMap *ebpf.Map) {
	ctx := context.Background()
	ipList, err := client.LRange(ctx, "xdp_drop_ip_port", 0, -1).Result()
	if err == redis.Nil {
		log.Fatal("xdp_drop_ip_port key does not exist")
	} else if err != nil {
		log.Fatal(err)
	} else {
		log.Println("IpList", ipList)
	}

	type ipPortKey struct {
		IP   uint32
		Port uint16
		_    uint16
	}

	for i := range ipList {
		log.Println("Processing IP:Port", ipList[i])
		split := strings.Split(ipList[i], ":")
		ip, _ := ipToUint32(split[0])
		port64, err := strconv.ParseUint(split[1], 10, 16)
		if err != nil {
			log.Fatalf("invalid port number: %s", split[1])
		}
		port := uint16(port64)

		key := ipPortKey{
			IP:   ip,
			Port: port,
		}
		value := uint32(1)
		log.Println("Adding IP:Port to map:", ip, port, key, value)

		err = updateMap.Put(key, value)
		if err != nil {
			log.Fatalf("Failed to update map: %v", err)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	ifaceName := os.Args[1]
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "pwd",
		DB:       0,
	})

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	c := cron.New()
	c.AddFunc("@every 30s", func() { updateMapKeyV(client, objs.DropIpsPorts) })
	c.Start()

	defer client.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("Received signal, exiting...")
}
