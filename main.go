package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-ping/ping"
	gosnmp "github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v3"
)

type Device struct {
    IP       string
    Hostname string
    Status   string // "up" atau "down"
}

type Config struct {
    Networks     []string `yaml:"networks"`
    SNMP         SNMPConfig
    PollInterval int `yaml:"poll_interval"` // Detik
}

type SNMPConfig struct {
    Community string `yaml:"community"`
    Version   int    `yaml:"version"` // 1 = v2c, 3 = v3
    Port      int    `yaml:"port"`
}

func loadConfig(filename string) (Config, error) {
    var config Config
    data, err := os.ReadFile(filename)
    if err != nil {
        return config, err
    }
    err = yaml.Unmarshal(data, &config)
    return config, err
}

func getIPsFromCIDR(cidr string) ([]string, error) {
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, err
    }

    var ips []string
    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
        ips = append(ips, ip.String())
    }
    return ips[1 : len(ips)-1], nil // Hilangkan network dan broadcast address
}

func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

func checkICMP(ip string) bool {
    pinger, err := ping.NewPinger(ip)
    if err != nil {
        return false
    }
    pinger.Count = 1
    pinger.Timeout = 2 * time.Second
    err = pinger.Run()
    return err == nil && pinger.Statistics().PacketsRecv > 0
}

func checkSNMP(ip, community string, version, port int) (string, error) {
    snmp := gosnmp.GoSNMP{
        Target:    ip,
        Port:      uint16(port),
        Community: community,
        Version:   gosnmp.SnmpVersion(version),
        Timeout:   2 * time.Second,
    }

    err := snmp.Connect()
    if err != nil {
        return "", err
    }
    defer snmp.Conn.Close()

    result, err := snmp.Get([]string{"1.3.6.1.2.1.1.5.0"}) // sysName OID
    if err != nil || len(result.Variables) == 0 {
        return "", err
    }

    return string(result.Variables[0].Value.([]byte)), nil
}

func discoverDevices(config Config) []Device {
    var devices []Device
    var wg sync.WaitGroup

    deviceChan := make(chan Device)

    for _, network := range config.Networks {
        ips, err := getIPsFromCIDR(network)
        if err != nil {
            continue
        }

        for _, ip := range ips {
            wg.Add(1)
            go func(ip string) {
                defer wg.Done()

                device := Device{IP: ip, Status: "down"}
                if checkICMP(ip) {
                    device.Status = "up"
                    if hostname, err := checkSNMP(ip, config.SNMP.Community, config.SNMP.Version, config.SNMP.Port); err == nil {
                        device.Hostname = hostname
                    }
                }
                deviceChan <- device
            }(ip)
        }
    }

    go func() {
        wg.Wait()
        close(deviceChan)
    }()

    for dev := range deviceChan {
        devices = append(devices, dev)
    }

    return devices
}

func main() {
    config, err := loadConfig("config.yml")
    if err != nil {
        panic(err)
    }

    ticker := time.NewTicker(time.Duration(config.PollInterval) * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            devices := discoverDevices(config)
            fmt.Printf("Discovered %d devices:\n", len(devices))
            for _, dev := range devices {
                fmt.Printf("- IP: %-15s Status: %-4s Hostname: %s\n", dev.IP, dev.Status, dev.Hostname)
            }
        }
    }
}