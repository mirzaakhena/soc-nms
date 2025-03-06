package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	gosnmp "github.com/gosnmp/gosnmp"
	_ "github.com/mattn/go-sqlite3"
	probing "github.com/prometheus-community/pro-bing"
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

func initializeDatabase(dbPath string) (*sql.DB, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, err
    }

    // Membuat tabel jika belum ada
    query := `
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        hostname TEXT,
        status TEXT,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS topology (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        local_device_ip TEXT NOT NULL,
        remote_device_ip TEXT NOT NULL,
        local_port TEXT,
        remote_port TEXT,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
    );    
    `
    _, err = db.Exec(query)
    if err != nil {
        return nil, err
    }

    return db, nil
}

func saveDeviceToDB(db *sql.DB, device Device) error {
    query := `
    INSERT INTO devices (ip_address, hostname, status, last_updated)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(ip_address) DO UPDATE SET
        hostname = excluded.hostname,
        status = excluded.status,
        last_updated = excluded.last_updated;
    `
    _, err := db.Exec(query, device.IP, device.Hostname, device.Status)
    return err
}

func checkICMP(ip string) bool {
    pinger, err := probing.NewPinger(ip)
    if err != nil {
        log.Printf("Failed to create pinger for %s: %v", ip, err)
        return false
    }

    // Set timeout and count
    pinger.Timeout = 2 * time.Second
    pinger.Count = 1

    // Run the ping
    err = pinger.Run()
    if err != nil {
        log.Printf("Ping failed for %s: %v", ip, err)
        return false
    }

    stats := pinger.Statistics()
    return stats.PacketsRecv > 0
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

func discoverDevices(config Config, db *sql.DB) {
    var wg sync.WaitGroup

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

                    // Ambil informasi LLDP jika perangkat mendukung
                    lldpData, err := getLLDPInfo(ip, config.SNMP.Community, config.SNMP.Version, config.SNMP.Port)
                    if err == nil {
                        log.Printf("LLDP data for %s: %+v", ip, lldpData)

                        saveTopologyToDB(db, ip, lldpData["remoteSystemName"], "", lldpData["remotePortDesc"])
                    } else {
                        log.Printf("Failed to get LLDP info for %s: %v", ip, err)

                        // Jika LLDP tidak didukung, gunakan ARP
                        arpTable, err := getARPTable(ip, config.SNMP.Community, config.SNMP.Version, config.SNMP.Port)
                        if err == nil {
                            log.Printf("ARP table for %s: %+v", ip, arpTable)
                            inferConnectionsFromARP(db, arpTable)
                        } else {
                            log.Printf("Failed to get ARP table for %s: %v", ip, err)
                        }
                    }
                }

                // Simpan perangkat ke database
                if err := saveDeviceToDB(db, device); err != nil {
                    log.Printf("Error saving device %s to DB: %v", ip, err)
                }
            }(ip)
        }
    }

    wg.Wait()
}

func main() {
    // Inisialisasi database
    db, err := initializeDatabase("devices.db")
    if err != nil {
        log.Fatalf("Failed to initialize database: %v", err)
    }
    defer db.Close()

    // Konfigurasi jaringan (contoh statis, bisa diganti dengan loadConfig)
    config := Config{
        Networks: []string{"192.168.1.0/24"},
        SNMP: SNMPConfig{
            Community: "public",
            Version:   1, // SNMPv2c
            Port:      161,
        },
        PollInterval: 60, // Detik
    }

    // Polling berkala
    ticker := time.NewTicker(time.Duration(config.PollInterval) * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        discoverDevices(config, db)
        fmt.Println("Discovery completed and saved to database.")
    }
}

func saveTopologyToDB(db *sql.DB, localIP, remoteIP, localPort, remotePort string) error {
    query := `
    INSERT INTO topology (local_device_ip, remote_device_ip, local_port, remote_port, last_updated)
    VALUES (?, ?, ?, ?, datetime('now'))
    ON CONFLICT(local_device_ip, remote_device_ip) DO UPDATE SET
        local_port = excluded.local_port,
        remote_port = excluded.remote_port,
        last_updated = excluded.last_updated;
    `
    _, err := db.Exec(query, localIP, remoteIP, localPort, remotePort)
    return err
}

func getLLDPInfo(ip, community string, version, port int) (map[string]string, error) {
    snmp := gosnmp.GoSNMP{
        Target:    ip,
        Port:      uint16(port),
        Community: community,
        Version:   gosnmp.SnmpVersion(version),
        Timeout:   2 * time.Second,
    }

    err := snmp.Connect()
    if err != nil {
        return nil, err
    }
    defer snmp.Conn.Close()

    // Ambil OID lldpRemSysName dan lldpRemPortDesc
    oids := []string{"1.0.8802.1.1.2.1.4.1.1.5", "1.0.8802.1.1.2.1.4.1.1.8"}
    result, err := snmp.Get(oids)
    if err != nil {
        return nil, err
    }

    lldpData := make(map[string]string)
    for _, variable := range result.Variables {
        switch variable.Name {
        case "1.0.8802.1.1.2.1.4.1.1.5":
            lldpData["remoteSystemName"] = string(variable.Value.([]byte))
        case "1.0.8802.1.1.2.1.4.1.1.8":
            lldpData["remotePortDesc"] = string(variable.Value.([]byte))
        }
    }

    return lldpData, nil
}

func getARPTable(ip, community string, version, port int) (map[string]string, error) {
    snmp := gosnmp.GoSNMP{
        Target:    ip,
        Port:      uint16(port),
        Community: community,
        Version:   gosnmp.SnmpVersion(version),
        Timeout:   2 * time.Second,
    }

    err := snmp.Connect()
    if err != nil {
        return nil, err
    }
    defer snmp.Conn.Close()

    result, err := snmp.WalkAll("1.3.6.1.2.1.4.22.1")
    if err != nil {
        return nil, err
    }

    arpTable := make(map[string]string)
    for _, variable := range result {
        if strings.HasSuffix(variable.Name, ".1") { // IP Address
            ipAddr := string(variable.Value.([]byte))
            macAddr := ""
            for _, v := range result {
                if strings.HasPrefix(v.Name, strings.TrimSuffix(variable.Name, ".1")) && strings.HasSuffix(v.Name, ".2") {
                    macAddr = string(v.Value.([]byte))
                    break
                }
            }
            arpTable[ipAddr] = macAddr
        }
    }

    return arpTable, nil
}

func inferConnectionsFromARP(db *sql.DB, arpTable map[string]string) {
    macToIPs := make(map[string][]string)

    for ip, mac := range arpTable {
        if mac != "" {
            macToIPs[mac] = append(macToIPs[mac], ip)
        }
    }

    for mac, ips := range macToIPs {
        if len(ips) > 1 {
            log.Printf("MAC: %s connects the following IPs: %v", mac, ips)
            for i := 0; i < len(ips)-1; i++ {
                localIP := ips[i]
                remoteIP := ips[i+1]
                log.Printf("Saving topology: localIP=%s, remoteIP=%s", localIP, remoteIP)
                if err := saveTopologyToDB(db, localIP, remoteIP, "", ""); err != nil {
                    log.Printf("Error saving topology for MAC %s: %v", mac, err)
                }
            }
        } else if len(ips) == 1 {
            log.Printf("MAC: %s connects to single IP: %s", mac, ips[0])
            if err := saveTopologyToDB(db, ips[0], "", "", ""); err != nil {
                log.Printf("Error saving topology for MAC %s: %v", mac, err)
            }
        }
    }
}