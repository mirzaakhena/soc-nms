package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	_ "github.com/mattn/go-sqlite3"
	probing "github.com/prometheus-community/pro-bing"
)

// Struktur data hasil scan
type ScanResult struct {
	IP           string
	Timestamp    time.Time
	Protocol     string
	Status       string
	ResponseTime float64
	SNMPData     string
}

// Logger kustom
type Logger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
}

// Membuat logger baru
func NewLogger() *Logger {
	return &Logger{
		infoLogger:  log.New(os.Stdout, "[INFO] ", log.Ldate|log.Ltime),
		errorLogger: log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile),
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	l.infoLogger.Printf(format, v...)
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
}

// Membuat dan menginisialisasi database
func initDB(dbPath string, logger *Logger) (*sql.DB, error) {
	logger.Info("Menginisialisasi database SQLite di %s", dbPath)
	
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Membuat tabel jika belum ada
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		protocol TEXT NOT NULL,
		status TEXT NOT NULL,
		response_time REAL,
		snmp_data TEXT
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, err
	}

	logger.Info("Database berhasil diinisialisasi")
	return db, nil
}

// Menyimpan hasil scan ke database
func saveResult(db *sql.DB, result ScanResult, logger *Logger) error {
	insertSQL := `
	INSERT INTO scan_results (ip, timestamp, protocol, status, response_time, snmp_data)
	VALUES (?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(insertSQL, result.IP, result.Timestamp, result.Protocol, result.Status, result.ResponseTime, result.SNMPData)
	if err != nil {
		logger.Error("Gagal menyimpan hasil scan untuk %s: %v", result.IP, err)
		return err
	}

	logger.Info("Hasil scan untuk %s (%s) berhasil disimpan", result.IP, result.Protocol)
	return nil
}

// Scan ICMP (ping) - Dimodifikasi berdasarkan kode teman Anda
func scanICMP(ip string, timeout time.Duration, logger *Logger) (bool, float64) {
	logger.Info("Memulai scan ICMP untuk %s", ip)
	
	pinger, err := probing.NewPinger(ip)
	if err != nil {
		logger.Error("Gagal membuat pinger untuk %s: %v", ip, err)
		return false, 0
	}
	
	pinger.Count = 1
	pinger.Timeout = timeout
	// Tidak menggunakan SetPrivileged agar lebih mirip dengan kode teman
	
	err = pinger.Run()
	if err != nil {
		logger.Error("Gagal menjalankan ping untuk %s: %v", ip, err)
		return false, 0
	}
	
	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 {
		responseTime := float64(stats.AvgRtt) / float64(time.Millisecond)
		logger.Info("ICMP berhasil untuk %s: response time %.2f ms", ip, responseTime)
		return true, responseTime
	}
	
	logger.Info("ICMP gagal untuk %s: tidak ada respons", ip)
	return false, 0
}

// Scan SNMP - Dimodifikasi berdasarkan kode teman Anda
func scanSNMP(ip string, community string, timeout time.Duration, logger *Logger) (string, float64, error) {
	logger.Info("Memulai scan SNMP untuk %s dengan community %s", ip, community)
	
	// Membuat objek SNMP baru seperti kode teman Anda
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
	}
	
	startTime := time.Now()
	err := snmp.Connect()
	if err != nil {
		logger.Error("Gagal koneksi SNMP ke %s: %v", ip, err)
		return "", 0, err
	}
	defer snmp.Conn.Close()
	
	// Gunakan OID yang sama dengan kode teman Anda (sysName)
	oids := []string{"1.3.6.1.2.1.1.5.0"}
	
	resp, err := snmp.Get(oids)
	if err != nil {
		logger.Error("Gagal mendapatkan data SNMP dari %s: %v", ip, err)
		return "", 0, err
	}
	
	if len(resp.Variables) == 0 {
		logger.Error("Tidak ada data SNMP yang dikembalikan dari %s", ip)
		return "", 0, fmt.Errorf("tidak ada data SNMP")
	}
	
	snmpData := ""
	hostname := ""
	for _, variable := range resp.Variables {
		snmpData += fmt.Sprintf("%s = %s\n", variable.Name, variable.Value)
		if variable.Value != nil {
			// Pastikan tipe konversi yang aman
			switch v := variable.Value.(type) {
			case []byte:
				hostname = string(v)
			case string:
				hostname = v
			default:
				hostname = fmt.Sprintf("%v", v)
			}
		}
	}
	
	responseTime := float64(time.Since(startTime)) / float64(time.Millisecond)
	logger.Info("SNMP berhasil untuk %s: response time %.2f ms", ip, responseTime)
	
	return hostname, responseTime, nil
}

// Memperluas CIDR menjadi list IP - Dimodifikasi berdasarkan kode teman Anda
func expandCIDR(network *net.IPNet, logger *Logger) ([]string, error) {
	var ipList []string
	
	// Mendapatkan IP awal
	ip := network.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("hanya mendukung IPv4")
	}
	
	// Konversi IP ke uint32 untuk memudahkan increment
	startIP := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	
	// Mendapatkan mask
	mask := network.Mask
	ones, _ := mask.Size()
	
	// Menghitung jumlah IP
	hostBits := 32 - ones
	numIPs := uint32(1 << hostBits)
	
	logger.Info("Memperluas CIDR menjadi %d IP", numIPs)
	
	// Memperluas range, tapi SKIP IP pertama (network) dan terakhir (broadcast)
	for i := uint32(1); i < numIPs-1; i++ {
		currentIP := startIP + i
		ip := net.IPv4(byte(currentIP>>24), byte(currentIP>>16), byte(currentIP>>8), byte(currentIP))
		ipList = append(ipList, ip.String())
	}
	
	return ipList, nil
}

// Memperluas range IP seperti "192.168.1.1-192.168.1.254" menjadi list IP
func expandIPRange(ipRange string, logger *Logger) ([]string, error) {
	// Memeriksa apakah input adalah CIDR
	if _, network, err := net.ParseCIDR(ipRange); err == nil {
		logger.Info("Memproses range CIDR: %s", ipRange)
		return expandCIDR(network, logger)
	}
	
	// Memeriksa apakah input adalah IP tunggal
	if ip := net.ParseIP(ipRange); ip != nil {
		logger.Info("IP tunggal terdeteksi: %s", ipRange)
		return []string{ipRange}, nil
	}
	
	// Memeriksa apakah input adalah range IP (format: start-end)
	var startIP, endIP string
	if _, err := fmt.Sscanf(ipRange, "%s-%s", &startIP, &endIP); err == nil {
		logger.Info("Range IP terdeteksi: %s ke %s", startIP, endIP)
		return expandIPStartEnd(startIP, endIP, logger)
	}
	
	return nil, fmt.Errorf("format IP tidak didukung: %s", ipRange)
}

// Memperluas range IP dari start ke end
func expandIPStartEnd(startIPStr, endIPStr string, logger *Logger) ([]string, error) {
	startIP := net.ParseIP(startIPStr).To4()
	endIP := net.ParseIP(endIPStr).To4()
	
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("format IP tidak valid")
	}
	
	// Konversi IP ke uint32
	start := uint32(startIP[0])<<24 | uint32(startIP[1])<<16 | uint32(startIP[2])<<8 | uint32(startIP[3])
	end := uint32(endIP[0])<<24 | uint32(endIP[1])<<16 | uint32(endIP[2])<<8 | uint32(endIP[3])
	
	if end < start {
		return nil, fmt.Errorf("IP akhir harus lebih besar dari IP awal")
	}
	
	numIPs := end - start + 1
	logger.Info("Memperluas range IP menjadi %d IP", numIPs)
	
	var ipList []string
	for i := start; i <= end; i++ {
		ip := net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
		ipList = append(ipList, ip.String())
	}
	
	return ipList, nil
}

// Scan network dengan metode yang direvisi
func scanNetwork(ipRange string, snmpCommunity string, timeout time.Duration, workers int, db *sql.DB, logger *Logger) {
	ipList, err := expandIPRange(ipRange, logger)
	if err != nil {
		logger.Error("Gagal mengurai range IP %s: %v", ipRange, err)
		return
	}
	
	logger.Info("Memulai scan network untuk %d IP dengan %d workers", len(ipList), workers)
	
	var wg sync.WaitGroup
	ipChan := make(chan string, len(ipList))
	
	// Menambahkan semua IP ke channel
	for _, ip := range ipList {
		ipChan <- ip
	}
	close(ipChan)
	
	// Memulai worker
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			logger.Info("Worker %d dimulai", id)
			
			for ip := range ipChan {
				// Scan ICMP dengan metode baru
				isOnline, responseTime := scanICMP(ip, timeout, logger)
				
				// Catat hasil ICMP
				icmpResult := ScanResult{
					IP:           ip,
					Timestamp:    time.Now(),
					Protocol:     "ICMP",
					Status:       "Failed",
					ResponseTime: 0,
				}
				
				if isOnline {
					icmpResult.Status = "Online"
					icmpResult.ResponseTime = responseTime
				}
				
				err := saveResult(db, icmpResult, logger)
				if err != nil {
					logger.Error("Worker %d: Gagal menyimpan hasil ICMP untuk %s: %v", id, ip, err)
				}
				
				// Jika ICMP berhasil, lanjutkan dengan SNMP
				if isOnline {
					hostname, snmpRespTime, err := scanSNMP(ip, snmpCommunity, timeout, logger)
					
					snmpResult := ScanResult{
						IP:           ip,
						Timestamp:    time.Now(),
						Protocol:     "SNMP",
						Status:       "Failed",
						ResponseTime: 0,
					}
					
					if err == nil {
						snmpResult.Status = "Online"
						snmpResult.ResponseTime = snmpRespTime
						snmpResult.SNMPData = fmt.Sprintf("Hostname = %s", hostname)
						logger.Info("Worker %d: Device ditemukan: %s, hostname: %s", id, ip, hostname)
					}
					
					err = saveResult(db, snmpResult, logger)
					if err != nil {
						logger.Error("Worker %d: Gagal menyimpan hasil SNMP untuk %s: %v", id, ip, err)
					}
				} else {
					logger.Info("Worker %d: Melewati SNMP untuk %s karena ICMP gagal", id, ip)
				}
			}
			
			logger.Info("Worker %d selesai", id)
		}(i)
	}
	
	wg.Wait()
	logger.Info("Scan network selesai")
}

func main() {
	// Flag command line
	dbPath := flag.String("db", "network_scan.db", "Path ke database SQLite")
	ipRange := flag.String("range", "192.168.1.1/24", "Range IP untuk di-scan (CIDR, single IP, atau range start-end)")
	snmpCommunity := flag.String("community", "public", "SNMP community string")
	timeoutSec := flag.Int("timeout", 2, "Timeout dalam detik")
	workers := flag.Int("workers", 10, "Jumlah worker paralel")
	logFile := flag.String("log", "", "Path ke file log (kosong untuk output ke console)")
	flag.Parse()
	
	// Setup logger
	logger := NewLogger()
	
	// Mengatur output log ke file jika diperlukan
	if *logFile != "" {
		file, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.Error("Gagal membuka file log %s: %v", *logFile, err)
			os.Exit(1)
		}
		defer file.Close()
		
		logger.infoLogger.SetOutput(file)
		logger.errorLogger.SetOutput(file)
	}
	
	logger.Info("Network Scanner dimulai")
	logger.Info("Konfigurasi: IP Range=%s, SNMP Community=%s, Timeout=%ds, Workers=%d, DB=%s",
		*ipRange, *snmpCommunity, *timeoutSec, *workers, *dbPath)
	
	// Inisialisasi database
	db, err := initDB(*dbPath, logger)
	if err != nil {
		logger.Error("Gagal menginisialisasi database: %v", err)
		os.Exit(1)
	}
	defer db.Close()
	
	// Mengatur timeout
	timeout := time.Duration(*timeoutSec) * time.Second
	
	// Memulai scan dengan metode yang direvisi
	scanNetwork(*ipRange, *snmpCommunity, timeout, *workers, db, logger)
	
	logger.Info("Network Scanner selesai")
}