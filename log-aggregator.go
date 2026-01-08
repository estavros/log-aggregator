package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const logFile = "logs.jsonl"
const alertFile = "alerts.log"

type LogEntry struct {
	Service   string    `json:"service"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type AlertRule struct {
	Service   string        `json:"service"`
	Level     string        `json:"level"`
	Contains  string        `json:"contains"`
	Threshold int           `json:"threshold"`
	Window    time.Duration `json:"window"`
}

var (
	fileMutex     sync.Mutex
	alertMutex    sync.Mutex
	alertCounters = map[string][]time.Time{}

	wsLogClients   = map[*websocket.Conn]bool{}
	wsAlertClients = map[*websocket.Conn]bool{}
	wsMutex        sync.Mutex
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// ---------------- ALERT RULES ----------------

var alertRules = []AlertRule{
	{Service: "payments", Level: "error", Threshold: 3, Window: 60 * time.Second},
	{Level: "fatal", Threshold: 1, Window: 10 * time.Second},
}

// ---------------- SERVER ----------------

func runServer() {
	http.HandleFunc("/log", handleLog)
	http.HandleFunc("/logs", handleList)
	http.HandleFunc("/alerts", handleAlerts)

	http.HandleFunc("/ws/logs", wsLogs)
	http.HandleFunc("/ws/alerts", wsAlerts)

	fmt.Println("Log server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

// ---------------- WebSockets ----------------

func wsLogs(w http.ResponseWriter, r *http.Request) {
	c, _ := upgrader.Upgrade(w, r, nil)
	wsMutex.Lock()
	wsLogClients[c] = true
	wsMutex.Unlock()
}

func wsAlerts(w http.ResponseWriter, r *http.Request) {
	c, _ := upgrader.Upgrade(w, r, nil)
	wsMutex.Lock()
	wsAlertClients[c] = true
	wsMutex.Unlock()
}

func broadcastLogs(e LogEntry) {
	wsMutex.Lock()
	defer wsMutex.Unlock()
	for c := range wsLogClients {
		c.WriteJSON(e)
	}
}

func broadcastAlert(msg string) {
	wsMutex.Lock()
	defer wsMutex.Unlock()
	for c := range wsAlertClients {
		c.WriteMessage(websocket.TextMessage, []byte(msg))
	}
}

// ---------------- HTTP ----------------

func handleLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var entry LogEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	entry.Timestamp = time.Now().UTC()

	processAlerts(entry)
	broadcastLogs(entry)

	data, _ := json.Marshal(entry)

	fileMutex.Lock()
	defer fileMutex.Unlock()

	f, _ := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(string(data) + "\n")

	w.WriteHeader(http.StatusCreated)
}

func handleList(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	level := r.URL.Query().Get("level")

	fileMutex.Lock()
	defer fileMutex.Unlock()

	f, _ := os.Open(logFile)
	defer f.Close()

	var logs []LogEntry
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		var e LogEntry
		json.Unmarshal(scanner.Bytes(), &e)

		if service != "" && e.Service != service {
			continue
		}
		if level != "" && e.Level != level {
			continue
		}
		logs = append(logs, e)
	}

	json.NewEncoder(w).Encode(logs)
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(alertRules)
}

// ---------------- ALERT ENGINE ----------------

func processAlerts(entry LogEntry) {
	alertMutex.Lock()
	defer alertMutex.Unlock()

	now := time.Now()

	for _, rule := range alertRules {
		if rule.Service != "" && entry.Service != rule.Service {
			continue
		}
		if rule.Level != "" && entry.Level != rule.Level {
			continue
		}

		key := rule.Service + rule.Level
		alertCounters[key] = append(alertCounters[key], now)

		cutoff := now.Add(-rule.Window)
		var recent []time.Time
		for _, t := range alertCounters[key] {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		alertCounters[key] = recent

		if len(recent) >= rule.Threshold {
			msg := fmt.Sprintf("🚨 %s %d %s logs from %s\n",
				time.Now().Format(time.RFC3339),
				len(recent),
				rule.Level,
				rule.Service,
			)

			fmt.Print(msg)
			broadcastAlert(msg)

			f, _ := os.OpenFile(alertFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			f.WriteString(msg)
			f.Close()

			alertCounters[key] = []time.Time{}
		}
	}
}

// ---------------- CLI ----------------

func sendLog(service, level, msg string) {
	entry := LogEntry{Service: service, Level: level, Message: msg}
	data, _ := json.Marshal(entry)
	http.Post("http://localhost:8080/log", "application/json", bytes.NewBuffer(data))
	fmt.Println("Sent")
}

func listLogs(service, level string) {
	url := "http://localhost:8080/logs?service=" + service + "&level=" + level
	resp, _ := http.Get(url)
	defer resp.Body.Close()

	var logs []LogEntry
	json.NewDecoder(resp.Body).Decode(&logs)
	for _, l := range logs {
		fmt.Println(l.Timestamp, l.Level, l.Service, l.Message)
	}
}

// ---------------- MAIN ----------------

func main() {
	if len(os.Args) < 2 {
		fmt.Println("server | send | list")
		return
	}

	switch os.Args[1] {
	case "server":
		runServer()
	case "send":
		sendCmd := flag.NewFlagSet("send", flag.ExitOnError)
		s := sendCmd.String("service", "", "")
		l := sendCmd.String("level", "", "")
		m := sendCmd.String("msg", "", "")
		sendCmd.Parse(os.Args[2:])
		sendLog(*s, *l, *m)
	case "list":
		listCmd := flag.NewFlagSet("list", flag.ExitOnError)
		s := listCmd.String("service", "", "")
		l := listCmd.String("level", "", "")
		listCmd.Parse(os.Args[2:])
		listLogs(*s, *l)
	}
}
