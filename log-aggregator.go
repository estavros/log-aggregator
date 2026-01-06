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
)

// ---------------- ALERT RULES ----------------

// You can change or add more
var alertRules = []AlertRule{
	{
		Service:   "payments",
		Level:     "error",
		Contains:  "",
		Threshold: 3,
		Window:    60 * time.Second,
	},
	{
		Service:   "",
		Level:     "fatal",
		Contains:  "",
		Threshold: 1,
		Window:    10 * time.Second,
	},
}

// ---------------- SERVER ----------------

func runServer() {
	http.HandleFunc("/log", handleLog)
	http.HandleFunc("/logs", handleList)
	http.HandleFunc("/alerts", handleAlerts)

	fmt.Println("Log server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func handleLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var entry LogEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	entry.Timestamp = time.Now().UTC()

	processAlerts(entry)

	data, _ := json.Marshal(entry)

	fileMutex.Lock()
	defer fileMutex.Unlock()

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Could not open log file", 500)
		return
	}
	defer f.Close()

	f.WriteString(string(data) + "\n")
	w.WriteHeader(http.StatusCreated)
}

func handleList(w http.ResponseWriter, r *http.Request) {
	serviceFilter := r.URL.Query().Get("service")
	levelFilter := r.URL.Query().Get("level")
	sinceStr := r.URL.Query().Get("since")

	var since time.Time
	if sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err == nil {
			since = t
		}
	}

	fileMutex.Lock()
	defer fileMutex.Unlock()

	f, err := os.Open(logFile)
	if err != nil {
		w.Write([]byte("[]"))
		return
	}
	defer f.Close()

	var logs []LogEntry
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		var e LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}

		if serviceFilter != "" && e.Service != serviceFilter {
			continue
		}
		if levelFilter != "" && e.Level != levelFilter {
			continue
		}
		if !since.IsZero() && e.Timestamp.Before(since) {
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
		if rule.Contains != "" && !strings.Contains(entry.Message, rule.Contains) {
			continue
		}

		key := rule.Service + "|" + rule.Level + "|" + rule.Contains

		alertCounters[key] = append(alertCounters[key], now)

		// Remove old timestamps
		cutoff := now.Add(-rule.Window)
		var recent []time.Time
		for _, t := range alertCounters[key] {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		alertCounters[key] = recent

		if len(recent) >= rule.Threshold {
			triggerAlert(rule, entry, len(recent))
			alertCounters[key] = []time.Time{} // reset after firing
		}
	}
}

func triggerAlert(rule AlertRule, entry LogEntry, count int) {
	msg := fmt.Sprintf(
		"%s ALERT: %d %s logs from service=%s in %s\n",
		time.Now().Format(time.RFC3339),
		count,
		rule.Level,
		rule.Service,
		rule.Window,
	)

	fmt.Print("🚨 ", msg)

	f, _ := os.OpenFile(alertFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(msg)
}

// ---------------- CLI ----------------

func sendLog(service, level, msg string) {
	entry := LogEntry{
		Service: service,
		Level:   level,
		Message: msg,
	}

	data, _ := json.Marshal(entry)

	resp, err := http.Post("http://localhost:8080/log", "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Log sent:", resp.Status)
}

func listLogs(service, level, since string) {
	url := "http://localhost:8080/logs?"

	if service != "" {
		url += "service=" + service + "&"
	}
	if level != "" {
		url += "level=" + level + "&"
	}
	if since != "" {
		url += "since=" + since + "&"
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	var logs []LogEntry
	json.NewDecoder(resp.Body).Decode(&logs)

	for _, l := range logs {
		fmt.Printf("[%s] %-8s %-10s %s\n",
			l.Timestamp.Format(time.RFC3339),
			l.Level,
			l.Service,
			l.Message,
		)
	}
}

// ---------------- MAIN ----------------

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: server | send | list")
		return
	}

	switch os.Args[1] {
	case "server":
		runServer()

	case "send":
		sendCmd := flag.NewFlagSet("send", flag.ExitOnError)
		service := sendCmd.String("service", "", "service name")
		level := sendCmd.String("level", "", "log level")
		msg := sendCmd.String("msg", "", "message")
		sendCmd.Parse(os.Args[2:])

		if *service == "" || *level == "" || *msg == "" {
			fmt.Println("Missing flags")
			return
		}

		sendLog(*service, *level, *msg)

	case "list":
		listCmd := flag.NewFlagSet("list", flag.ExitOnError)
		service := listCmd.String("service", "", "filter by service")
		level := listCmd.String("level", "", "filter by level")
		since := listCmd.String("since", "", "RFC3339 timestamp")
		listCmd.Parse(os.Args[2:])

		listLogs(*service, *level, *since)

	default:
		fmt.Println("Unknown command")
	}
}
