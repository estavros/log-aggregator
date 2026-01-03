package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

const logFile = "logs.jsonl"

type LogEntry struct {
	Service   string    `json:"service"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

var fileMutex sync.Mutex

// ---------------- SERVER ----------------

func runServer() {
	http.HandleFunc("/log", handleLog)
	http.HandleFunc("/logs", handleList)

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
		json.Unmarshal(scanner.Bytes(), &e)
		logs = append(logs, e)
	}

	json.NewEncoder(w).Encode(logs)
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

func listLogs() {
	resp, err := http.Get("http://localhost:8080/logs")
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
		listLogs()

	default:
		fmt.Println("Unknown command")
	}
}
