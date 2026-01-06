# Log Aggregator

A minimal log aggregation system written in Go.  
It provides an HTTP server for collecting structured logs and a CLI tool for sending and querying them.

Logs are stored in an append-only JSON file and can be filtered by service, level, and time through both the API and the CLI.

---

## Features

- HTTP-based log ingestion  
- Structured JSON logs  
- Append-only file storage (logs.jsonl)  
- CLI for sending and listing logs  
- Concurrent-safe writes  
- Filtering by service, level, and timestamp  

---

## Getting Started

### 1. Start the server

go run main.go server

The server will start on:

http://localhost:8080

---

### 2. Send logs

In another terminal:

go run main.go send --service=auth --level=info --msg="user logged in"  
go run main.go send --service=payments --level=error --msg="card declined"  
go run main.go send --service=auth --level=error --msg="invalid password"

---

### 3. List all logs

go run main.go list

Example output:

[2026-01-03T18:00:00Z] info     auth       user logged in  
[2026-01-03T18:01:10Z] error    payments   card declined  
[2026-01-03T18:02:45Z] error    auth       invalid password  

---

### 4. Filter logs (CLI)

go run main.go list --service auth  
go run main.go list --level error  
go run main.go list --service auth --level error  
go run main.go list --since 2026-01-03T18:01:00Z  
go run main.go list --service auth --level error --since 2026-01-03T18:01:00Z  

The --since flag uses RFC3339 timestamps.

---

## HTTP API

POST /log

Send a log entry:

{
  "service": "auth",
  "level": "error",
  "message": "invalid password"
}

The server adds a timestamp automatically.

---

GET /logs

Returns all stored logs:

[
  {
    "service": "auth",
    "level": "error",
    "message": "invalid password",
    "timestamp": "2026-01-03T18:00:00Z"
  }
]

---

GET /logs with filters

You can filter logs using query parameters:

/logs?service=auth  
/logs?level=error  
/logs?service=auth&level=error  
/logs?since=2026-01-03T18:01:00Z  
/logs?service=auth&level=error&since=2026-01-03T18:01:00Z  

Example response:

[
  {
    "service": "auth",
    "level": "error",
    "message": "invalid password",
    "timestamp": "2026-01-03T18:02:45Z"
  }
]

---

## Alerts

The server can automatically monitor logs and trigger alerts based on configurable rules.

### Default Rules
- 3 or more `error` logs from the `payments` service within 1 minute trigger an alert.
- Any `fatal` log triggers an immediate alert.

### How Alerts Work
- Alerts are printed to the console.
- Alerts are written to `alerts.log`.
- Rules are evaluated in real-time as logs are ingested.

### View Active Rules
You can see the configured alert rules via the API:

---

## Data Format

Logs are stored in logs.jsonl using the JSON Lines format (one JSON object per line):

{"service":"auth","level":"error","message":"bad password","timestamp":"2026-01-03T18:00:00Z"}

This format is:

- Append-only  
- Crash-safe  
- Easy to parse and stream  
- Efficient for filtering and indexing  

---

## Why this project

This project is meant to be a small but realistic backend system.  
It demonstrates how services send logs to a central server using HTTP, how logs are stored safely on disk, and how they can be queried and filtered efficiently using both an API and a CLI.

It can serve as a foundation for building more advanced systems such as log search engines, monitoring pipelines, alerting systems, and distributed tracing backends.
