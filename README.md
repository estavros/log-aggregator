# Log Aggregator (Go)

A minimal log aggregation system written in Go.  
It provides an HTTP server for collecting structured logs and a CLI tool for sending and listing them.

Logs are stored in an append-only JSON file and can be queried through a simple API or the command line.

---

## Features

- HTTP-based log ingestion  
- Structured JSON logs  
- Append-only file storage (`logs.jsonl`)  
- CLI for sending and listing logs  
- Concurrent-safe writes  

---

## Getting Started

### 1. Start the server

```bash
go run main.go server
```

The server will start on:

```
http://localhost:8080
```

---

### 2. Send logs

In another terminal:

```bash
go run main.go send --service=auth --level=info --msg="user logged in"
go run main.go send --service=payments --level=error --msg="card declined"
```

---

### 3. List logs

```bash
go run main.go list
```

Example output:

```
[2026-01-03T18:00:00Z] info     auth       user logged in
[2026-01-03T18:01:10Z] error    payments   card declined
```

---

## HTTP API

### POST /log

Send a log entry:

```json
{
  "service": "auth",
  "level": "error",
  "message": "invalid password"
}
```

The server adds a timestamp automatically.

---

### GET /logs

Returns all stored logs:

```json
[
  {
    "service": "auth",
    "level": "error",
    "message": "invalid password",
    "timestamp": "2026-01-03T18:00:00Z"
  }
]
```

---

## Data Format

Logs are stored in `logs.jsonl` using the JSON Lines format (one JSON object per line):

```
{"service":"auth","level":"error","message":"bad password","timestamp":"2026-01-03T18:00:00Z"}
```

This format is:
- Append-only  
- Crash-safe  
- Easy to parse and stream  

---

## Why this project

This project is meant to be a small but realistic backend system.  
It demonstrates how services send logs to a central server using HTTP and how those logs can be stored and queried efficiently.
