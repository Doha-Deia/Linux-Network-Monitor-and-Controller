# Linux-Network-Monitor-and-Controller

A real-time Linux network monitoring and control system designed to visualize traffic activity, correlate network usage with processes and users, and provide interactive system-level controls through a lightweight web dashboard.

## Project Overview

This project was developed as a systems-level monitoring solution for Linux environments.

The system combines:

- **Rust backend** for packet capture, process monitoring, aggregation, correlation, and system control
- **HTML / CSS / JavaScript frontend** for live visualization and user interaction
- **Real-time communication** between backend and frontend

The goal is to demonstrate strong knowledge in:

- Operating systems
- Linux internals
- Networking
- Process management
- Real-time systems
- Software architecture

---

## Key Features

## Monitoring

- Real-time network upload/download tracking
- Active connections monitoring
- Per-process network usage detection
- Per-user traffic correlation
- Packet statistics and protocol breakdown

## Visualization  

- Live bandwidth charts
- Top network-consuming processes
- Top active users
- Connection tables
- Alerts dashboard
- Clean responsive interface

---

## System Architecture

```text
+---------------------------+
| HTML / JS Web Frontend    |
| Dashboard / Charts / UI   |
+-------------+-------------+
              |
       HTTP API / WebSocket
              |
+-------------v-------------+
|       Rust Backend        |
| Packet Capture Engine     |
| Traffic Aggregator        |
| Process Correlator        |
+-------------+-------------+
              |
      Linux Kernel / /proc
