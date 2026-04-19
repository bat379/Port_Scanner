# Port Scanner

This is a basic port scanner built using Python as part of learning cybersecurity and networking. The purpose of this project is to understand how systems communicate over networks and how open ports can reveal running services on a machine.

Instead of only studying theory, this project focuses on practical implementation to see how port scanning actually works.

---

## What this project does

This tool scans a target (either an IP address or a website) and checks which ports are open.

If a port is open, it usually means a service is running on that port, such as a web server or SSH.

---

## How it works

The scanner attempts to establish a connection to different ports on the target system.

* If the connection is successful, the port is considered open
* If the connection fails, the port is considered closed or filtered

---

## Technologies used

* Python
* socket module
* threading (optional, for faster scanning)

---

## How to run

1. Clone the repository
2. Open a terminal in the project folder
3. Run the script:

```bash
python scanner.py
```

If command-line arguments are supported:

```bash
python scanner.py -t example.com -p 1-100
```

---

## Why I made this

I am currently learning ethical hacking and cybersecurity, and I wanted to build a simple tool to better understand network behavior and security concepts through practice.

---

## Important note

This tool is intended for educational purposes only.
Do not use it on systems without proper permission.

---

## Future improvements

* Improve scanning speed using better threading
* Add service detection (e.g., HTTP, FTP)
* Create a simple graphical interface
* Save scan results to a file

---

## Final thoughts

This is a beginner-level project, but it provides a strong foundation for understanding networking and basic security testing. Building small tools like this makes learning much more practical and clear.

