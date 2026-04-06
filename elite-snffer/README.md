# EliteSniffer v2.5

*A zero dependency network forensics tool for people who hate complexity.*

I built this because I’m apparently insane: **a full featured network forensics tool in a single Java file.**

No Maven. No Gradle. No external JARs. Just one `.java` file you can run with:

```bash
java EliteSniffer.java capture.pcap
```

It gives you:

- Streaming PCAP reading and filtering (works on multi gigabyte captures without blowing up your RAM)
- Clean VLAN + IPv6 extension header support
- TCP flags, HTTP request sniffing, DNS queries, TLS handshake detection, and **JA3 style TLS fingerprinting**
- A proper recursive filter parser with `and`/`or`/`not` and `src`/`dst` qualifiers
- Streaming export (slice out only the traffic you care about, packet by packet)
- Live capture via tcpdump with clean shutdown
- Nice colored output, summary stats, TLS/DNS hotspots, and heuristic alerts

All while staying ridiculously lightweight and self contained.

***

### Quick Start

Requires **Java 21+** — no build tools, no dependencies.

```bash
java EliteSniffer.java capture.pcap
```

***

### Quick Examples

```bash
java EliteSniffer.java capture.pcap
java EliteSniffer.java capture.pcap --filter "tcp and port 443" --dump
java EliteSniffer.java capture.pcap --filter "tcp and port 443" --json
java EliteSniffer.java --export capture.pcap tls-only.pcap --filter "tcp and port 443"
java EliteSniffer.java --live eth0 --count 100 --filter "udp and port 53"
```

***

### Features

- **Single Java source file** zero external dependencies.  
- **Fully streaming PCAP reader and writer** constant memory usage even on huge files.  
- **Correct magic number detection** for endianness and timestamp precision.  
- **Supports multiple link types**: Ethernet (1), NULL/Loopback (0), Linux Cooked/SLL (113).  
- **Automatic VLAN tag peeling** (802.1Q + QinQ).  
- **IPv6 extension header chain parsing**.  
- **TCP flag and port extraction**, **DNS sniffing**, **HTTP line sniffing**, **TLS handshake + JA3 fingerprinting**.  
- **Recursive descent filter parser** with `AND`/`OR`/`NOT` and direction qualifiers.  
- **Streaming filtered export** no in memory packet lists.  
- **Live capture bridge** to tcpdump with proper process management.  
- **Rich summary** with top talkers, TLS/DNS hotspots, and heuristic alerts.  
- **Safe, proper JSON output.**

***

### Filter Examples

```bash
--filter "tcp and port 443"
--filter "udp and port 53"
--filter "src host 8.8.8.8"
--filter "(tcp and port 80) or (udp and port 53)"
--filter "not icmp and src host 10.0.0.1"
```

***

### Notes

- Works with classic **PCAP** format (not PCAPNG).  
- Live mode requires `tcpdump` installed and capture permissions.  
- Tested on Java 21+ using `--source 21` shebang with modern Java features.

***

### Status

**Stable**

***

### Author

**Pithy Cyborg**

- 🌐 [https://pithycyborg.com](https://pithycyborg.com)  
- 📰 [https://pithycyborg.substack.com/subscribe](https://pithycyborg.substack.com/subscribe)  
- 🐦 [https://x.com/mrcomputersci](https://x.com/mrcomputersci)  
- 🐦 [https://x.com/pithycyborg](https://x.com/pithycyborg)

***

### License

MIT License © 2026 **Pithy Cyborg**

***

### Design Philosophy

EliteSniffer comes from a simple frustration: network forensics tools have gotten bloated.  
Everything wants dependencies, daemons, plugins, or GUIs the size of a small continent.  

I wanted something you could **drop on a box and run**. No setup, no build system, no excuses.  
Just pure code that understands packets, not frameworks.  

Writing it all in one Java source file is an experiment in purity:  
a reminder that you don’t need an ecosystem to build serious tools, just clarity and discipline.  
This project exists to prove that **simplicity scales.**
