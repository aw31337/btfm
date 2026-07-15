# DDoS Detection & Response
*Section 3 — DETECT | BTFM v2*

Linux command-line tools for identifying and responding to denial-of-service attacks.
All commands run on Ubuntu 20.04+ / RHEL 8+.

---

## Detect High Connection Volume (Port 80)

Count connections per source IP on port 80:
```bash
netstat -plane | grep :80 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

List connections to target IPs (server-side):
```bash
netstat -alpn | grep :80 | awk '{print $4}' | awk -F: '{print $(NF-1)}' | sort | uniq -c | sort -n
```

List connections by source IP:
```bash
netstat -alpn | grep :80 | awk '{print $5}' | awk -F: '{print $(NF-1)}' | sort | uniq -c | sort -n
```

Count connections by TCP state:
```bash
netstat -an | grep ":80" | awk '/tcp/ {print $6}' | sort | uniq -c
```

Total unique external IPs connected:
```bash
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n | wc -l
```

---

## Detect SYN Flood

Count SYN connections (high value = likely flood):
```bash
netstat -nap | grep SYN | wc -l
```

---

## Detect UDP DoS

List UDP connection sources:
```bash
netstat -nap | grep 'udp' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n
```

Check both TCP and UDP simultaneously:
```bash
netstat -anp | grep 'tcp\|udp' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n
```

---

## Identify Attacker with tcpdump

Capture traffic from a specific host:
```bash
tcpdump -c 1000 -n -i eth0 -p host <ATTACKER_IP>
```

---

## Block an Attacking IP (Null Route)

Add a null route to block an IP:
```bash
route add <ATTACKER_IP> reject
```

Verify the null route:
```bash
route -n | grep <ATTACKER_IP>
```

---

## Block with Firewall (CSF / APF)

```bash
csf -d <ATTACKER_IP> "DDoS block"
apf -d <ATTACKER_IP>
```

---

## Top Talkers from a pcap File

Show the top source IPs in a capture:
```bash
tcpdump -nnt -r <CAPTURE_FILE>.pcap | awk -F '.' '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -nr | head
```
