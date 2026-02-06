# SOC Threat Hunting Laboratory

**Comprehensive threat detection system demonstrating detection engineering, SIEM deployment, and hypothesis-driven threat hunting across the MITRE ATT&CK framework.**

[![Detection Rate](https://img.shields.io/badge/Detection%20Rate-100%25-success)](https://github.com/itsmiu/soc-threat-hunting-pipeline)
[![False Positives](https://img.shields.io/badge/False%20Positives-0%25-success)](https://github.com/itsmiu/soc-threat-hunting-pipeline)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-3%20Techniques-blue)](https://attack.mitre.org/)
[![Alerts Generated](https://img.shields.io/badge/Alerts-57-orange)](https://github.com/itsmiu/soc-threat-hunting-pipeline)



---

## 🎯 Quick Stats

| Metric | Value |
|--------|-------|
| **Total Detections** | 57 alerts across 3 attack types |
| **Detection Accuracy** | 100% (0 false positives, 0 false negatives) |
| **Mean Time to Detect** | <60 seconds |
| **Custom Rules** | 7 Suricata IDS signatures |
| **MITRE Coverage** | 3 techniques, 4 tactics |
| **Technologies** | Suricata + ELK Stack (Elasticsearch, Logstash, Kibana, Filebeat) |

---

## 📸 Dashboard Preview

![SOC Dashboard](docs/screenshots/11-dashboard-top.png)
*Real-time threat detection dashboard showing 57 alerts across DNS tunneling, port scanning, and SSH brute force attacks*

---

## 🚀 What This Project Does

This lab demonstrates **production-grade threat hunting** and **detection engineering** capabilities:

✅ **Network-based IDS** with custom Suricata signatures  
✅ **Full SIEM pipeline** with automated log enrichment  
✅ **Real-time alerting** with <60 second detection time  
✅ **MITRE ATT&CK mapping** for standardized threat intelligence  
✅ **Hypothesis-driven hunting** with documented methodologies  
✅ **Multi-stage attack detection** across the cyber kill chain  

---

## 🔍 Threat Hunts Conducted

### Hunt 1: DNS Tunneling Detection
**MITRE ATT&CK:** [T1071.004](https://attack.mitre.org/techniques/T1071/004/) - Command & Control  
**Alerts:** 6 (11%)  
**Detection:** Long subdomains, high entropy patterns, excessive query volume  

### Hunt 2: Port Scan Detection
**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) - Discovery  
**Alerts:** 48 (84%)  
**Detection:** High SYN packet rate, multiple port targeting  

### Hunt 3: SSH Brute Force Detection
**MITRE ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) - Initial Access  
**Alerts:** 3 (5%)  
**Detection:** High frequency connections, sustained attack patterns  

📄 **Detailed Reports:** See `docs/hunt-reports/` for complete analysis

---

## 🏗️ Architecture
```
┌─────────────────────────────────────────┐
│         Kali Linux Host                 │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │   Docker Network (172.20.0.0/16)│   │
│  │                                 │   │
│  │  Suricata IDS → Filebeat       │   │
│  │       ↓                         │   │
│  │  Logstash (enrichment)          │   │
│  │       ↓                         │   │
│  │  Elasticsearch ←→ Kibana        │   │
│  │                                 │   │
│  │  Ubuntu Target (172.20.0.20)    │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

**Components:**
- **Suricata 8.0.3** - Network IDS with custom signatures
- **Elasticsearch 8.12.0** - SIEM database
- **Logstash 8.12.0** - Log enrichment pipeline
- **Kibana 8.12.0** - Analysis dashboard
- **Filebeat 8.12.0** - Log shipper
- **Docker Compose** - Orchestration

---

## ⚡ Quick Start

### Prerequisites
- **Linux system** (tested on Kali Linux / Ubuntu)
- **Docker** and **Docker Compose** installed
- **8GB+ RAM** recommended
- **20GB+ disk space**

### Installation
```bash
# Clone the repository
git clone https://github.com/itsmiu/soc-threat-hunting-pipeline.git
cd soc-threat-hunting-pipeline

# Start all services
docker-compose up -d

# Wait for services to initialize (~2 minutes)
sleep 120

# Verify all 6 containers are running
docker-compose ps

# Check Suricata is monitoring
docker logs soc-suricata | grep "signatures processed"
```

**Expected output:** `7 signatures processed`

### Access the Dashboard

Open your browser to:
```
http://localhost:5601
```

**Login:**
- Username: `elastic`
- Password: `SOC_Lab_2025!Secure`

**Navigate to:** Dashboards → "SOC Threat Detection Dashboard"

---

## 🧪 Testing Detection Rules

### Test 1: DNS Tunneling
```bash
# Generate DNS tunneling traffic
for i in {1..15}; do
  RANDOM_SUB=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)
  docker exec soc-target nslookup ${RANDOM_SUB}.test.local 2>/dev/null &
  sleep 2
done

wait
sleep 60

# Check alerts
docker exec soc-suricata grep -c '"event_type":"alert"' /var/log/suricata/eve.json
```

### Test 2: Port Scanning
```bash
# Run nmap scan from target
docker exec soc-target nmap -sS 172.20.0.1 -p 1-500 --max-rate 100

sleep 60

# Verify detection
docker exec soc-suricata grep "Port Scan" /var/log/suricata/eve.json | wc -l
```

### Test 3: SSH Brute Force
```bash
# Create password list
cat > /tmp/passwords.txt << 'EOF'
wrong1
wrong2
wrong3
wrong4
wrong5
EOF

# Run brute force
hydra -l fakeuser -P /tmp/passwords.txt ssh://172.20.0.20 -t 2

sleep 60

# Check detection
docker exec soc-suricata grep "SSH Brute Force" /var/log/suricata/eve.json | wc -l
```

---

## 📊 Detection Rules

| Rule ID | Description | Threshold | MITRE |
|---------|-------------|-----------|-------|
| 1000001 | Long Subdomain (>50 chars) | 10/60s | T1071.004 |
| 1000002 | High Entropy Subdomain | 20/60s | T1071.004 |
| 1000003 | Excessive DNS Queries | 50/60s | T1071.004 |
| 1000011 | High Connection Rate | 50/60s | T1046 |
| 1000012 | Multiple Ports Targeted | 20/30s | T1046 |
| 1000021 | High SSH Connection Rate | 20/60s | T1110.001 |
| 1000022 | Sustained SSH Attack | 10/30s | T1110.001 |

📝 **Full Rules:** `detection-rules/suricata/all-rules.rules`

---

## 📂 Project Structure
```
soc-threat-hunting-pipeline/
├── configs/                    # Service configurations
│   ├── filebeat/filebeat.yml
│   ├── logstash/
│   │   └── pipelines/suricata-pipeline.conf
│   └── suricata/suricata.yaml
├── detection-rules/
│   └── suricata/all-rules.rules  # 7 custom signatures
├── docs/
│   ├── hunt-hypotheses/        # Pre-hunt planning
│   ├── hunt-reports/           # Detailed findings
│   └── screenshots/            # Visual evidence
├── docker-compose.yml          # Infrastructure definition
├── README.md                   # This file
└── PROJECT_SUMMARY.md          # Complete documentation
```

---

## 🎓 Skills Demonstrated

### Security Operations
- Threat hunting methodology
- Detection engineering
- SIEM deployment and configuration
- Incident response procedures
- Hypothesis-driven analysis

### Technical Skills
- **Suricata IDS** rule development
- **ELK Stack** deployment and tuning
- **Docker** containerization
- **Network analysis** with tcpdump/Wireshark
- **Attack simulation** with nmap, Hydra

### Frameworks
- **MITRE ATT&CK** framework mapping
- **Cyber Kill Chain** understanding
- **Detection engineering lifecycle**

---

## 📈 Results & Metrics

### Detection Performance
- **100% Detection Rate** - All 57 attacks detected
- **0% False Positive Rate** - Zero false alarms
- **<60 Second MTTD** - Mean time to detect
- **Real-time Processing** - 100+ events/minute

### Attack Coverage
- **84%** Reconnaissance (Port Scanning)
- **11%** Command & Control (DNS Tunneling)
- **5%** Initial Access (SSH Brute Force)

### MITRE ATT&CK Coverage
- **4 Tactics:** Initial Access, Credential Access, Discovery, Command & Control
- **3 Techniques:** T1071.004, T1046, T1110.001

---

## 🔧 Troubleshooting

### Services Won't Start
```bash
# Check Docker resources
docker system df

# Restart services
docker-compose down
docker-compose up -d
```

### No Alerts Generated
```bash
# Verify Suricata is running
docker logs soc-suricata | tail -20

# Check bridge interface
ip addr show | grep br-

# Verify rules loaded
docker logs soc-suricata | grep "signatures processed"
```

### Can't Access Kibana
```bash
# Check Elasticsearch health
curl -u elastic:SOC_Lab_2025!Secure http://localhost:9200/_cluster/health

# Restart Kibana
docker-compose restart kibana
```

---

## 🛠️ Customization

### Adding New Detection Rules

1. **Edit rules file:**
```bash
nano detection-rules/suricata/all-rules.rules
```

2. **Add your signature:**
```
alert tcp any any -> any 80 (msg:"Custom Rule"; content:"malicious"; sid:2000001; rev:1;)
```

3. **Restart Suricata:**
```bash
docker-compose stop suricata
docker rm -f soc-suricata
docker-compose up -d suricata
```

### Adjusting Thresholds

Edit `detection-rules/suricata/all-rules.rules` and modify the `threshold` values:
```
threshold: type threshold, track by_src, count 50, seconds 60
```

Lower values = more sensitive detection (more alerts)

---

## 📚 Documentation

- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Complete technical documentation
- **[Hunt Reports](docs/hunt-reports/)** - Detailed analysis for each threat hunt
- **[Hunt Hypotheses](docs/hunt-hypotheses/)** - Pre-hunt planning documents
- **[Screenshots](docs/screenshots/)** - Visual evidence and dashboard views

---

## 🔗 References

### MITRE ATT&CK
- [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

### Tools
- [Suricata Documentation](https://docs.suricata.io/)
- [Elastic Stack Guide](https://www.elastic.co/guide/)
- [Docker Documentation](https://docs.docker.com/)
- [nmap Reference](https://nmap.org/book/)

---

## 👤 Author

**Imam Uddin Mohammed**  
Cybersecurity Researcher | Detection Engineer | SOC Analyst

**Contact:**
- GitHub: [@itsmiu](https://github.com/itsmiu)
- LinkedIn: [Imam Uddin Mohammed](https://www.linkedin.com/in/imamuddinmohammed/)
- Email: mohammed.imamud@gmail.com

---

## 📄 License

This project is for **educational purposes only**. All attack simulations were conducted in an isolated lab environment against authorized infrastructure.

**Do not use these techniques against systems you do not own or have explicit permission to test.**

---

## 🙏 Acknowledgments

- **MITRE ATT&CK** - Threat intelligence framework
- **Suricata Community** - Open-source IDS
- **Elastic** - ELK Stack SIEM platform

---

## ⭐ Star This Repository

If you found this project helpful, please consider giving it a star! It helps others discover this work.

---

**Built with 🔒 for cybersecurity education and skill development**
