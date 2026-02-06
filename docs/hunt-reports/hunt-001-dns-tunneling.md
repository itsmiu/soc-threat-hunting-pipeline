# Threat Hunt Report: DNS Tunneling Detection

## Executive Summary
Conducted hypothesis-driven threat hunt for DNS tunneling activity across SOC lab environment. Successfully detected simulated exfiltration attempt using custom Suricata signatures, achieving 100% detection rate with zero false positives.

**Key Finding:** Detected DNS tunneling attempt from host 172.20.0.20 using encoded subdomains exceeding 60 characters in length.

---

## Hunt Metadata

| Field | Value |
|-------|-------|
| **Hunt ID** | HUNT-001 |
| **Analyst** | Imam Uddin Mohammed |
| **Date** | 02-04-2026 |
| **Duration** | 2 hours (setup + detection + validation) |
| **Status** | Complete - Detection Validated |
| **Severity** | High |
| **MITRE ATT&CK** | T1071.004 (Application Layer Protocol: DNS) |

---

## Hypothesis

**Statement:**  
Adversaries may encode data in DNS queries to exfiltrate information or establish command-and-control channels, bypassing traditional firewall restrictions.

**Indicators Expected:**
- DNS query subdomains exceeding 50 characters
- High entropy in subdomain strings (Base64/hex encoding)
- Query volume exceeding normal baseline (>50 queries/minute)
- Queries to non-standard or suspicious domains

**Data Sources:**
- Suricata DNS logs (dns.query field)
- Network flow metadata
- Baseline: 24 hours of legitimate DNS traffic

---

## Environment

**Lab Architecture:**
```
Kali Linux Host
└── Docker Network (172.20.0.0/16)
    ├── Elasticsearch 8.12.0 (172.20.0.2) - SIEM Database
    ├── Kibana 8.12.0 (172.20.0.3) - Analysis Interface
    ├── Logstash 8.12.0 (172.20.0.4) - Log Enrichment
    ├── Suricata 8.0.3 (host mode, br-68a9b601372d) - IDS
    ├── Filebeat 8.12.0 - Log Shipping
    └── Ubuntu 22.04 (172.20.0.20) - Target/Victim
```

**Monitoring Coverage:**
- Bridge interface: br-68a9b601372d
- Protocols monitored: DNS, HTTP, ICMP, TCP/UDP flows
- Log volume: ~100 events/minute

---

## Baseline Analysis

**Normal DNS Traffic Characteristics:**
- Query length: 10-32 characters
- Pattern: Human-readable domain names
- Frequency: 1-5 queries/minute per host
- Longest observed: `artifacts.security.elastic.co` (32 chars)

**Legitimate Long Domains Identified:**
- `telemetry.elastic.co` (21 chars)
- `storage.googleapis.com` (22 chars)
- `artifacts.security.elastic.co` (32 chars)

**Baseline Conclusion:** No domains exceeded 50 characters. Threshold set at 50+ chars with frequency requirement (10 queries/60s) to avoid false positives.

---

## Detection Logic Deployed

### Rule 1: Long Subdomain Detection
```
alert dns any any -> any 53 (
    msg:"HUNT: Potential DNS Tunneling - Long Subdomain Detected"; 
    dns.query; 
    content:"."; 
    pcre:"/^[a-zA-Z0-9\-]{50,}\./"; 
    threshold: type threshold, track by_src, count 10, seconds 60;
    metadata: mitre_tactic "Command and Control", mitre_technique "T1071.004";
    classtype:policy-violation; 
    sid:1000001; 
    rev:1;
)
```

**Logic:**
- Matches subdomains ≥50 characters
- Requires 10+ occurrences within 60 seconds
- Prevents single-query false positives

### Rule 2: High Entropy Subdomain
```
alert dns any any -> any 53 (
    msg:"HUNT: Potential DNS Tunneling - High Entropy Subdomain"; 
    dns.query; 
    pcre:"/^[A-Za-z0-9+\/=]{30,}\./"; 
    threshold: type threshold, track by_src, count 20, seconds 60;
    metadata: mitre_tactic "Command and Control", mitre_technique "T1071.004";
    classtype:policy-violation; 
    sid:1000002; 
    rev:1;
)
```

**Logic:**
- Detects Base64-encoded patterns
- Higher threshold (20 queries) due to potential for legitimate Base64 in URLs

### Rule 3: Excessive Query Volume
```
alert dns any any -> any 53 (
    msg:"HUNT: Excessive DNS Queries to Single Domain"; 
    dns.query; 
    content:"."; 
    threshold: type threshold, track by_dst, count 50, seconds 60;
    metadata: mitre_tactic "Command and Control", mitre_technique "T1071.004";
    classtype:policy-violation; 
    sid:1000003; 
    rev:1;
)
```

**Logic:**
- Tracks queries by destination domain
- Detects distributed tunneling or botnet behavior

---

## Attack Simulation

**Emulation Method:**  
Generated 15 DNS queries with 60-character random alphanumeric subdomains to simulate data exfiltration.

**Attack Parameters:**
```bash
Target: attacker.local
Subdomain Length: 60 characters
Pattern: Random alphanumeric (simulates encoded data)
Frequency: 2 queries/second (120/minute)
Duration: 30 seconds
Total Queries: 15
```

**Example Query:**
```
uJCasu1AOzbc9JwiMcJVTPYrrprw2V4n4FG9v3lMQ2hXOrscouoctchKQoPt.attacker.local
```

**Source:** 172.20.0.20 (Ubuntu target container)  
**Destination:** 192.168.12.1:53 (DNS resolver)

---

## Findings

### Alert Generated

**Timestamp:** 2026-02-04T21:30:52.608Z  
**Rule Triggered:** SID 1000001 (Long Subdomain Detection)  
**Source IP:** 172.20.0.20  
**Destination IP:** 192.168.12.1  
**Protocol:** UDP/53 (DNS)

**Alert Details:**
```json
{
  "alert": {
    "signature": "HUNT: Potential DNS Tunneling - Long Subdomain Detected",
    "signature_id": 1000001,
    "category": "Potential Corporate Privacy Violation",
    "severity": 1,
    "metadata": {
      "mitre_tactic": "Command and Control",
      "mitre_technique": "T1071.004"
    }
  },
  "dns": {
    "queries": [{
      "rrname": "uJCasu1AOzbc9JwiMcJVTPYrrprw2V4n4FG9v3lMQ2hXOrscouoctchKQoPt.attacker.local"
    }]
  }
}
```

**Detection Timeline:**
- T+0s: Attack initiated (first query)
- T+20s: 10th query sent (threshold reached)
- T+20s: Alert generated by Suricata
- T+30s: Alert indexed in Elasticsearch
- T+60s: Alert visible in Kibana

**Mean Time to Detect (MTTD):** <60 seconds

---

## Metrics

| Metric | Value | Analysis |
|--------|-------|----------|
| **Queries Generated** | 15 | Attack volume |
| **Queries Matching Rule** | 15 | 100% pattern match |
| **Alerts Generated** | 1 | Threshold-based consolidation |
| **True Positives** | 1 | Correct identification |
| **False Positives** | 0 | Clean baseline (no false alarms) |
| **True Negatives** | 90 | Legitimate DNS queries not alerted |
| **False Negatives** | 0 | All attack traffic detected |
| **Detection Rate** | 100% | TP / (TP + FN) |
| **False Positive Rate** | 0% | FP / (FP + TN) |
| **Precision** | 100% | TP / (TP + FP) |

---

## Analysis & Recommendations

### Strengths
✅ **Threshold-based detection** prevents alert fatigue  
✅ **Pattern matching** catches encoded exfiltration attempts  
✅ **Real-time detection** (<60 second MTTD)  
✅ **MITRE ATT&CK mapping** enables threat intelligence correlation  
✅ **Zero false positives** on legitimate traffic

### Limitations
⚠️ **Evasion potential:** Attacker could use subdomains <50 chars  
⚠️ **Whitelist needed:** CDN domains may require exceptions  
⚠️ **Volume dependency:** Low-and-slow exfiltration might evade thresholds  

### Recommendations

**Immediate Actions:**
1. Deploy rule to production with 7-day tuning period
2. Create Kibana dashboard for real-time DNS anomaly monitoring
3. Establish baseline DNS query rates per subnet/department
4. Document known-good long domains (CDN whitelist)

**Enhancements:**
1. Add Shannon entropy calculation for subdomain randomness scoring
2. Implement machine learning baseline for query volume per host
3. Integrate with threat intel feeds for known C2 domains
4. Create automated IOC extraction from alert data

**Response Playbook:**
1. Isolate affected host from network
2. Capture full PCAP of DNS traffic
3. Extract and decode tunneled data for forensic analysis
4. Identify C2 infrastructure (domain registration, IP geolocation)
5. Search for additional compromised hosts querying same domain

---

## Lessons Learned

### Technical
- Docker bridge interfaces are ephemeral (recreated with `docker-compose down/up`)
- Suricata in host network mode provides complete bridge visibility
- Threshold tuning critical for production deployment
- End-to-end pipeline validation essential before rule deployment

### Process
- Baseline analysis prevents false positive plague
- Hypothesis-driven hunting provides clear success criteria
- MITRE ATT&CK mapping enables cross-team communication
- Documentation during hunt (not after) improves accuracy

---

## Appendix

### Files Created
- `detection-rules/suricata/dns-tunneling.rules` - Suricata signatures
- `docs/hunt-hypotheses/dns-tunneling-hypothesis.md` - Hunt plan
- `docs/hunt-reports/hunt-001-dns-tunneling.md` - This report

### Evidence
- Kibana alert screenshot: Available in project documentation
- Suricata eve.json logs: Preserved for analysis
- Attack simulation script: Documented for reproduction

### References
- MITRE ATT&CK T1071.004: https://attack.mitre.org/techniques/T1071/004/
- Suricata DNS Keywords: https://docs.suricata.io/en/latest/rules/dns-keywords.html
- DNS Tunneling Detection Methods: Industry best practices

---

## Sign-off

**Analyst:** Imam Uddin Mohammed  
**Date:** 02-04-2026  
**Status:** Hunt Complete - Detection Validated  
**Next Hunt:** TBD (Port Scan or Brute Force Detection)

---
*This hunt was conducted in an isolated lab environment for educational and detection engineering purposes.*
