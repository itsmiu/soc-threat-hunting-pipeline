# Port Scan Detection Hypothesis

## Date
02-05-2026

## Analyst
Imam Uddin Mohammed

## Hypothesis Statement
Adversaries conduct network reconnaissance by scanning multiple ports to identify running services and potential vulnerabilities. We expect to observe:
- High volume of connection attempts (>50/minute)
- Sequential or random port patterns
- Multiple destination ports from single source
- Short-lived connections (SYN packets without completion)

## MITRE ATT&CK Mapping
- **Tactic:** Discovery (TA0007)
- **Technique:** Network Service Discovery (T1046)
- **Sub-technique:** Port Scanning
- **Data Sources:** Network Traffic (Flow), Packet Capture

## Detection Logic
1. **Connection volume:** >50 new connections in 60 seconds
2. **Port diversity:** Connections to >10 different ports
3. **Incomplete connections:** High ratio of SYN packets without handshake completion
4. **Source pattern:** Single source targeting multiple destinations

## Data Sources Required
- Suricata flow logs
- TCP connection states
- Source/destination port pairs

## Success Criteria
- Detect nmap scan with >90% accuracy
- Alert within 30 seconds of scan initiation
- False positive rate <5%
- Identify scan type (SYN scan, full connect, etc.)

## Emulation Plan
1. Run nmap SYN scan from Kali against target: `nmap -sS 172.20.0.20`
2. Generate 1000+ connection attempts across common ports
3. Verify Suricata detects pattern
4. Test with slow scan to validate threshold

## Expected Challenges
- Legitimate services may have high connection rates (web servers)
- Load balancers generate many connections
- Need to distinguish between scans and normal traffic spikes
