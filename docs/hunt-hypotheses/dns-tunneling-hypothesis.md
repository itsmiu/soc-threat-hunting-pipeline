# DNS Tunneling Detection Hypothesis

## Date
02-04-2026

## Analyst
Imam Uddin Mohammed

## Hypothesis Statement
Adversaries may encode data in DNS queries to exfiltrate information or establish C2 channels. We expect to observe:
- DNS query subdomains exceeding 50 characters in length
- High entropy in subdomain strings (randomness indicating encoding)
- Query volumes exceeding 100 queries/minute to a single domain
- Unusual DNS query patterns (TXT records, non-standard record types)

## MITRE ATT&CK Mapping
- **Tactic:** Command and Control (TA0011)
- **Technique:** Application Layer Protocol: DNS (T1071.004)
- **Sub-technique:** DNS Tunneling
- **Data Sources:** Network Traffic (DNS queries)

## Detection Logic
1. **Subdomain length:** Query names > 50 characters
2. **Entropy threshold:** Shannon entropy > 4.0 (indicates Base64/hex encoding)
3. **Query frequency:** > 50 queries/minute to same domain
4. **Record types:** Excessive TXT or NULL record queries

## Data Sources Required
- Suricata DNS logs (dns.query, dns.rrname fields)
- Minimum 1 hour baseline of normal DNS traffic
- Network flow data for context

## Success Criteria
- Detect dnscat2 tunneling with > 90% accuracy
- False positive rate < 5%
- Alert within 60 seconds of tunnel establishment
- Provide actionable IOCs (domain, source IP, tunnel type)

## Emulation Plan
1. Install dnscat2 on Kali (client)
2. Run dnscat2 server in container
3. Establish tunnel with encoded subdomain pattern
4. Generate 200+ queries over 5 minutes
5. Verify Suricata detection triggers

## Expected Challenges
- Legitimate CDN subdomains can be long (need whitelist)
- Base64 in URLs for tracking pixels (filter by domain reputation)
- High DNS volume from busy networks (threshold tuning needed)

## Baseline Requirements
Before testing, collect:
- 24 hours of normal DNS traffic
- Whitelist of known-good long domains (CDNs, analytics)
- Average queries/minute per host (establish normal)
