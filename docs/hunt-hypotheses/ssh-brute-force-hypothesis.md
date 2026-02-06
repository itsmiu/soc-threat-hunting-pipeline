# SSH Brute Force Detection Hypothesis

## Date
02-05-2026

## Analyst
Imam Uddin Mohammed

## Hypothesis Statement
Adversaries attempt to gain initial access to systems by conducting brute force attacks against SSH services, trying multiple username/password combinations until successful authentication is achieved.

## MITRE ATT&CK Mapping
- **Tactic:** Initial Access (TA0001), Credential Access (TA0006)
- **Technique:** Brute Force (T1110)
- **Sub-technique:** Password Guessing (T1110.001)
- **Data Sources:** Authentication Logs, Application Logs

## Detection Logic
1. **Failed login attempts:** >10 failed SSH attempts in 60 seconds
2. **Multiple usernames:** Attempts against different user accounts
3. **Source IP pattern:** Single source targeting SSH port (22)
4. **Success after failures:** Successful login following failed attempts

## Expected Indicators
- High frequency of SSH connection attempts
- TCP connections to port 22
- Pattern: Multiple connection attempts from same source
- SSH protocol negotiation followed by authentication failure

## Data Sources Required
- Suricata flow logs (TCP port 22)
- SSH connection patterns
- Source IP reputation (optional)

## Success Criteria
- Detect brute force attack with >90% accuracy
- Alert within 30 seconds of attack initiation
- False positive rate <5%
- Identify attacking source IP

## Emulation Plan
1. Install hydra password cracker on Kali
2. Create small password wordlist
3. Execute brute force: `hydra -l root -P wordlist.txt ssh://172.20.0.20`
4. Generate 50+ failed login attempts
5. Verify Suricata detects connection pattern

## Expected Challenges
- Legitimate users may trigger alerts (forgotten passwords)
- Slow brute force attacks (<10 attempts/minute) may evade
- Need to distinguish between single typo vs sustained attack
- VPN/proxy users may have dynamic source IPs
