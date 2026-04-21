# Security Operations Checklists

**Path:** `github.com/safeedges/infrasecurity/checklists/`  
**Document Version:** 1.3  
**Classification:** Operational Reference  
**Usage:** Pre-launch, Ongoing Operations, Incident Response  

---

## How to Use These Checklists

These checklists are derived from the full technical documentation across all domain READMEs in this repository. They are organized by operational phase and role. Each checklist item references the relevant detailed documentation.

Items marked **CRITICAL** represent controls whose absence was directly responsible for losses in the 2026 incidents. These items are non-negotiable minimum requirements for any protocol or infrastructure operator.

---

## Pre-Launch Security Review

This checklist must be completed before deploying any protocol to mainnet with user funds. It is not a substitute for a professional security audit; it is a minimum baseline.

### Smart Contract Review

1. All critical invariants are documented in writing before the first audit engagement  
2. **CRITICAL** Reentrancy guards are applied to all external-call-making state-changing functions  
3. Checks-effects-interactions pattern is enforced in all withdrawal and claim functions  
4. Arithmetic uses SafeMath or Solidity 0.8+ checked math throughout  
5. All external call return values are explicitly checked  
6. Flash loan attack vectors have been analyzed by at least one independent reviewer  
7. Two independent security audits have been completed with findings resolved  
8. Bug bounty program is live before mainnet deployment  

### Bridge and Cross-Chain Configuration

9. **CRITICAL** DVN configuration uses minimum 2-of-3 independent verifiers  
10. **CRITICAL** Each DVN queries minimum 3 independent RPC providers  
11. An independent cross-chain supply consistency monitor is deployed and tested  
12. Automated minting circuit breakers are deployed and the pause mechanism is tested end-to-end  
13. Emergency pause response time has been tested and is under 5 minutes from alert to execution  

### Oracle Configuration

14. Staleness checks are configured for all price feeds with asset-appropriate thresholds  
15. Sanity bounds are defined and configured for all supported assets  
16. New token listing policy defines minimum liquidity and history requirements  
17. Multi-source consensus is required before oracle data is used for collateral valuation  

### Governance Configuration

18. **CRITICAL** A timelock with minimum 48-hour delay is applied to all administrative functions  
19. **CRITICAL** The timelock delay can only be increased, never instantly decreased  
20. Emergency multisig requires minimum 3-of-5 signers with hardware wallets  
21. All multisig signers are confirmed on hardware wallets before mainnet deployment  
22. Public disclosure procedure for emergency actions is documented  

### Infrastructure Pre-Launch

23. All production server binaries have been integrity-hashed on a verified clean system  
24. File integrity monitoring is active and tested on all production nodes  
25. Network segmentation is in place between development and production environments  
26. Remote signer architecture is deployed for all validator keys  
27. On-call rotation is staffed with documented escalation procedures  

---

## Ongoing Operations Monthly Checklist

### Access Review

1. Review all individuals with multisig signing authority. Remove departed team members immediately.  
2. Verify all multisig signers have functional hardware wallets  
3. Review all API keys and secrets. Rotate any that are over 90 days old or have unknown usage.  
4. Review SSH authorized_keys files on all production servers  
5. Review sudo access grants on all production servers  

### External Engagement Review

6. **CRITICAL** Review all active integration conversations for anomalous patterns (extended trust-building, requests to share development tools, requests for inside access)  
7. Verify that no team member has installed external applications on devices with production access without the security team's knowledge  
8. Review GitHub repository access grants. Remove any external collaborators who are no longer active.  
9. Verify no new IDE extensions have been installed on machines with production access  

### Infrastructure Health

10. Verify file integrity monitoring is running and producing daily reports on all nodes  
11. Review audit logs for any anomalous privileged commands  
12. Verify AIDE database is current and was taken on a verified clean system  
13. Verify node binary hashes match expected values  
14. Test emergency pause mechanism in a staging environment  

### Protocol Health

15. Verify cross-chain supply consistency monitor is running and producing clean reports  
16. Review any governance proposals queued in the timelock  
17. Verify all oracle staleness alerts are correctly configured  
18. Review any anomalous transaction patterns identified by monitoring  

---

## Incident Response Checklist

When an anomaly is detected, follow this sequence. Time is critical.

### Immediate Actions (Target: Under 5 Minutes)

1. Do not discuss specifics on public channels. Use the private incident channel.  
2. Activate the incident command structure. Designate an incident commander.  
3. **CRITICAL** Assess whether emergency pause is required. If in doubt, pause.  
4. Execute emergency pause if asset risk is present or imminent  
5. Notify security contacts at all integrated protocols (they may need to freeze their own exposure)  
6. Preserve on-chain state: record block height, transaction hashes, and wallet addresses  
7. Capture infrastructure state: snapshots, logs, running process lists  

### Investigation Actions (Target: First 30 Minutes)

8. Identify the vector: contract logic, bridge verification, oracle, governance, or infrastructure  
9. Quantify total exposure: amount at risk, amounts already moved  
10. Identify attacker wallets and submit to exchange and bridge operator block lists  
11. Contact SEAL 911 (Ethereum security incident response), LayerZero if bridge is involved  
12. Contact ZachXBT and blockchain analytics firms (Chainalysis, Elliptic, TRM Labs) for on-chain tracing  
13. Contact law enforcement if loss exceeds regulatory reporting threshold  
14. Prepare public disclosure draft (do not publish until legal review if possible)  

### Recovery and Disclosure (First 48 Hours)

15. Conduct root cause analysis with technical details  
16. Publish public post-mortem with full technical details, no later than 72 hours after incident  
17. Verify attacker wallets are flagged on major centralized exchanges  
18. Implement immediate mitigations to close the exploited vector  
19. Engage independent security firms to verify the mitigation is effective  
20. Communicate with affected users about recovery plan  
21. Update security documentation and checklists based on new findings  

---

## New Integration Partner Vetting Checklist

Before granting any external team access to development resources, repositories, or shared applications:

1. Verify the legal entity exists and is registered in a known jurisdiction  
2. Verify on-chain history: do they operate a real protocol with real TVL?  
3. Verify team LinkedIn profiles are consistent and long-standing  
4. **CRITICAL** Never share development tools, repositories, or applications without prior security team approval  
5. Any code shared by the external party must be reviewed in an isolated sandbox VM before opening on any primary workstation  
6. Any applications shared by the external party must be reviewed by the security team before installation on any device  
7. Capital deposits from new integration partners should be monitored for unusual transaction patterns before granting further access  
8. Maintain written records of all integration partner communications  
9. If a request seems unusual (sharing of dev tools, requests for inside access, pressure to move fast), escalate to the security team immediately  

---

## Developer OPSEC Quick Reference

This card summarizes the OPSEC practices most relevant to the Drift Protocol attack vector.

```
DEVELOPER OPSEC QUICK REFERENCE
================================

BEFORE OPENING ANY EXTERNAL REPOSITORY:
  Open in isolated container:  docker run --rm -it --network=none ubuntu:24.04 bash
  Clone inside the container.  Do not clone to your primary workstation.
  Review manually before running any part of the code.

BEFORE INSTALLING ANY APPLICATION:
  Was it sent by an integration partner or external contact? 
  YES: Do not install without security team approval.
  NO:  Is it from an official app store or verified publisher?
       YES: Proceed with standard review.
       NO:  Do not install.

SIGNING MACHINE RULES:
  No internet browsing on signing machines.
  No IDE on signing machines.
  No external applications on signing machines.
  Transactions come in via QR code or verified USB only.
  
CONFERENCE OPSEC:
  No production access from conference WiFi.
  Use mobile hotspot or dedicated VPN if remote access is necessary.
  Do not accept USB drives, QR codes for apps, or repository invitations at events.
  Report any unusual requests for inside access to the security team.

IF YOU SUSPECT COMPROMISE:
  Isolate the affected machine immediately (disable network).
  Alert the security team before touching anything else.
  Do not attempt to investigate on the potentially compromised machine.
  Preserve logs and memory state if possible.
```
