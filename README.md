
# SafeEdges Infrastructure Security Repository

**Repository:** `github.com/safeedges/infrasecurity`  
**Maintainer:** SafeEdges Security Research Division  


---

## Context and Motivation

This repository was compiled in direct response to the coordinated wave of state-sponsored attacks against Web3 infrastructure observed in Q1 and Q2 2026. The incidents analyzed include the Drift Protocol compromise on April 1 ($286 million, Solana), the KelpDAO rsETH bridge exploit on April 18 ($292 million, LayerZero), and the broader ecosystem contagion that erased over $13 billion in total value locked across DeFi within 48 hours of the KelpDAO incident.

Both attacks were attributed with medium-to-high confidence to DPRK-affiliated threat actors operating under the Lazarus Group umbrella, specifically the TraderTraitor and AppleJeus units of UNC4736. The tactics, techniques, and procedures observed across both incidents demonstrate a fundamental shift in adversary capability: from opportunistic smart contract exploitation to long-cycle, infrastructure-layer, and human-targeting operations that defeat code-level audits entirely.

The purpose of this repository is to provide protocol teams, infrastructure operators, and DApp developers with an authoritative, operationally grounded security posture framework that addresses the full attack surface exposed by these and similar incidents.

---

## Repository Structure

```
safeedges/infrasecurity/
    README.md                        This file
    incident-analysis/
        README.md                    2026 incident breakdown and TTPs
    protocol-security/
        README.md                    Smart contract, bridge, and governance security
    infrastructure-security/
        README.md                    RPC node, validator, and network security
    os-security/
        README.md                    Operating system hardening for Web3 operators
    dapp-security/
        README.md                    Frontend, wallet integration, and OPSEC
    checklists/
        README.md                    Operational checklists for all domains
```

---

## Threat Landscape Summary (April 2026)

The following table summarizes confirmed or attributed major incidents in 2026 through April 21.

| Protocol       | Date          | Loss        | Vector                             | Attribution      |
|----------------|---------------|-------------|-------------------------------------|------------------|
| Drift Protocol | April 1, 2026 | $286 million | Social engineering, durable nonce, oracle manipulation, governance takeover | DPRK Lazarus / UNC4736 |
| KelpDAO rsETH  | April 18, 2026| $292 million | RPC endpoint compromise, DVN poisoning, fabricated burn event | DPRK Lazarus / TraderTraitor |

Total confirmed losses in these two incidents alone: approximately $578 million.  
DeFi TVL reduction in the 48 hours following KelpDAO: $13.21 billion.  
Protocols forced to freeze or pause operations as a result of KelpDAO contagion: at least 9 confirmed, including Aave V3, SparkLend, Fluid, Compound, Euler, Curve Finance, and Ethena.

---

## Attack Pattern Evolution

The adversaries responsible for these incidents are no longer exploiting integer overflows or reentrancy bugs. The pattern that emerges from both 2026 incidents is:

**Phase 1 (Reconnaissance and Insertion, months 1 to 6):**  
Build a credible professional identity. Attend real conferences. Deposit real money. Ask real technical questions. Establish documented trust with target team members over multiple in-person and digital touchpoints.

**Phase 2 (Access Establishment):**  
Deliver malware via trusted channels. In Drift's case: a GitHub repository presented as a frontend tool, and a TestFlight application presented as a wallet product. A known VSCode and Cursor vulnerability enabled silent code execution upon file open. In KelpDAO's case: compromise of RPC endpoints feeding the DVN, combined with DDoS of healthy endpoints to force routing through poisoned nodes.

**Phase 3 (Pre-positioning, weeks 1 to 3 before execution):**  
Pre-sign transactions. Create dormant accounts. Deploy auxiliary tokens. Test transaction routing. Drift's attackers deployed the CVT token on March 12, three weeks before execution, funded from Tornado Cash on March 11.

**Phase 4 (Execution, minutes):**  
Drift: 12 minutes to drain $286 million across 31 withdrawal transactions touching nearly 20 vaults.  
KelpDAO: Minted unbacked rsETH via fabricated burn events, then used stolen tokens as collateral on Aave to borrow WETH, creating approximately $195 million in additional bad debt.

**Phase 5 (Laundering):**  
Rapid cross-chain dispersal. Conversion to ETH. Distribution across hundreds of fresh wallets. Routing through Thorchain, Umbra, and other privacy-preserving protocols.

---

## How to Use This Repository

Each subdirectory contains a dedicated README with the following structure:

1. Threat model specific to that domain
2. Attack surface analysis grounded in confirmed incident data
3. Mermaid flowcharts illustrating secure architecture and decision flows
4. Code samples demonstrating secure implementation patterns
5. Operational checklist for that domain
6. References to relevant standards, audits, and post-mortem reports

Start with `incident-analysis/README.md` to understand the threat actor TTPs.  
Then proceed to the domain most relevant to your operational role.  
Use `checklists/README.md` for ongoing operational verification.

---

## Document Standards

All documents in this repository adhere to the following conventions:

1. No unsubstantiated claims. Every statement about attack mechanics is sourced from confirmed post-mortem data, on-chain analysis, or established security research.
2. Code samples are annotated with the specific vulnerability or control they demonstrate.
3. Flowcharts use Mermaid syntax and render natively in GitHub.
4. Severity classifications follow the CVSS v3.1 framework where applicable.
5. Controls are mapped to the NIST Cybersecurity Framework 2.0 functions: Identify, Protect, Detect, Respond, Recover.
