# Prior Art Search Report

**Subject:** DNS-Based AI Agent Traffic Steering via RPZ and MCP Server Directories
**Date:** March 17, 2026
**Prepared for:** Provisional Patent Application — Project Slipstream

---

## Executive Summary

This prior art search evaluates whether the core inventive concept — using DNS Response Policy Zones populated with Model Context Protocol server hostnames to transparently redirect AI agent traffic to a security inspection proxy — is anticipated or rendered obvious by existing art.

**Finding:** The specific combination of (1) MCP server directory harvesting + (2) RPZ generation + (3) AI security proxy steering appears **novel**. The individual component technologies (RPZ, AI inspection proxies, MCP) are separately well-established, but no prior art was found combining them in this manner.

---

## Search Methodology

- USPTO Patent Full-Text Database (patents.google.com)
- WIPO PATENTSCOPE
- IEEE Xplore, ACM Digital Library
- Web search for commercial products, academic papers, and technical blog posts
- ISC RPZ documentation and extension history
- IETF datatracker (DNS-related RFCs and drafts)
- MCP protocol documentation and security research (2024–2026)

### Search Terms Used

- "DNS Response Policy Zone" AND "AI" OR "machine learning" OR "agent"
- "RPZ" AND "proxy" AND "redirect" AND "inspection"
- "DNS firewall" AND "AI agent" OR "LLM" OR "language model"
- "Model Context Protocol" AND "security" AND "DNS"
- "MCP server" AND "traffic inspection" AND "proxy"
- "DNS steering" AND "AI security"
- "prompt injection" AND "network" AND "DNS"
- "AI agent" AND "traffic inspection" AND "proxy" AND "network level"

---

## Component 1: DNS Response Policy Zones (RPZ)

### Status: Well-established prior art (non-novel individually)

| Reference | Year | Relevance |
|---|---|---|
| Paul Vixie & Vernon Schryver, "DNS Response Policy Zones (DNS RPZ)" IETF Draft | 2010–2012 | Original specification of RPZ mechanism |
| ISC BIND 9.8 release notes | 2012 | First implementation of RPZ in production DNS software |
| US Patent 8,677,473 (Nominum) | 2014 | DNS-based policy enforcement; covers RPZ-adjacent mechanisms |
| US Patent 9,253,206 (Verisign) | 2016 | DNS query response modification for security |
| US Patent 11,032,127 (Cloudflare) | 2021 | DNS-layer traffic filtering and redirection |
| Infoblox DNS Firewall product | 2013–present | Commercial RPZ-based threat blocking |
| Cisco Umbrella (OpenDNS) | 2006–present | DNS-layer security enforcement, selective proxy |

**Analysis:** RPZ as a mechanism for DNS-based blocking and redirection is thoroughly covered by prior art. The use of RPZ to redirect traffic to a proxy IP (rather than simply returning NXDOMAIN) is also known — Cisco Umbrella's "selective proxy" feature (c. 2015) does exactly this for web traffic.

**Key distinction from invention:** Existing RPZ deployments target *malicious* domains. The invention applies RPZ to *legitimate but security-sensitive* domains (MCP servers) for *beneficial interception* rather than blocking.

---

## Component 2: AI/LLM Traffic Inspection Proxies

### Status: Emerging commercial art (novel category, 2023–2026)

| Reference | Year | Relevance |
|---|---|---|
| HiddenLayer AI Detection Platform | 2022–present | Inline proxy inspection for LLM prompt injection, model attacks |
| Robust Intelligence AI Firewall (now Cisco) | 2023–present | LLM output filtering and guardrails |
| Lakera Guard | 2023–present | Prompt injection detection proxy |
| NVIDIA NeMo Guardrails | 2023–present | Programmatic LLM guardrails (agent-side, not network proxy) |
| Aporia Guardrails | 2024–present | AI traffic monitoring |
| Prompt Security | 2024–present | Enterprise AI security proxy |
| Palo Alto AI Runtime Security | 2025 | Inline inspection for AI agent communications |

**Analysis:** AI security inspection proxies are a recognized product category. However, all identified products rely on **agent-side configuration** (SDK integration, environment variable configuration, or explicit proxy settings in AI agent frameworks). No product uses DNS to enforce routing to these proxies.

**Key distinction:** Network-level enforcement via DNS eliminates the agent-side configuration requirement and prevents bypass by non-compliant agents.

---

## Component 3: Model Context Protocol (MCP) and Its Security

### Status: New protocol (November 2024); security research sparse

| Reference | Year | Relevance |
|---|---|---|
| Anthropic, "Model Context Protocol" specification | Nov 2024 | Protocol definition |
| Palo Alto Unit 42, "MCP Attack Vectors" | Mar 2025 | Prompt injection via MCP; motivates need for inspection |
| Simon Willison, "MCP Prompt Injection" | Apr 2025 | Technical analysis of MCP vulnerabilities |
| Elastic Security Labs, "MCP Tools: Attack and Defense" | 2025 | Defense recommendations (all agent-side) |
| SecurityWeek, "Top 25 MCP Vulnerabilities" | 2025 | Vulnerability catalog |
| Research finding: 43% of MCP servers contain command injection flaws | 2025 | Quantifies scope of risk |

**Analysis:** MCP security is a recognized research area as of 2025. All identified defense recommendations are agent-side or server-side; **no prior work proposes network-level DNS enforcement** for MCP traffic.

---

## Component 4: DNS Steering to Inspection Proxies for Specific Service Categories

### Status: Partial prior art found; does not anticipate invention

| Reference | Year | Relevance |
|---|---|---|
| Cisco Umbrella "Selective Proxy" | ~2015 | RPZ-triggered proxy redirect for risky web domains |
| Zscaler "Cloud Proxy" with DNS redirect | 2017–present | DNS used to redirect web traffic to cloud proxy |
| Palo Alto Prisma Access with DNS control | 2019–present | DNS-triggered traffic forwarding to SASE platform |
| Blue Coat ProxySG with WCCP | ~2010 | DNS/WCCP-based web traffic redirection to SWG |
| Menlo Security Isolation Proxy | 2016–present | DNS-redirected isolation for web traffic |

**Analysis:** DNS-to-proxy redirection for web/URL traffic is known. However:
1. None of these systems target **AI agent traffic** or **AI-specific protocols** (MCP)
2. None perform automated enumeration of target service endpoints from protocol-specific directories
3. None address prompt injection, tool poisoning, or other AI-specific threat classes
4. The threat model differs fundamentally: existing systems protect users from malicious content on the web; this invention protects AI agents (and systems they control) from malicious instructions from AI servers

---

## Closest Prior Art Analysis

### US Patent 11,032,127 (Cloudflare, 2021) — "DNS-Layer Traffic Filtering"
**Relevance:** Covers DNS query interception and policy-based response modification.
**Distinction:** Does not address AI agents, MCP, or AI security inspection. No automated service directory component. No wildcard MCP-specific entries.

### Cisco Umbrella Selective Proxy
**Relevance:** Uses DNS redirect to route traffic to a security inspection proxy. Closest architectural analog.
**Distinction:** Applies to web/HTTP traffic, not AI agent protocols. Uses threat intelligence feeds of malicious domains, not legitimate-service-endpoint directories. No MCP awareness. No prompt injection inspection.

### ISC RPZ + Infoblox DNS Firewall
**Relevance:** The core RPZ mechanism and commercial deployment platform.
**Distinction:** Feed content is malware/phishing domains. No AI agent use case contemplated.

---

## Novelty Assessment by Claim

| Claim Element | Prior Art Found? | Anticipates? | Notes |
|---|---|---|---|
| DNS RPZ as mechanism | Yes (ISC, BIND 9.8, 2012) | No | Mechanism is known; specific application is novel |
| RPZ redirect to proxy (not NXDOMAIN) | Yes (Cisco Umbrella ~2015) | No | Web traffic use case only |
| Automated MCP server hostname harvesting | No | — | Novel |
| RPZ for AI agent traffic specifically | No | — | Novel |
| Wildcard RPZ entries for MCP hostnames | No | — | Novel |
| Delegated TLS to downstream proxy | Partial (Umbrella design pattern) | No | Not in AI context |
| Passthrough for non-AI traffic | No specific claim | — | Design property, not claimed |
| MCP directory as security feed | No | — | Novel |

---

## Freedom to Operate Assessment

**Risk areas requiring counsel review:**

1. **Cisco Umbrella selective proxy patents**: Cisco may hold broad claims on "DNS redirect to inspection proxy" patterns. The AI-specific application and MCP directory component should differentiate, but counsel should confirm.

2. **Cloudflare DNS filtering patents (US 11,032,127 and family)**: Cloudflare has broad claims in the DNS filtering space. Counsel should review claim scope.

3. **Infoblox RPZ-related IP**: As the intended deployment platform, alignment with Infoblox's existing patent portfolio is favorable but should be confirmed.

**Low risk areas:**
- The MCP directory harvesting component has no identified prior art
- The AI-specific traffic steering application has no identified prior art
- The combination of all elements has no identified prior art

---

## Recommendations

1. **File provisional immediately** to establish priority date (March 2026). MCP security is a rapidly evolving field; competitors may independently arrive at this approach.

2. **Broaden claims beyond RPZ** to cover DNS-based AI traffic steering generally (not just RPZ mechanism), to avoid design-around via alternative DNS policy mechanisms.

3. **File non-provisional within 12 months** with full claim development by patent counsel, particularly around the "automated AI service directory as DNS policy feed" concept.

4. **Monitor** Cisco, Palo Alto, Cloudflare, and Infoblox patent filings in the DNS + AI security intersection — this space will become crowded quickly.

5. **Consider trade secret protection** for the hostname filtering heuristics (shared platform blocklist, filtering logic) as a complement to patent protection.

---

*This prior art search is a good-faith assessment and does not constitute legal advice. A registered patent attorney should review prior to filing.*
*Prepared: March 17, 2026*
