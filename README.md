# Slipstream

**MCP Server RPZ Harvester — DNS-based AI Traffic Steering for Security Inspection**

## What This Is

Slipstream harvests known public MCP (Model Context Protocol) server hostnames from multiple sources and generates a DNS Response Policy Zone (RPZ) file that steers AI agent traffic to a security inspection proxy (e.g., HiddenLayer).

When loaded into an Infoblox DNS Firewall (or any BIND/Unbound RPZ-capable resolver), DNS queries to known MCP server hostnames are answered with the proxy IP instead of the real address — transparently redirecting AI agent connections through the proxy for prompt injection detection, data loss prevention, and behavioral analysis.

The proxy is responsible for TLS termination, inspection, and forwarding. Incorrectly classified non-AI traffic may be disrupted unless the proxy is explicitly configured to handle it safely.

## Architecture

```
AI Agent → DNS query for mcp.example.com
         ↓
   DNS Firewall (RPZ loaded)
         ↓
   Returns: proxy-ip (HiddenLayer)
         ↓
   AI Agent connects to HiddenLayer proxy
         ↓
   HiddenLayer inspects / forwards to real MCP server
```

## Sources

The harvester pulls from:
1. **Official MCP Registry** — `registry.modelcontextprotocol.io` (unauthenticated REST API)
2. **Anthropic reference servers** — `github.com/modelcontextprotocol/servers` (GitHub API)
3. **awesome-mcp-servers** — `github.com/punkpeye/awesome-mcp-servers` (GitHub raw markdown)
4. **best-of-mcp-servers** — `github.com/tolkonepiu/best-of-mcp-servers` (GitHub API)
5. **Smithery registry** — `smithery.ai` (API key optional, falls back to scrape)

Results are merged, deduplicated, and filtered (localhost, IPs, and shared hosting platforms are excluded).

## Usage

Requires **Python 3.10 or newer** (`str | None` type annotations are evaluated at startup), plus the dependencies in `requirements.txt`. Use an isolated virtual environment and verify the offline seed-only path before any network harvest:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python harvester.py --seed-only --output smoke.rpz  # no network calls

# Basic — generates RPZ with NXDOMAIN (block)
python harvester.py --output mcp.rpz

# Redirect to a proxy IP
python harvester.py --output mcp.rpz --proxy-ip 10.1.2.3

# Verbose
python harvester.py --output mcp.rpz --proxy-ip 10.1.2.3 --verbose

# Skip GitHub sources (no token needed)
python harvester.py --output mcp.rpz --no-github
```

## Output

Generates a standard BIND/RPZ zone file. **Review the generated hostnames before loading it into a resolver**: the seed-only smoke run included broadly used API domains, and an NXDOMAIN policy could disrupt unrelated traffic. Redirect mode requires a correctly configured inspection proxy; this repository does not prove that non-AI connections are passed through harmlessly. Do not deploy a generated policy automatically as part of an archive/rebuild check.

## Examples

See `examples/` for sample RPZ files.

## License

MIT
