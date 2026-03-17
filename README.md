# Slipstream

**MCP Server RPZ Harvester — DNS-based AI Traffic Steering for Security Inspection**

## What This Is

Slipstream harvests known public MCP (Model Context Protocol) server hostnames from multiple sources and generates a DNS Response Policy Zone (RPZ) file that steers AI agent traffic to a security inspection proxy (e.g., HiddenLayer).

When loaded into an Infoblox DNS Firewall (or any BIND/Unbound RPZ-capable resolver), DNS queries to known MCP server hostnames are answered with the proxy IP instead of the real address — transparently redirecting AI agent connections through the proxy for prompt injection detection, data loss prevention, and behavioral analysis.

The proxy is responsible for TLS termination and inspection. Non-AI connections forwarded accidentally are passed through harmlessly.

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

```bash
pip install -r requirements.txt

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

Generates a standard BIND/RPZ zone file. Load it in Infoblox DNS Firewall or any RPZ-capable resolver.

## Examples

See `examples/` for sample RPZ files.

## License

MIT
