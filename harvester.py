#!/usr/bin/env python3
"""
Slipstream MCP Server RPZ Harvester
====================================
Fetches known public MCP server hostnames from multiple sources and generates
a DNS Response Policy Zone (RPZ) file for use with Infoblox DNS Firewall or
any BIND/Unbound RPZ-capable resolver.

Usage:
    python harvester.py --output mcp.rpz --proxy-ip 10.1.2.3

Sources:
    1. Official MCP Registry (registry.modelcontextprotocol.io)
    2. Anthropic reference servers (github.com/modelcontextprotocol/servers)
    3. awesome-mcp-servers (github.com/punkpeye/awesome-mcp-servers)
    4. best-of-mcp-servers (github.com/tolkonepiu/best-of-mcp-servers)
    5. Smithery registry (smithery.ai)
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

USER_AGENT = "Slipstream-RPZ-Harvester/1.0 (github.com/druceinfoblox/Slipstream)"

# Shared-hosting / CDN platforms where individual servers live under a path,
# not a dedicated hostname. Steering the entire platform would be too broad.
SHARED_PLATFORM_BLOCKLIST = {
    "vercel.app",
    "netlify.app",
    "railway.app",
    "render.com",
    "fly.dev",
    "replit.dev",
    "repl.co",
    "glitch.me",
    "workers.dev",
    "pages.dev",
    "azurewebsites.net",
    "azurestaticapps.net",
    "amazonaws.com",
    "compute.amazonaws.com",
    "elasticbeanstalk.com",
    "herokussl.com",
    "herokuapp.com",
    "onrender.com",
    "ngrok.io",
    "ngrok-free.app",
    "loca.lt",
    "tunnelto.dev",
    "cloudflare.com",          # too broad
    "openai.com",              # shared API host
    "anthropic.com",           # shared API host
    "google.com",
    "googleapis.com",
    "azure.com",
}

# Smithery-hosted MCP servers live at smithery.ai/server/* but the actual
# remote endpoint is *.smithery.ai — we DO want those.
DEDICATED_MCP_PLATFORMS = {
    "smithery.ai",
    "mcp.so",
}

RPZ_ZONE_NAME = "mcp-slipstream.rpz"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg: str, verbose: bool = False, force: bool = False):
    if force or verbose:
        print(f"[slipstream] {msg}", file=sys.stderr)


def extract_hostnames_from_text(text: str) -> set[str]:
    """
    Pull hostnames/FQDNs from free-form text (markdown, JSON strings, etc.)
    Looks for http(s):// URLs and bare hostnames that look like FQDNs.
    """
    found = set()

    # URLs
    for url in re.findall(r'https?://([^\s/\'">\)\]]+)', text):
        host = url.split('/')[0].split('?')[0].split('#')[0].lower().strip()
        if host:
            found.add(host)

    return found


def is_valid_mcp_hostname(host: str) -> bool:
    """
    Return True if this looks like a real, steerable MCP server hostname.
    Rejects: localhost, IPs, bare TLDs, shared platforms, internal hostnames.
    """
    if not host or len(host) < 4:
        return False

    # Must contain at least one dot
    if '.' not in host:
        return False

    # Reject localhost variants
    if host in ('localhost', '127.0.0.1', '::1') or host.startswith('localhost'):
        return False

    # Reject IP addresses (v4)
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        return False

    # Reject IPv6
    if ':' in host:
        return False

    # Reject internal/private hostnames
    if host.endswith('.local') or host.endswith('.internal') or host.endswith('.lan'):
        return False

    # Reject shared platforms (check suffix)
    host_lower = host.lower()
    for platform in SHARED_PLATFORM_BLOCKLIST:
        if host_lower == platform or host_lower.endswith('.' + platform):
            return False

    # Must look like a proper FQDN (letters/digits/hyphens, valid TLD)
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]+[a-z0-9]$', host_lower):
        return False

    return True


def normalize_hostname(host: str) -> str:
    return host.lower().strip().rstrip('.')


# ---------------------------------------------------------------------------
# Source 1: Official MCP Registry
# ---------------------------------------------------------------------------

def fetch_official_registry(verbose: bool = False) -> set[str]:
    """
    Hits registry.modelcontextprotocol.io/v0/servers (unauthenticated).
    Paginates through all results.
    """
    base_url = "https://registry.modelcontextprotocol.io/v0/servers"
    hostnames = set()
    offset = 0
    limit = 100
    page = 0

    log("Fetching official MCP registry...", verbose)

    while True:
        try:
            resp = requests.get(
                base_url,
                params={"limit": limit, "offset": offset},
                headers={"User-Agent": USER_AGENT},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log(f"  Official registry error (offset={offset}): {e}", force=True)
            break

        servers = data.get("servers", [])
        if not servers:
            break

        for server in servers:
            # Check homepage, repository, and any URL fields
            for field in ("homepage", "repository", "url", "endpoint"):
                val = server.get(field, "")
                if val and isinstance(val, str):
                    parsed = urlparse(val)
                    if parsed.hostname:
                        hostnames.add(normalize_hostname(parsed.hostname))

            # Check packages for remote endpoints
            for pkg in server.get("packages", []):
                for field in ("registry_url", "url"):
                    val = pkg.get(field, "")
                    if val and isinstance(val, str):
                        parsed = urlparse(val)
                        if parsed.hostname:
                            hostnames.add(normalize_hostname(parsed.hostname))

            # Extract from full JSON dump (catches nested URLs)
            raw = json.dumps(server)
            for h in extract_hostnames_from_text(raw):
                hostnames.add(normalize_hostname(h))

        log(f"  Registry page {page}: {len(servers)} servers, {len(hostnames)} hostnames so far", verbose)

        if not data.get("nextPageToken") and len(servers) < limit:
            break

        offset += limit
        page += 1
        time.sleep(0.3)  # be polite

    log(f"  Official registry total raw hostnames: {len(hostnames)}", verbose)
    return hostnames


# ---------------------------------------------------------------------------
# Source 2: GitHub modelcontextprotocol/servers README
# ---------------------------------------------------------------------------

def fetch_github_mcp_servers(verbose: bool = False) -> set[str]:
    """
    Fetches the raw README from the official Anthropic MCP servers repo
    and extracts URLs.
    """
    url = "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md"
    log("Fetching modelcontextprotocol/servers README...", verbose)

    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=15)
        resp.raise_for_status()
        hostnames = extract_hostnames_from_text(resp.text)
        log(f"  MCP servers README: {len(hostnames)} raw hostnames", verbose)
        return hostnames
    except Exception as e:
        log(f"  modelcontextprotocol/servers error: {e}", force=True)
        return set()


# ---------------------------------------------------------------------------
# Source 3: awesome-mcp-servers
# ---------------------------------------------------------------------------

def fetch_awesome_mcp_servers(verbose: bool = False) -> set[str]:
    """
    Fetches punkpeye/awesome-mcp-servers README.
    """
    url = "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md"
    log("Fetching awesome-mcp-servers...", verbose)

    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=15)
        resp.raise_for_status()
        hostnames = extract_hostnames_from_text(resp.text)
        log(f"  awesome-mcp-servers: {len(hostnames)} raw hostnames", verbose)
        return hostnames
    except Exception as e:
        log(f"  awesome-mcp-servers error: {e}", force=True)
        return set()


# ---------------------------------------------------------------------------
# Source 4: best-of-mcp-servers
# ---------------------------------------------------------------------------

def fetch_best_of_mcp_servers(verbose: bool = False) -> set[str]:
    """
    Fetches tolkonepiu/best-of-mcp-servers README.
    """
    url = "https://raw.githubusercontent.com/tolkonepiu/best-of-mcp-servers/main/README.md"
    log("Fetching best-of-mcp-servers...", verbose)

    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=15)
        resp.raise_for_status()
        hostnames = extract_hostnames_from_text(resp.text)
        log(f"  best-of-mcp-servers: {len(hostnames)} raw hostnames", verbose)
        return hostnames
    except Exception as e:
        log(f"  best-of-mcp-servers error: {e}", force=True)
        return set()


# ---------------------------------------------------------------------------
# Source 5: Smithery registry (public search page scrape)
# ---------------------------------------------------------------------------

def fetch_smithery(verbose: bool = False) -> set[str]:
    """
    Fetches smithery.ai public server listing page.
    Note: Smithery hosts servers at <name>.smithery.ai for remote servers.
    We capture those subdomain patterns from their listing.
    """
    log("Fetching Smithery registry...", verbose)
    hostnames = set()

    # Smithery's public listing
    urls_to_try = [
        "https://smithery.ai/servers",
        "https://smithery.ai",
    ]

    for url in urls_to_try:
        try:
            resp = requests.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; Slipstream/1.0)",
                    "Accept": "text/html,application/json",
                },
                timeout=15,
            )
            resp.raise_for_status()
            found = extract_hostnames_from_text(resp.text)
            for h in found:
                if 'smithery' in h or 'mcp' in h.lower():
                    hostnames.add(normalize_hostname(h))
            log(f"  Smithery ({url}): {len(found)} raw hostnames", verbose)
        except Exception as e:
            log(f"  Smithery ({url}) error: {e}", verbose)

    # Add known smithery remote endpoint pattern
    hostnames.add("server.smithery.ai")

    return hostnames


# ---------------------------------------------------------------------------
# Known dedicated MCP endpoints (manually curated seed list)
# ---------------------------------------------------------------------------

KNOWN_MCP_ENDPOINTS = {
    # Anthropic / official
    "mcp.anthropic.com",

    # GitHub
    "mcp.github.com",
    "api.github.com",  # used by GitHub MCP server

    # Stripe
    "mcp.stripe.com",

    # Smithery hosted
    "server.smithery.ai",

    # Atlassian
    "mcp.atlassian.com",

    # Cloudflare (MCP gateway)
    "mcp.cloudflare.com",

    # Brave Search MCP
    "api.search.brave.com",

    # HuggingFace
    "huggingface.co",

    # Notion
    "api.notion.com",

    # Linear
    "api.linear.app",

    # Slack
    "slack.com",
    "api.slack.com",

    # Airtable
    "api.airtable.com",

    # Asana
    "app.asana.com",

    # Jira / Atlassian cloud
    "api.atlassian.com",

    # Sentry
    "sentry.io",

    # Supabase
    "api.supabase.io",
    "api.supabase.com",

    # Planetscale
    "api.planetscale.com",

    # MongoDB Atlas
    "cloud.mongodb.com",

    # Neon
    "api.neon.tech",

    # Vercel MCP (dedicated endpoint, not shared hosting)
    "api.vercel.com",
}


# ---------------------------------------------------------------------------
# RPZ generation
# ---------------------------------------------------------------------------

def generate_rpz(
    hostnames: set[str],
    proxy_ip: str | None,
    zone_name: str,
    serial: str,
) -> str:
    """
    Generate a BIND-format RPZ zone file.

    If proxy_ip is set: redirect to that IP (A record).
    If proxy_ip is None: return NXDOMAIN (CNAME .).
    """
    now = datetime.now(timezone.utc)
    action_desc = f"redirect to {proxy_ip}" if proxy_ip else "NXDOMAIN (block)"

    lines = [
        f"; Slipstream MCP Server RPZ",
        f"; Generated: {now.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"; Hostnames: {len(hostnames)}",
        f"; Action: {action_desc}",
        f"; Source: github.com/druceinfoblox/Slipstream",
        f";",
        f"$ORIGIN {zone_name}.",
        f"",
        f"@ SOA {zone_name}. hostmaster.{zone_name}. (",
        f"        {serial}  ; serial",
        f"        3600       ; refresh (1 hour)",
        f"        600        ; retry (10 min)",
        f"        604800     ; expire (7 days)",
        f"        300        ; minimum TTL",
        f")",
        f"  NS ns1.{zone_name}.",
        f"",
        f"; --- Policy Records ---",
        f"",
    ]

    sorted_hosts = sorted(hostnames)

    for host in sorted_hosts:
        fqdn = f"{host}."
        wildcard = f"*.{host}."
        if proxy_ip:
            lines.append(f"{fqdn:<50} A  {proxy_ip}")
            lines.append(f"{wildcard:<50} A  {proxy_ip}")
        else:
            lines.append(f"{fqdn:<50} CNAME  .")
            lines.append(f"{wildcard:<50} CNAME  .")

    lines.append("")
    lines.append("; --- End of Slipstream RPZ ---")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Slipstream: Harvest MCP server hostnames and generate an RPZ file."
    )
    parser.add_argument("--output", "-o", default="mcp.rpz", help="Output RPZ filename")
    parser.add_argument("--proxy-ip", default=None, help="Proxy IP to redirect to (default: NXDOMAIN)")
    parser.add_argument("--zone-name", default=RPZ_ZONE_NAME, help="RPZ zone name")
    parser.add_argument("--no-github", action="store_true", help="Skip GitHub sources")
    parser.add_argument("--no-smithery", action="store_true", help="Skip Smithery")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--seed-only", action="store_true", help="Only use built-in seed list (no network)")
    args = parser.parse_args()

    v = args.verbose
    all_hostnames: set[str] = set()

    if not args.seed_only:
        # Source 1: Official registry
        all_hostnames |= fetch_official_registry(verbose=v)

        # Source 2-4: GitHub
        if not args.no_github:
            all_hostnames |= fetch_github_mcp_servers(verbose=v)
            all_hostnames |= fetch_awesome_mcp_servers(verbose=v)
            all_hostnames |= fetch_best_of_mcp_servers(verbose=v)

        # Source 5: Smithery
        if not args.no_smithery:
            all_hostnames |= fetch_smithery(verbose=v)

    # Seed list always included
    all_hostnames |= KNOWN_MCP_ENDPOINTS

    log(f"\nTotal raw hostnames collected: {len(all_hostnames)}", force=True)

    # Filter
    valid = {normalize_hostname(h) for h in all_hostnames if is_valid_mcp_hostname(h)}
    log(f"After filtering: {len(valid)} valid MCP hostnames", force=True)

    if not valid:
        log("No valid hostnames found. Exiting.", force=True)
        sys.exit(1)

    # Generate serial from date
    serial = datetime.now(timezone.utc).strftime("%Y%m%d01")

    # Generate RPZ
    rpz_content = generate_rpz(
        hostnames=valid,
        proxy_ip=args.proxy_ip,
        zone_name=args.zone_name,
        serial=serial,
    )

    # Write output
    with open(args.output, "w") as f:
        f.write(rpz_content)

    log(f"\n✓ RPZ file written to: {args.output}", force=True)
    log(f"  Hostnames in RPZ: {len(valid)}", force=True)
    log(f"  Zone: {args.zone_name}", force=True)
    if args.proxy_ip:
        log(f"  Redirect to: {args.proxy_ip}", force=True)
    else:
        log(f"  Action: NXDOMAIN (no --proxy-ip specified)", force=True)

    # Print summary to stdout
    print(f"\nSlipstream RPZ Summary")
    print(f"======================")
    print(f"Output file : {args.output}")
    print(f"Hostnames   : {len(valid)}")
    print(f"Zone name   : {args.zone_name}")
    print(f"Proxy IP    : {args.proxy_ip or 'NXDOMAIN'}")
    print(f"\nSample entries:")
    for h in sorted(valid)[:10]:
        print(f"  {h}")
    if len(valid) > 10:
        print(f"  ... and {len(valid) - 10} more")


if __name__ == "__main__":
    main()
