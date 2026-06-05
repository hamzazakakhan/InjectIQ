"""
InjectIQ AI Copilot Integration — Real-time AI analysis of injection results.
Unlike sqlmap which has zero AI, InjectIQ uses Ollama to:
1. Analyze WAF responses and generate custom tamper scripts
2. Decide next extraction steps based on partial results
3. Identify false positives from response patterns
4. Generate novel bypass techniques for unknown WAFs
"""
import json
import httpx


class AICopilot:
    """Ollama-powered AI copilot for injection decision-making."""

    def __init__(self, model: str = "qwen2.5-coder:7b", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=120)

    async def _chat(self, system: str, user: str) -> str:
        """Send chat completion to Ollama."""
        try:
            resp = await self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 1024},
                },
            )
            if resp.status_code == 200:
                return resp.json().get("message", {}).get("content", "")
        except Exception:
            pass
        return ""

    async def analyze_waf_response(self, waf_type: str, blocked_payload: str,
                                   response_headers: dict, response_body: str) -> dict:
        """AI analyzes a blocked WAF response and generates bypass strategy."""
        system = """You are a WAF bypass expert. Analyze the blocked request and WAF response.
Return JSON with:
- "bypass_strategy": description of bypass approach
- "tamper_script": Python function body that transforms payload to bypass WAF
- "confidence": 0.0-1.0
- "reasoning": why this bypass should work"""

        user = f"""WAF: {waf_type}
Blocked payload: {blocked_payload}
Response headers: {json.dumps(dict(response_headers), indent=2)}
Response body (first 500 chars): {response_body[:500]}

Generate a bypass for this WAF."""

        result = await self._chat(system, user)
        try:
            # Extract JSON from AI response
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
        except json.JSONDecodeError:
            pass
        return {"bypass_strategy": "unknown", "tamper_script": "", "confidence": 0.0, "reasoning": result}

    async def decide_next_step(self, extraction_state: dict, injection_points: list) -> dict:
        """AI decides what to extract next based on current progress."""
        system = """You are a database exploitation expert. Given the current extraction state,
decide the next most valuable data to extract. Return JSON with:
- "next_query": SQL query to execute
- "reasoning": why this is the best next step
- "priority": "high"/"medium"/"low"
- "stop": true if we have enough data"""

        user = f"""Current extraction state:
{json.dumps(extraction_state, indent=2)}

Available injection points:
{json.dumps(injection_points[:3], indent=2)}

What should we extract next?"""

        result = await self._chat(system, user)
        try:
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
        except json.JSONDecodeError:
            pass
        return {"next_query": "", "reasoning": result, "priority": "medium", "stop": False}

    async def identify_false_positive(self, injection_result: dict,
                                      baseline_length: int, baseline_status: int) -> dict:
        """AI identifies whether an injection result is a false positive."""
        system = """You are a SQL injection expert. Determine if the detected injection is a false positive.
Consider: response length changes, status codes, error patterns, timing consistency.
Return JSON with:
- "is_false_positive": true/false
- "confidence": 0.0-1.0
- "reasoning": explanation"""

        user = f"""Injection result: {json.dumps(injection_result, indent=2)}
Baseline response length: {baseline_length}
Baseline status code: {baseline_status}

Is this a false positive?"""

        result = await self._chat(system, user)
        try:
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
        except json.JSONDecodeError:
            pass
        return {"is_false_positive": False, "confidence": 0.5, "reasoning": result}

    async def generate_tamper_script(self, waf_type: str, dbms: str,
                                     sample_blocked: list[str]) -> str:
        """AI generates a novel tamper script for a specific WAF+DBMS combo.
        This is the key innovation — sqlmap has 68 fixed scripts, InjectIQ
        generates new ones on the fly. Feeds actual sqlmap tamper source code
        + modern 2025-2026 techniques to the AI as training context."""
        import json
        from pathlib import Path
        from .tamper_modern import AI_TAMPER_TRAINING_PROMPT

        # Load actual tamper source code for AI training
        training_path = Path(__file__).parent / "sqlmap_tamper_training.json"
        legacy_code = ""
        if training_path.exists():
            with open(training_path) as f:
                tampers = json.load(f)
            # Provide relevant tamper code examples (not all 70 — too many tokens)
            # Filter by DBMS relevance
            dbms_keywords = {
                "mysql": ["mysql", "sleep", "concat", "schema", "versioned", "0eunion"],
                "postgresql": ["substring", "greatest", "least", "between"],
                "mssql": ["mssql", "sp_password", "plus2", "space2mssql"],
                "oracle": ["dunion", "uppercase", "lowercase"],
                "sqlite": ["randomblank", "space2dash"],
            }
            relevant_keywords = dbms_keywords.get(dbms, []) + ["space2", "random", "encode", "comment"]
            relevant = [t for t in tampers if any(kw in t["name"] for kw in relevant_keywords)]
            # Always include a few general-purpose ones
            general = [t for t in tampers if t["name"] in
                       ["charencode", "randomcase", "between", "equaltolike", "if2case"]]
            seen = set()
            examples = []
            for t in relevant + general:
                if t["name"] not in seen:
                    seen.add(t["name"])
                    examples.append(t)
            legacy_code = "\n\n".join(
                f"# --- {t['name']} ---\n# {t['doc']}\n{t['code']}"
                for t in examples[:15]
            )

        system = AI_TAMPER_TRAINING_PROMPT.format(legacy_tampers=legacy_code)

        user = f"""WAF: {waf_type}
DBMS: {dbms}
Sample payloads that were blocked:
{chr(10).join(f'- {p}' for p in sample_blocked[:5])}

Generate a tamper function to bypass this WAF for this DBMS using the NEW techniques above.
Study the legacy tamper code patterns for structure, then apply modern techniques."""

        result = await self._chat(system, user)
        # Extract just the function code
        if "def tamper" in result:
            start = result.find("def tamper")
            return result[start:]
        return result
