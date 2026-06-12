"""Provider-agnostic LLM client.

Speaks the standard OpenAI-compatible Chat Completions API, so it works against
any compatible endpoint — hosted or a local model (Ollama / LM Studio / vLLM) —
without locking the tool to a single vendor. Stdlib only (urllib): no SDK deps.

The API key is read from an environment variable, never from the committed
profile, so secrets don't end up in version control.
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass


@dataclass
class LLMClient:
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    api_key: str = ""
    temperature: float = 0.2
    timeout: int = 90

    @classmethod
    def from_profile(cls, profile: dict | None) -> "LLMClient":
        llm = (profile or {}).get("llm") or {}
        key_env = llm.get("api_key_env", "WEBSTRIKE_LLM_KEY")
        return cls(
            base_url=str(llm.get("base_url", "https://api.openai.com/v1")).rstrip("/"),
            model=llm.get("model", "gpt-4o-mini"),
            api_key=os.environ.get(key_env, ""),
            temperature=float(llm.get("temperature", 0.2)),
            timeout=int(llm.get("timeout", 90)),
        )

    def configured(self) -> bool:
        return bool(self.api_key)

    def chat(self, system: str, user: str) -> str:
        """Send a system+user prompt, return the assistant's text content."""
        body = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]
