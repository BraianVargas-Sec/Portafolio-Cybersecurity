# wazuh_client.py
# Cliente para la API de Wazuh
# Autor: briamrlz82

import os
import json
import aiohttp
from datetime import datetime, timedelta
from typing import List, Dict
from pathlib import Path

class WazuhClient:

    def __init__(self, use_sample: bool = False):
        self.use_sample = use_sample
        self.host     = os.getenv("WAZUH_HOST", "https://localhost:55000")
        self.user     = os.getenv("WAZUH_USER", "wazuh")
        self.password = os.getenv("WAZUH_PASSWORD", "")
        self.token    = None

    async def _authenticate(self) -> str:
        """Obtiene token JWT de la API de Wazuh."""
        url = f"{self.host}/security/user/authenticate"
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                auth=aiohttp.BasicAuth(self.user, self.password),
                ssl=False
            ) as resp:
                data = await resp.json()
                return data["data"]["token"]

    async def get_recent_alerts(self, limit: int = 100,
                                 min_level: int = 7,
                                 hours: int = 1) -> List[Dict]:
        """Obtiene alertas recientes de Wazuh."""

        # Modo demo: usar alertas de ejemplo
        if self.use_sample:
            return self._load_sample_alerts()

        if not self.token:
            self.token = await self._authenticate()

        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

        url = f"{self.host}/alerts"
        params = {
            "limit":        limit,
            "sort":         "-timestamp",
            "q":            f"rule.level>={min_level};timestamp>{since}",
        }
        headers = {"Authorization": f"Bearer {self.token}"}

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   params=params, ssl=False) as resp:
                data = await resp.json()
                return data.get("data", {}).get("affected_items", [])

    def _load_sample_alerts(self) -> List[Dict]:
        """Carga alertas de ejemplo para testing sin Wazuh real."""
        sample_path = Path(__file__).parent.parent / "examples" / "sample_alerts.json"
        if sample_path.exists():
            with open(sample_path) as f:
                return json.load(f)
        return []
