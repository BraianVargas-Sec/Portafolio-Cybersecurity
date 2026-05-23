# llm_engine.py
# Integración con Claude API para análisis de alertas
# Autor: briamrlz82

import os
import json
import anthropic
from typing import List, Dict

class LLMEngine:

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model  = "claude-opus-4-5"

    async def analyze_alerts(self, alerts: List[Dict], chains: List[Dict]) -> str:
        """Analiza alertas con IA y devuelve triaje estructurado."""

        # Preparar resumen para el prompt (evitar enviar todo el JSON)
        alerts_summary = []
        for a in alerts[:20]:  # Top 20 por prioridad
            alerts_summary.append({
                "timestamp":   a.get("timestamp", ""),
                "agent":       a.get("agent", {}).get("name", ""),
                "rule_id":     a.get("rule", {}).get("id", ""),
                "description": a.get("rule", {}).get("description", ""),
                "level":       a.get("rule", {}).get("level", 0),
                "tactic":      a.get("tactic", ""),
                "technique":   a.get("technique", ""),
                "priority":    a.get("priority", 0),
            })

        prompt = f"""Eres un analista SOC senior. Analizá las siguientes alertas de seguridad de Wazuh y proporcioná un triaje claro y accionable.

ALERTAS (ordenadas por prioridad):
{json.dumps(alerts_summary, indent=2, ensure_ascii=False)}

CADENAS DE ATAQUE DETECTADAS:
{json.dumps(chains, indent=2, ensure_ascii=False)}

Respondé con:
1. RESUMEN EJECUTIVO (2-3 oraciones sobre el estado de seguridad)
2. INCIDENTES CRÍTICOS (si hay cadenas de ataque o alertas nivel 14+)
3. TOP 5 ALERTAS PRIORITARIAS con análisis breve de cada una
4. ACCIONES INMEDIATAS recomendadas
5. PATRONES detectados (si los hay)

Formato: Markdown claro, directo, orientado a acción. Sin tecnicismos innecesarios."""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
