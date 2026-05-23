# alert_analyzer.py
# Clasificación, enriquecimiento y detección de cadenas de ataque
# Autor: briamrlz82

from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any

# Mapping de reglas Wazuh a tácticas MITRE ATT&CK
MITRE_MAPPING = {
    # Execution
    "100001": {"technique": "T1059.001", "tactic": "Execution",         "name": "PowerShell"},
    "100002": {"technique": "T1059.001", "tactic": "Execution",         "name": "PowerShell Evasion"},
    "100003": {"technique": "T1562.001", "tactic": "Defense Evasion",   "name": "AMSI Bypass"},
    # Defense Evasion
    "100020": {"technique": "T1218",     "tactic": "Defense Evasion",   "name": "LOLBAS certutil"},
    "100021": {"technique": "T1105",     "tactic": "C2",                "name": "certutil Download"},
    "100033": {"technique": "T1218.011", "tactic": "Defense Evasion",   "name": "rundll32 MiniDump"},
    # Credential Access
    "100030": {"technique": "T1003.001", "tactic": "Credential Access", "name": "LSASS Access"},
    "100031": {"technique": "T1003.001", "tactic": "Credential Access", "name": "Mimikatz Hash"},
    "100032": {"technique": "T1003.001", "tactic": "Credential Access", "name": "ProcDump LSASS"},
    # Lateral Movement
    "100040": {"technique": "T1570",     "tactic": "Lateral Movement",  "name": "PsExec Service"},
    "100041": {"technique": "T1570",     "tactic": "Lateral Movement",  "name": "PsExec Child Process"},
    "100042": {"technique": "T1021.002", "tactic": "Lateral Movement",  "name": "PsExec SMB"},
}

# Secuencias conocidas de cadenas de ataque
ATTACK_CHAINS = [
    {
        "name": "Ransomware Pre-deployment",
        "description": "Patrón clásico pre-ransomware: ejecución → credenciales → movimiento lateral",
        "sequence": ["Execution", "Credential Access", "Lateral Movement"],
        "severity": "CRÍTICO",
        "action": "CONTENER INMEDIATAMENTE — Aislar equipos afectados de la red"
    },
    {
        "name": "Living Off the Land Attack",
        "description": "Uso de binarios del sistema para evadir detección",
        "sequence": ["Defense Evasion", "Execution"],
        "severity": "ALTA",
        "action": "Investigar proceso padre y origen de la ejecución"
    },
    {
        "name": "Credential Harvesting",
        "description": "Volcado de credenciales seguido de uso",
        "sequence": ["Credential Access", "Lateral Movement"],
        "severity": "CRÍTICO",
        "action": "Rotar credenciales comprometidas — Iniciar proceso de IR"
    },
]

class AlertAnalyzer:

    def enrich_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Enriquece alertas con contexto MITRE y clasificación."""
        enriched = []
        for alert in alerts:
            rule_id = str(alert.get("rule", {}).get("id", ""))
            mitre   = MITRE_MAPPING.get(rule_id, {})

            enriched.append({
                **alert,
                "mitre_enriched": mitre,
                "tactic":    mitre.get("tactic", "Unknown"),
                "technique": mitre.get("technique", ""),
                "priority":  self._calculate_priority(alert, mitre),
                "timestamp": alert.get("timestamp", datetime.now().isoformat()),
            })

        # Ordenar por prioridad
        return sorted(enriched, key=lambda x: x["priority"], reverse=True)

    def _calculate_priority(self, alert: Dict, mitre: Dict) -> int:
        """Calcula prioridad 1-100 basada en nivel, táctica y contexto."""
        level   = alert.get("rule", {}).get("level", 0)
        score   = level * 5

        tactic_weights = {
            "Credential Access": 25,
            "Lateral Movement":  25,
            "Execution":         15,
            "Defense Evasion":   15,
            "C2":                20,
            "Persistence":       15,
        }
        score += tactic_weights.get(mitre.get("tactic", ""), 0)
        return min(score, 100)

    def detect_attack_chains(self, alerts: List[Dict],
                             window_minutes: int = 30) -> List[Dict]:
        """Detecta cadenas de ataque por agente y ventana de tiempo."""
        detected_chains = []

        # Agrupar por agente
        by_agent = defaultdict(list)
        for alert in alerts:
            agent = alert.get("agent", {}).get("name", "unknown")
            by_agent[agent].append(alert)

        for agent, agent_alerts in by_agent.items():
            tactics_seen = [a.get("tactic") for a in agent_alerts if a.get("tactic") != "Unknown"]

            for chain in ATTACK_CHAINS:
                required = chain["sequence"]
                # Verificar si todos los pasos de la cadena están presentes
                if all(any(t == req for t in tactics_seen) for req in required):
                    detected_chains.append({
                        "agent":       agent,
                        "chain_name":  chain["name"],
                        "description": chain["description"],
                        "severity":    chain["severity"],
                        "action":      chain["action"],
                        "alerts":      [a for a in agent_alerts
                                        if a.get("tactic") in required],
                    })

        return detected_chains

    def get_statistics(self, alerts: List[Dict]) -> Dict:
        """Genera estadísticas del conjunto de alertas."""
        stats = {
            "total":    len(alerts),
            "critical": sum(1 for a in alerts if a.get("priority", 0) >= 80),
            "high":     sum(1 for a in alerts if 60 <= a.get("priority", 0) < 80),
            "medium":   sum(1 for a in alerts if 40 <= a.get("priority", 0) < 60),
            "low":      sum(1 for a in alerts if a.get("priority", 0) < 40),
            "by_tactic":  defaultdict(int),
            "by_agent":   defaultdict(int),
        }
        for alert in alerts:
            stats["by_tactic"][alert.get("tactic", "Unknown")] += 1
            stats["by_agent"][alert.get("agent", {}).get("name", "unknown")] += 1

        return stats
