# main.py
# AI SOC Assistant — Entry point
# Autor: briamrlz82

import argparse
import asyncio
import json
from datetime import datetime
from src.wazuh_client import WazuhClient
from src.alert_analyzer import AlertAnalyzer
from src.llm_engine import LLMEngine
from src.report_generator import ReportGenerator

def print_banner():
    print("""
\033[36m═══════════════════════════════════════════════════
  AI SOC ASSISTANT v1.0
  Análisis de alertas Wazuh con IA
  github.com/briamrlz82
═══════════════════════════════════════════════════\033[0m
""")

async def run_triage(wazuh: WazuhClient, analyzer: AlertAnalyzer, llm: LLMEngine):
    """Triaje de alertas recientes."""
    print(f"\033[36m[*]\033[0m Obteniendo alertas de Wazuh...")
    alerts = await wazuh.get_recent_alerts(limit=100, min_level=7)
    
    if not alerts:
        print("\033[33m[!]\033[0m No hay alertas recientes con nivel >= 7")
        return

    print(f"\033[32m[OK]\033[0m {len(alerts)} alertas obtenidas")
    print(f"\033[36m[*]\033[0m Analizando con IA...\n")

    # Clasificar y enriquecer cada alerta
    enriched = analyzer.enrich_alerts(alerts)
    
    # Detectar cadenas de ataque
    chains = analyzer.detect_attack_chains(enriched)
    
    # Análisis con LLM
    analysis = await llm.analyze_alerts(enriched, chains)
    
    # Mostrar resultado
    print(analysis)
    
    # Guardar resultado
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"reports/triage_{timestamp}.md"
    with open(output_file, "w") as f:
        f.write(analysis)
    print(f"\n\033[32m[OK]\033[0m Reporte guardado: {output_file}")

async def run_report(wazuh: WazuhClient, analyzer: AlertAnalyzer, 
                     llm: LLMEngine, report_gen: ReportGenerator):
    """Genera reporte ejecutivo del período."""
    print(f"\033[36m[*]\033[0m Generando reporte ejecutivo (últimas 24h)...")
    
    alerts = await wazuh.get_recent_alerts(limit=500, hours=24)
    enriched = analyzer.enrich_alerts(alerts)
    chains = analyzer.detect_attack_chains(enriched)
    stats = analyzer.get_statistics(enriched)
    
    report = await report_gen.generate_executive_report(
        alerts=enriched,
        chains=chains,
        stats=stats,
        llm=llm
    )
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"reports/executive_report_{timestamp}.md"
    with open(output_file, "w") as f:
        f.write(report)
    
    print(f"\033[32m[OK]\033[0m Reporte ejecutivo guardado: {output_file}")
    print(report[:500] + "...")

async def run_watch(wazuh: WazuhClient, analyzer: AlertAnalyzer, llm: LLMEngine):
    """Monitoreo continuo con análisis cada N segundos."""
    import os
    interval = int(os.getenv("TRIAGE_INTERVAL", "300"))
    
    print(f"\033[36m[*]\033[0m Modo watch activo — análisis cada {interval}s")
    print(f"\033[33m[!]\033[0m Ctrl+C para detener\n")
    
    while True:
        try:
            await run_triage(wazuh, analyzer, llm)
            print(f"\n\033[36m[*]\033[0m Próximo análisis en {interval}s...")
            await asyncio.sleep(interval)
        except KeyboardInterrupt:
            print("\n\033[33m[!]\033[0m Watch detenido")
            break

async def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="AI SOC Assistant")
    parser.add_argument("--mode", choices=["triage", "report", "watch"],
                        default="triage", help="Modo de operación")
    parser.add_argument("--sample", action="store_true",
                        help="Usar alertas de ejemplo (sin Wazuh real)")
    args = parser.parse_args()

    # Inicializar componentes
    wazuh   = WazuhClient(use_sample=args.sample)
    analyzer = AlertAnalyzer()
    llm      = LLMEngine()
    report   = ReportGenerator()

    # Ejecutar modo seleccionado
    if args.mode == "triage":
        await run_triage(wazuh, analyzer, llm)
    elif args.mode == "report":
        await run_report(wazuh, analyzer, llm, report)
    elif args.mode == "watch":
        await run_watch(wazuh, analyzer, llm)

if __name__ == "__main__":
    asyncio.run(main())
