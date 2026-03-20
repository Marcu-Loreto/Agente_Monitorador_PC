#!/usr/bin/env python3
"""
Motor de Scoring auxiliar.
Em uma implementação corporativa onde partes da análise são determinísticas,
este script pode receber os achados de NLP do Claude (extração de multas, etc)
e aplicar regras hard-coded de compliance regional.
"""
def regra_multa_abusiva(valor_multa_percentual):
    """Código Civil Brasileiro considera abusiva multa muito superior à obrigação."""
    if valor_multa_percentual > 30:
        return "Alto"
    elif valor_multa_percentual > 10:
        return "Médio"
    return "Baixo"

def avaliar_risco(extracao_llm):
    """
    extracao_llm seria um dicionário com os dados brutos encontrados pelo Claude.
    """
    pontos_criticos = 0
    risco_final = "Baixo"
    
    if extracao_llm.get("clausula_lock_in", False):
        pontos_criticos += 3
        
    if regra_multa_abusiva(extracao_llm.get("multa_rescisao_pct", 0)) == "Alto":
        pontos_criticos += 2
        
    if not extracao_llm.get("aderente_lgpd", True):
        pontos_criticos += 3
        
    if pontos_criticos >= 4:
        risco_final = "Alto"
    elif pontos_criticos >= 2:
        risco_final = "Médio"
        
    return risco_final

if __name__ == "__main__":
    mock_llm_data = {
        "clausula_lock_in": True,
        "aderente_lgpd": False,
        "multa_rescisao_pct": 50
    }
    print(f"Risco Calculado pelo Motor: {avaliar_risco(mock_llm_data)}")
