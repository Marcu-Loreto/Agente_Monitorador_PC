#!/usr/bin/env python3
"""
Pipeline principal de análise semântica.
Na prática, a skill 'legal-document-explainer-br' executa esse raciocínio 
diretamente como agente LLM. Mas este script materializa a lógica em Python
para chamadas em batelada, injetando o contexto local e o prompt da SKILL.md.
"""
import os
import json

def construir_prompt_analise(texto_documento, diretorio_base="."):
    """Monta o prompt agregando as regras de fomento e legislação."""
    
    # Carregando a regra principal do skill
    with open(f"{diretorio_base}/SKILL.md", "r", encoding="utf-8") as f:
        instrucoes = f.read()
        
    # Carregando template JSON de saída
    with open(f"{diretorio_base}/assets/template_saida.json", "r", encoding="utf-8") as f:
        template = f.read()

    # Montando a chamada
    prompt = f"""
    INSTRUÇÕES DA SKILL:
    {instrucoes}
    
    TEMPLATE OBRIGATÓRIO (Responder SOMENTE JSON Mapeando estas chaves):
    {template}
    
    DOCUMENTO ALVO:
    {texto_documento}
    """
    return prompt

def submeter_ao_llm(prompt):
    # Pseudo-função que enviaria a uma API (ex: Anthropic)
    print("Enviando prompt de 10.000 tokens ao Motor Cognitivo (Claude)...")
    return "{ \"status\": \"sucesso\" }"

if __name__ == "__main__":
    texto_fake = "CONTRATO SOCIAL..."
    prompt = construir_prompt_analise(texto_fake, "../")
    res = submeter_ao_llm(prompt)
    print(res)
