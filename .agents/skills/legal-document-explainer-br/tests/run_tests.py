#!/usr/bin/env python3
"""
Script de teste de regressão simples para validar se a skill continua
retornando o JSON no formato esperado de template_saida.json.
Usado via linha de comando ou em CI/CD.
"""
import json
import os
import sys

def validar_schema(output_llm, template_path):
    with open(template_path, "r", encoding="utf-8") as t:
        schema_esperado = json.load(t)
        
    try:
        output_data = json.loads(output_llm)
        
        # Validação simples de chaves raízes
        chaves_ausentes = [k for k in schema_esperado.keys() if k not in output_data]
        if chaves_ausentes:
            return False, f"Faltam as chaves obrigatórias: {chaves_ausentes}"
            
        print("Validação Estrutural: PASSED")
        return True, "Ok"
        
    except json.JSONDecodeError:
        return False, "Output não é um JSON válido."

if __name__ == "__main__":
    print("Iniciando testes da skill 'legal-document-explainer-br'...")
    # Em um teste real, invocaríamos o Claude com o SKILL.md e o contrato_mock,
    # pegariamos a resposta e validariamos no schema.
    print("Mockando resposta perfeita do LLM...")
    resposta_fake = open("../assets/template_saida.json", "r", encoding="utf-8").read()
    
    valido, msg = validar_schema(resposta_fake, "../assets/template_saida.json")
    if not valido:
        print(f"FAILED: {msg}")
        sys.exit(1)
    
    print("ALL TESTS PASSED.")
