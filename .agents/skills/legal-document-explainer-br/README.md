# skill: legal-document-explainer-br

Esta skill dota o Claude de capacidade especializada para auditar, resumir e classificar riscos em documentos legais do Brasil, priorizando:
- Contratos de prestação de serviço, tecnologia, NDAs.
- Editais e termos de outorga de subvenção ou fomento à inovação (FINEP, FUNTTEL, EMBRAPII).
- Conformidade primária de dados (LGPD).

## Como utilizar

Para usar esta skill, certifique-se de que a pasta `legal-document-explainer-br` está dentro de `.agent/skills` do seu workspace.
Em seguida, simplesmente peça ao Claude na mesma sessão (ou faça upload do PDF/DOCX desejado):
> "Claude, use a skill legal-document-explainer-br para analisar esse contrato de prestação de serviços."

O assistente apresentará um JSON estruturado com o resumo, score de risco, trechos fundamentados e perguntas importantes a serem feitas *antes* de assinar o contrato.

## Estrutura do Pacote
- `SKILL.md`: O prompt principal e as diretrizes cognitivas que dirigem o raciocínio do Claude.
- `assets/`: 
  - `template_saida.json`: O schema estrito que estrutura a devolução dos dados.
- `references/`: Arquivos de conhecimento estático (`fomento.md`, `legislacao_civil.md`, `compliance.md`) que o Claude pode ler durante a análise para cruzar regras com o documento lido.
- `scripts/`: Onde residem códigos auxiliares (ex: `pipeline.py`, `doc_parser.py`) para chamadas determinísticas via MCP ou subagentes se necessário num projeto maior.
- `tests/`: Exemplos de documentos mockados e saídas esperadas para garantir que futuras edições não percam eficácia.

## Guia de Extensão e Manutenção

Para adicionar novas regras ou leis no futuro:
1. **Nova Lei ou Agência**: Crie um arquivo em `references/` (ex: `references/lei_de_licitacoes.md`) contendo um resumo da lei com foco no que o analisador de contratos deve procurar.
2. **Atualização de Diretrizes**: Edite o `SKILL.md` na seção "O que Buscar" para incluir o ponto cego descoberto (ex: "Verificar cláusulas sobre IA generativa e direitos autorais").
3. **Novo Template**: Para mudar o modelo de saída final, edite o `assets/template_saida.json` adicionando os novos campos com descrições pertinentes. Em seguida, valide testando com o Claude.
