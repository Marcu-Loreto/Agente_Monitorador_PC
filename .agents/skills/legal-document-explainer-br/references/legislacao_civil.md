# Base Legal - Direito Civil e Proteção de Dados (Brasil)

## Contratos - Código Civil (CC)
- **Desequilíbrio Contratual**: Cláusulas que colocam uma parte em desvantagem exagerada são anuláveis (Art. 421 e 424 CC para contratos de adesão).
- **Resilição e Multas**: Multas que ultrapassem de forma excessiva o valor da obrigação principal podem ser reduzidas judicialmente (Art. 412 CC).
- **Sigilo / NDA**: Precisam delimitar o prazo. NDAs de "prazo eterno" causam insegurança jurídica; normalmente usam-se 2 a 5 anos pós-rescisão.

## LGPD (Lei Geral de Proteção de Dados - Lei 13.709/18)
- Um contrato que lida com fluxo de PII (Personally Identifiable Information) e informações sensíveis DEVE conter seções de LGPD estabelecendo papéis:
  - **Controlador**: Toma as decisões sobre o tratamento (normalmente o contratante do software/serviço).
  - **Operador**: Processa os dados em nome do controlador (normalmente a empresa de SaaS/Serviço).
- Exigências Contratuais:
  - Obrigatoriedade de reportar incidentes de segurança (vazamentos) em prazo curto (ex: 24h as 48h).
  - Garantia de que operadores não usarão os dados dos clientes para seus fins próprios (treinamento de modelos genéricos não anonimizados sem consentimento expresso).
- Qualquer documento que envolva bases de dados e não cite obrigações sob a LGPD apresenta uma falha perigosa.
