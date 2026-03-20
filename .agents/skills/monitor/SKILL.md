---
name: monitor
description: Monitora o desempenho do PC (CPU, Memória, Rede, Temperatura) e exibe um dashboard moderno. Use esta skill sempre que o usuário quiser ver o consumo de recursos, temperatura do processador ou throughput da rede, ou quando pedir para "monitorar meu PC".
---

# Monitor de Desempenho do PC

Esta skill permite coletar métricas de hardware em tempo real e visualizá-las em um dashboard premium integrado.

## Quando usar

- Quando o usuário pergunta "Como está o uso da CPU?".
- Quando o usuário quer ver a temperatura do processador.
- Quando há lentidão no sistema e o usuário quer diagnosticar consumo de memória.
- Quando o usuário quer ver a velocidade da internet ou throughput da rede.
- Quando o usuário pede um "dashboard de monitoramento".

## Como usar

1.  **Coletar Métricas**: Execute o script de utilitário para gerar os dados mais recentes.
    ```bash
    python .agents/skills/monitor/scripts/monitor_utils.py
    ```
2.  **Abrir o Dashboard**: Use a ferramenta de navegador para abrir o arquivo `index.html`. Como o dashboard lê o arquivo `metrics.json` gerado pelo script, certifique-se de que o script foi executado recentemente.
    - O dashboard está localizado em: `.agents/skills/monitor/dashboard/index.html`
3.  **Visualizar e Analisar**: Observe os valores no dashboard (CPU, Memória, Rede, Temperatura) e relate os pontos mais importantes para o usuário.

## Estrutura do Dashboard

- **CPU**: Mostra a porcentagem de uso atual e um gráfico de histórico.
- **Memória**: Exibe a porcentagem de uso da RAM.
- **Rede**: Mostra o throughput de download e upload em KB/s.
- **Temperatura**: Tenta obter a temperatura do processador (pode retornar N/A em hardware sem suporte).

## Notas Técnicas

- A coleta de dados utiliza a biblioteca `psutil`.
- A temperatura é obtida via WMI no Windows.
- O dashboard utiliza Chart.js para visualização dinâmica.
