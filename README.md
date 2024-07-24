# Network Security Analyzer

Este projeto coleta dados de conexões de rede, analisa a segurança dessas conexões utilizando APIs do Shodan e AbuseIPDB, e gera um relatório visual de segurança de rede.

## Funcionalidades

- **Coleta de Dados de Rede:** Usa a biblioteca `psutil` para coletar dados sobre conexões de rede atuais.
- **Verificação de IP Público:** Determina se um IP é público ou privado.
- **Análise de Vulnerabilidades:** Usa a API do Shodan para verificar vulnerabilidades conhecidas associadas aos IPs públicos.
- **Verificação de Reputação de IP:** Usa a API do AbuseIPDB para verificar a reputação de IPs públicos.
- **Detecção de Anomalias:** Utiliza o modelo `Isolation Forest` do `sklearn` para detectar conexões anômalas.
- **Geração de Relatório:** Cria um relatório em HTML com gráficos usando `Chart.js` e `Bootstrap`.
