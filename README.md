
# Network Security Analysis Tool

Este projeto coleta e analisa conexões de rede, verifica a reputação e vulnerabilidades de IPs usando APIs como Shodan e AbuseIPDB, e detecta anomalias com `IsolationForest`. Além disso, gera um relatório interativo em HTML com gráficos.

## Funcionalidades

- **Coleta de Dados de Rede:** Usa a biblioteca `psutil` para coletar dados sobre conexões de rede atuais.
- **Verificação de IP Público:** Determina se um IP é público ou privado.
- **Análise de Vulnerabilidades:** Usa a API do Shodan para verificar vulnerabilidades conhecidas associadas aos IPs públicos.
- **Verificação de Reputação de IP:** Usa a API do AbuseIPDB para verificar a reputação de IPs públicos.
- **Detecção de Anomalias:** Utiliza o modelo `Isolation Forest` do `sklearn` para detectar conexões anômalas.
- **Geração de Relatório:** Cria um relatório em HTML com gráficos usando `Chart.js` e `Bootstrap`.

## Pré-requisitos

Antes de iniciar, é necessário ter **Python 3.x** instalado. Também é necessário instalar as dependências listadas abaixo.

### Dependências

- `psutil`: Coleta informações sobre conexões de rede.
- `pandas`: Manipulação e análise de dados.
- `scikit-learn`: Modelagem e detecção de anomalias com IsolationForest.
- `requests`: Realiza chamadas HTTP para consumir APIs externas.
- `ipaddress`: Manipulação de endereços IP.
- `shodan`: Cliente para interagir com a API do Shodan.

### API Keys Necessárias

1. **Shodan API Key:**  
   Adquira uma chave em [Shodan.io](https://account.shodan.io/).
   
2. **AbuseIPDB API Key:**  
   Registre-se no [AbuseIPDB](https://www.abuseipdb.com/) para obter sua chave API.

---

## Instalação

1. **Clone o repositório ou copie o script.**

```bash
git clone https://github.com/seu-usuario/seu-repositorio.git
cd seu-repositorio
```

2. **Crie um ambiente virtual (opcional, mas recomendado).**

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate      # Windows
```

3. **Instale as dependências.**

Crie um arquivo `requirements.txt` com o seguinte conteúdo:

```
psutil==5.9.5
pandas==2.1.1
scikit-learn==1.3.0
requests==2.31.0
shodan==1.27.0
```

Agora, instale as dependências:

```bash
pip install -r requirements.txt
```

---

## Uso

1. **Configuração das Chaves API:**  
   Atualize as seguintes variáveis no script com suas chaves API:

   ```python
   SHODAN_API_KEY = 'sua_shodan_api_key'
   ABUSEIPDB_API_KEY = 'sua_abuseipdb_api_key'
   ```

2. **Executar o Script:**

```bash
python network_security_analysis.py
```

Isso irá gerar:
- `network_data.csv`: Dados de rede coletados.
- `network_data_analysis.csv`: Análise das conexões.
- `network_security_report.html`: Relatório com gráficos interativos.

---

## Contribuição

Sinta-se à vontade para abrir issues ou enviar PRs.

---

## Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.
