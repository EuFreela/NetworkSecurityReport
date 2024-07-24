import psutil
import pandas as pd
from sklearn.ensemble import IsolationForest
import requests
import ipaddress
import json
import shodan

SHODAN_API_KEY = 'YOUR_KEY_SHODAN'
ABUSEIPDB_API_KEY = 'YOUR_KEY_ABUSE'

# Função para coletar dados de conexões de rede
def collect_network_data():
    connections = psutil.net_connections(kind='inet')
    data = {
        'fd': [],
        'family': [],
        'type': [],
        'laddr_ip': [],
        'laddr_port': [],
        'raddr_ip': [],
        'raddr_port': [],
        'status': [],
        'pid': []
    }
    
    for conn in connections:
        data['fd'].append(conn.fd)
        data['family'].append(conn.family)
        data['type'].append(conn.type)
        data['laddr_ip'].append(conn.laddr.ip if conn.laddr else None)
        data['laddr_port'].append(conn.laddr.port if conn.laddr else None)
        data['raddr_ip'].append(conn.raddr.ip if conn.raddr else None)
        data['raddr_port'].append(conn.raddr.port if conn.raddr else None)
        data['status'].append(conn.status)
        data['pid'].append(conn.pid)
    
    df = pd.DataFrame(data)
    return df

# Função para verificar se um IP é público
def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False

# Coletar dados e salvar em um arquivo CSV
network_data = collect_network_data()
network_data.to_csv('network_data.csv', index=False)
print("Dados de rede coletados e salvos em 'network_data.csv'.")

# Função para verificar vulnerabilidades usando a API do Shodan
def check_vulnerabilities_shodan(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        if is_public_ip(ip):
            host = api.host(ip)
            vulnerabilities = host.get('vulns', [])
            return vulnerabilities
        else:
            return []
    except shodan.APIError as e:
        print(f"Erro ao verificar IP {ip} no Shodan: {e}")
        return []

# Função para verificar reputação de IP
def check_ip_reputation(ip):
    if not ip:
        return "IP não definido."
    
    url = f"https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    response_data = response.json()

    if response.status_code == 200:
        if response_data['data']['abuseConfidenceScore'] > 0:
            return f"IP {ip} é suspeito com uma pontuação de confiança de abuso de {response_data['data']['abuseConfidenceScore']}."
        else:
            return f"IP {ip} parece ser seguro."
    else:
        return f"Erro ao verificar IP {ip}: {response_data['errors'][0]['detail']}"

# Verificar vulnerabilidades e reputação dos IPs
def analyze_connections(network_data):
    results = []
    for index, row in network_data.iterrows():
        if is_public_ip(row['raddr_ip']):
            vulnerabilities = check_vulnerabilities_shodan(row['raddr_ip'])
            ip_reputation = check_ip_reputation(row['raddr_ip'])
            is_vulnerable = 1 if vulnerabilities else 0
            results.append((row['laddr_ip'], row['laddr_port'], row['raddr_ip'], row['raddr_port'], is_vulnerable, vulnerabilities, ip_reputation))
            print(f"Conexão: {row['laddr_ip']}:{row['laddr_port']} -> {row['raddr_ip']}:{row['raddr_port']}, Vulnerabilidades: {vulnerabilities}, Reputação: {ip_reputation}")
        else:
            results.append((row['laddr_ip'], row['laddr_port'], row['raddr_ip'], row['raddr_port'], 0, [], 'IP privado ou inválido'))
    
    results_df = pd.DataFrame(results, columns=['laddr_ip', 'laddr_port', 'raddr_ip', 'raddr_port', 'vulnerable', 'vulnerabilities', 'ip_reputation'])
    return results_df

# Analisar as conexões coletadas
results_df = analyze_connections(network_data)
results_df.to_csv('network_data_analysis.csv', index=False)
print("Análise de dados de rede salva em 'network_data_analysis.csv'.")

# Usar Isolation Forest para detectar anomalias
features = ['laddr_port', 'raddr_port']
X = results_df[features].fillna(-1)  # Preencher valores nulos com -1 para o modelo

model = IsolationForest(contamination=0.1)  # Ajustar o parâmetro de contaminação conforme necessário
results_df['anomaly'] = model.fit_predict(X)

# Criar os dados em formato JSON para o Chart.js
vulnerable_counts = results_df['vulnerable'].value_counts().reset_index()
vulnerable_counts.columns = ['vulnerable', 'count']

vulnerable_data = vulnerable_counts.to_dict(orient='records')
connection_data = results_df[['laddr_ip', 'raddr_ip', 'vulnerable']].to_dict(orient='records')

# Gerar o arquivo HTML com gráficos Chart.js e Bootstrap
html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .vulnerable {{
            background-color: red !important;
            color: white;
        }}
        .anomaly {{
            background-color: yellow !important;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center my-4">Network Security Report</h1>
        <div class="row">
            <div class="col-md-6" style="width: 400px; height: 400px;">
                <canvas id="vulnerableChart"></canvas>
            </div>
            <div class="col-md-6">
                <canvas id="connectionsChart"></canvas>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-md-12">
                <h3>Descrição</h3>
                <p>Este relatório mostra a distribuição de conexões vulneráveis e seguras, bem como a comparação entre conexões vulneráveis e seguras. Os dados foram coletados e analisados para identificar possíveis ameaças à segurança da rede.</p>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-md-12">
                <h3>Detalhes das Conexões</h3>
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>Local IP</th>
                            <th>Local Port</th>
                            <th>Remote IP</th>
                            <th>Remote Port</th>
                            <th>Vulnerável</th>
                            <th>Vulnerabilidades</th>
                            <th>Reputação IP</th>
                            <th>Anomalia</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join([f"<tr class='{'vulnerable' if row['vulnerable'] == 1 else ''} {'anomaly' if row['anomaly'] == -1 else ''}'><td>{row['laddr_ip']}</td><td>{row['laddr_port']}</td><td>{row['raddr_ip']}</td><td>{row['raddr_port']}</td><td>{'Sim' if row['vulnerable'] == 1 else 'Não'}</td><td>{', '.join(row['vulnerabilities']) if row['vulnerabilities'] else 'Nenhuma'}</td><td>{row['ip_reputation']}</td><td>{'Sim' if row['anomaly'] == -1 else 'Não'}</td></tr>" for index, row in results_df.iterrows()])}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Dados para o gráfico de pizza
        var vulnerableData = {json.dumps(vulnerable_data)};
        var vulnerableLabels = vulnerableData.map(function(item) {{
            return item.vulnerable == 1 ? 'Vulnerable' : 'Safe';
        }});
        var vulnerableCounts = vulnerableData.map(function(item) {{
            return item.count;
        }});

        var ctx1 = document.getElementById('vulnerableChart').getContext('2d');
        var vulnerableChart = new Chart(ctx1, {{
            type: 'pie',
            data: {{
                labels: vulnerableLabels,
                datasets: [{{
                    data: vulnerableCounts,
                    backgroundColor: ['#FF6384', '#36A2EB'],
                }}]
            }},
            options: {{
                responsive: true,
                title: {{
                    display: true,
                    text: 'Distribuição de Conexões Vulneráveis e Seguras'
                }}
            }}
        }});

        // Dados para o gráfico de dispersão
        var connectionData = {json.dumps(connection_data)};
        var scatterData = connectionData.map(function(item) {{
            return {{
                x: item.laddr_ip,
                y: item.raddr_ip,
                v: item.vulnerable
            }};
        }});

        var ctx2 = document.getElementById('connectionsChart').getContext('2d');
        var connectionsChart = new Chart(ctx2, {{
            type: 'scatter',
            data: {{
                datasets: [{{
                    label: 'Conexões',
                    data: scatterData,
                    backgroundColor: scatterData.map(function(item) {{
                        return item.v == 1 ? '#FF6384' : '#36A2EB';
                    }}),
                }}]
            }},
            options: {{
                responsive: true,
                title: {{
                    display: true,
                    text: 'Conexões Vulneráveis vs. Seguras'
                }},
                scales: {{
                    x: {{
                        type: 'linear',
                        position: 'bottom',
                        title: {{
                            display: true,
                            text: 'Local Address IP'
                        }}
                    }},
                    y: {{
                        title: {{
                            display: true,
                            text: 'Remote Address IP'
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""

with open("network_security_report.html", "w", encoding="utf-8") as file:
    file.write(html_content)

print("Relatório de segurança de rede salvo em 'network_security_report.html'.")
