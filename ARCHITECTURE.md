# Arquitetura Técnica - IoT Shodan

## 📐 Visão Geral da Arquitetura

Este documento detalha a estrutura técnica, fluxos de dados e responsabilidades de cada módulo.

### Diagrama de Componentes

```
┌─────────────────────────────────────────────────────────┐
│                   CLI Interface                          │
│                  (main.py, argparse)                     │
└──────────────┬──────────────────────────────────────────┘
               │
        ┌──────▼─────────┐
        │  Config Layer  │
        │ (settings.py)  │
        │ (filters.json) │
        └──────┬─────────┘
               │
    ┌──────────┴────────────────────────┐
    │                                    │
┌───▼────────────────┐    ┌────────────▼──────────┐
│   Shodan Client    │    │  Vulnerability       │
│ (shodan_client.py) │───▶│  Detector            │
│                    │    │ (vuln_detector.py)   │
│ • API Connection   │    │                      │
│ • Query Builder    │    │ • Banner Analysis    │
│ • Rate Limiting    │    │ • Pattern Matching   │
│ • Error Handling   │    │ • CVE Detection      │
└────────────────────┘    └────────────┬─────────┘
                                       │
                          ┌────────────▼──────────┐
                          │  Report Generator    │
                          │(report_generator.py) │
                          │                      │
                          │ • JSON Export        │
                          │ • CSV Export         │
                          │ • Templating         │
                          └──────────────────────┘
```

## 🔄 Fluxo de Dados Principal

### 1. **Inicialização**

```python
1. Carregar .env → API Key, proxy settings
2. Carregar config/settings.py → Config padrão
3. Carregar config/filters.json → Filtros predefinidos
4. Inicializar logger → Sistema de logs
5. Conectar à API do Shodan → Validar credenciais
```

### 2. **Busca de Dispositivos**

```python
# Input: Filtro + Parâmetros
ShodanClient.search(
    query="port:554",           # Filtro Shodan
    limit=100,                   # Limite de resultados
    timeout=30                   # Timeout
)

# Process:
→ Validar query
→ Rate limiting check
→ Executar query na API
→ Parse resposta JSON
→ Estruturar resultados

# Output: Lista de dispositivos
[
    {
        "ip": "192.168.1.1",
        "port": 554,
        "banner": "RTSP/1.0",
        "product": "Hikvision",
        "org": "ISP Corp",
        ...
    },
    ...
]
```

### 3. **Detecção de Vulnerabilidades**

```python
VulnerabilityDetector.analyze(devices)

# Para cada dispositivo:
→ Analisar banner em busca de:
   - "admin" / "root" / "default" em texto
   - Versões conhecidas com CVEs
   - Erros HTTP 401/403 (auth fail)
   - Credenciais padrão mencionadas

→ Atribuir score de risco (1-10)
→ Marcar dispositivo com flags de vulnerabilidade

# Output: Devices enriquecidos com vulnerabilities
[
    {
        "ip": "192.168.1.1",
        "port": 554,
        ...,
        "vulnerabilities": [
            {
                "type": "default_credentials_hint",
                "severity": 8,
                "reason": "Banner contém 'admin'"
            },
            ...
        ],
        "risk_score": 8
    }
]
```

### 4. **Geração de Relatório**

```python
ReportGenerator.export(
    devices=devices,
    format="json",  # ou "csv"
    output_path="reports/cameras.json"
)

# Process:
→ Filtrar dispositivos (por risco, tipo, etc.)
→ Formatar dados
→ Adicionar metadados (timestamp, filtros, resumo)
→ Salvar arquivo

# Output: Arquivo JSON/CSV estruturado
```

## 📦 Módulos Detalhados

### config/settings.py

**Responsabilidade**: Centralizar configurações

```python
# Exemplo de estrutura
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
MAX_RESULTS = 100
TIMEOUT = 30
LOG_LEVEL = "INFO"

# Padrões de vulnerabilidades
VULN_PATTERNS = {
    "default_credentials": [
        r"(?i)(admin|root|default)",
        r"(?i)(password|pass|pwd).*\d+",
    ],
    "auth_errors": [401, 403],
    "known_cves": {
        "Hikvision": ["CVE-2021-1234", ...],
    }
}
```

### src/shodan_client.py

**Responsabilidade**: Interface com API do Shodan

```python
class ShodanClient:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
    
    def search(self, query, limit=100):
        """Buscar dispositivos com filtro"""
        
    def get_host_details(self, ip):
        """Detalhes completos de um host"""
        
    def rate_limit_check(self):
        """Verificar limites de taxa"""
```

### src/vuln_detector.py

**Responsabilidade**: Analisar vulnerabilidades

```python
class VulnerabilityDetector:
    def __init__(self, patterns_config):
        self.patterns = patterns_config
    
    def analyze_banner(self, banner, product):
        """Detectar padrões de vulnerabilidade"""
        
    def assign_risk_score(self, vulns):
        """Score 0-10 baseado em severidade"""
        
    def detect_known_cves(self, product, version):
        """Cruzar com banco de CVEs conhecido"""
```

### src/report_generator.py

**Responsabilidade**: Exportar relatórios

```python
class ReportGenerator:
    def to_json(self, devices, metadata):
        """Exportar em JSON estruturado"""
        
    def to_csv(self, devices, fields):
        """Exportar em CSV"""
        
    def generate_summary(self, devices):
        """Resumo executivo"""
```

## 🔐 Segurança

### Variáveis de Ambiente

```bash
# .env (nunca fazer commit)
SHODAN_API_KEY=xxxxxxxxxxxxx
LOG_LEVEL=INFO
PROXY=http://proxy.corp:8080  # Opcional
```

### Validações

- ✓ Validar query antes de enviar à API
- ✓ Sanitizar entrada do usuário
- ✓ Validar resposta JSON da API
- ✓ Não logar dados sensíveis
- ✓ Usar rate limiting para evitar sobrecarga

## 📊 Estrutura JSON de Saída

```json
{
  "metadata": {
    "timestamp": "2026-06-10T17:18:05",
    "query_filter": "port:554",
    "total_results": 1250,
    "exported_results": 100,
    "duration_seconds": 45
  },
  "summary": {
    "critical_vulnerabilities": 12,
    "high_risk_devices": 45,
    "medium_risk_devices": 38,
    "low_risk_devices": 5
  },
  "devices": [
    {
      "ip": "192.168.1.1",
      "port": 554,
      "product": "Hikvision Camera",
      "version": "5.4.0",
      "country": "BR",
      "org": "ISP Corp",
      "banner": "RTSP/1.0 200 OK",
      "risk_score": 8,
      "vulnerabilities": [
        {
          "type": "default_credentials_hint",
          "severity": 8,
          "evidence": "Banner contém 'admin'"
        }
      ]
    }
  ]
}
```

## 🧪 Estratégia de Testes

- **Testes unitários**: Cada módulo isolado
- **Testes de integração**: Fluxo completo com mock da API
- **Testes de dados**: Validação de estruturas JSON/CSV

## 🚀 Pipeline de Execução

```
1. Iniciar script → Load config
2. Validar API key
3. Ler filtro do usuário
4. Executar busca Shodan
5. Analisar vulnerabilidades
6. Gerar relatório
7. Salvar arquivo
8. Exibir resumo
```

---

**Próxima Fase**: Implementar módulos conforme especificado acima.
