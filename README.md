# IoT Shodan - Relatório de Dispositivos Expostos

Um script de reconhecimento profissional e seguro que utiliza a API do Shodan para identificar dispositivos IoT e câmeras expostos na internet, com foco em vulnerabilidades óbvias.

## 📋 Visão Geral do Projeto

Este projeto automatiza a busca, análise e relatório de dispositivos expostos usando:

- **Shodan API** para busca de dispositivos
- **Filtros inteligentes** para identificar vulnerabilidades comuns
- **Relatórios estruturados** em JSON/CSV para análise

## ⚠️ Aviso Legal e Ético

Este script é **exclusivamente para fins de pesquisa e segurança** sobre dispositivos autorizados. Apenas use em:
- Seus próprios dispositivos
- Redes autorizadas
- Pesquisa de segurança permitida
- Conformidade com CVSS e regulações locais

## 🎯 Fase 1: Escopo e Arquitetura

### Fluxo Básico do Script

```
1. Conectar à API do Shodan
   └─ Validar credenciais
   └─ Testar conectividade

2. Buscar por Dispositivos com Filtros
   ├─ Câmeras RTSP: port:554
   ├─ Impressoras: product:"HP LaserJet"
   ├─ Servidores Web: port:80 OR port:443
   └─ Filtros customizáveis via config

3. Filtrar Vulnerabilidades Óbvias
   ├─ Banners contendo "admin" ou "default"
   ├─ Respostas HTTP 401 (Unauthorized)
   ├─ Credenciais padrão detectadas
   └─ Versões conhecidas com CVEs

4. Gerar Relatório
   ├─ Formato JSON com estrutura padronizada
   ├─ Formato CSV para análise em Excel
   └─ Metadados: timestamp, filtros usados, total de resultados
```

### Estrutura do Projeto

```
iot-shodan/
├── README.md                    # Este arquivo
├── ARCHITECTURE.md              # Documentação detalhada da arquitetura
├── requirements.txt             # Dependências Python
├── config/
│   ├── __init__.py
│   ├── settings.py             # Configuração central
│   └── filters.json            # Filtros de busca predefinidos
├── src/
│   ├── __init__.py
│   ├── shodan_client.py        # Wrapper da API do Shodan
│   ├── vuln_detector.py        # Detector de vulnerabilidades
│   ├── report_generator.py     # Gerador de relatórios
│   └── logger.py               # Sistema de logging
├── tests/
│   ├── __init__.py
│   └── test_integration.py     # Testes de integração
├── reports/                    # Diretório de saída
│   └── .gitkeep
└── .env.example               # Template de variáveis de ambiente
```

## 🔧 Funcionalidades Planejadas

### Fase 1 (Atual): Arquitetura e Setup
- [x] Definir escopo do projeto
- [x] Criar estrutura de diretórios
- [ ] Configurar dependências
- [ ] Implementar autenticação na API do Shodan
- [ ] Criar módulo de logging

### Fase 2: Core Functionality
- [ ] Implementar cliente Shodan com rate limiting
- [ ] Criar filtros de busca customizáveis
- [ ] Implementar detector de vulnerabilidades
- [ ] Testar com queries reais

### Fase 3: Relatórios e Export
- [ ] Gerador de relatórios JSON
- [ ] Gerador de relatórios CSV
- [ ] Templates de relatório personalizável

### Fase 4: Enhancements
- [ ] CLI com argparse
- [ ] Agendamento de buscas
- [ ] Notificações
- [ ] Cache de resultados

## 🚀 Quick Start

```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. Configurar credenciais
cp .env.example .env
# Editar .env com sua chave da API do Shodan

# 3. Executar script (após Fase 2)
python main.py --filter port:554 --output reports/cameras.json
```

## 📚 Documentação

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detalhes técnicos da arquitetura
- [Documentação da API do Shodan](https://developer.shodan.io/)

## 📝 Notas

- Requisitos: Python 3.8+
- API Key do Shodan necessária (free tier disponível)
- Limites: 1 crédito por busca na API

---

**Status**: Phase 1 - Arquitetura & Setup ✓
