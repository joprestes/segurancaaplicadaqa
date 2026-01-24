---
layout: lesson
title: "Aula 2.2: DAST: Dynamic Application Security Testing"
slug: dast-testes-dinamicos
module: module-2
lesson_id: lesson-2-2
duration: "90 minutos"
level: "Intermediário"
prerequisites: ["lesson-2-1"]
exercises:
  - lesson-2-2-exercise-1-owasp-zap-setup
  - lesson-2-2-exercise-3-dast-cicd
  - lesson-2-2-exercise-3-false-positive-investigation
  - lesson-2-2-exercise-4-dast-report-analysis
video:
  file: "assets/module-2/videos/2.2-DAST_Testes_Dinamicos.mp4"
  title: "DAST: Dynamic Application Security Testing"
  thumbnail: "assets/module-2/images/infograficos/infografico-lesson-2-2.png"
image: "assets/module-2/images/podcasts/2.2-DAST_Testes_Dinamicos.png"
permalink: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

<!-- # Aula 2.2: DAST: Dynamic Application Security Testing -->

## ⚡ TL;DR (5 minutos)

**O que você vai aprender**: DAST testa aplicação em execução (runtime), simulando ataques reais de hackers sem acesso ao código-fonte.

**Por que importa**: 60% das vulnerabilidades só são detectáveis em runtime (misconfigurations, falhas de autenticação, IDOR). DAST complementa SAST.

**Ferramentas principais**: OWASP ZAP (open-source, gratuito), Burp Suite (comercial, mais completo), Acunetix (automatizado)

**Aplicação prática**: Baseline scan em cada MR (10-15 min), full scan noturno, pre-production scan antes de deploy em produção.

**Tempo de leitura completa**: 90 minutos  
**Exercícios**: 4 (2 básicos, 2 intermediários)

---

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- [ ] Compreender o que é DAST e sua importância no processo de testes de segurança
- [ ] Diferenciar DAST de outras metodologias de teste (SAST, IAST, SCA)
- [ ] Identificar as principais ferramentas DAST disponíveis no mercado
- [ ] Executar testes dinâmicos de segurança em aplicações reais
- [ ] Interpretar resultados de DAST e priorizar vulnerabilidades
- [ ] Integrar DAST em pipelines CI/CD
- [ ] Configurar scans automatizados e personalizados

---

## 📚 Introdução ao DAST

### O que é DAST?

**DAST (Dynamic Application Security Testing)** é uma metodologia de teste de segurança que analisa aplicações **em execução**, simulando ataques reais de hackers. Diferente do SAST que analisa código estático, DAST testa a aplicação "de fora para dentro", como um atacante real faria, sem acesso ao código-fonte.

#### 🎭 Analogia: Ladrão Testando Segurança vs Inspetor de Construção

Imagine a segurança de uma casa:

**SAST = Inspetor de Construção**:
- Examina as plantas da casa antes de construir
- Verifica se portas e janelas estão bem projetadas
- Identifica problemas estruturais no papel
- **Vantagem**: Encontra problemas antes da construção
- **Limitação**: Não testa se as fechaduras realmente funcionam

**DAST = Ladrão Tentando Invadir**:
- Testa a casa pronta, como um ladrão real faria
- Tenta abrir portas, quebrar janelas, encontrar pontos fracos
- Verifica se alarmes realmente funcionam
- **Vantagem**: Testa segurança em condições reais
- **Limitação**: Precisa que a casa esteja construída

Na segurança de software:
- **SAST** analisa código sem executar (planta da casa)
- **DAST** testa aplicação rodando (casa pronta)
- **Melhor abordagem**: Usar ambos complementarmente!

### Por que DAST é Importante?

#### O Valor Único do DAST

DAST encontra vulnerabilidades que SAST não consegue detectar:

```
┌─────────────────────────────────────────────────────────┐
│   O QUE DAST ENCONTRA QUE SAST NÃO CONSEGUE            │
│                                                         │
│  ✅ Problemas de configuração (servidor, rede, infra)  │
│  ✅ Vulnerabilidades de runtime (comportamento real)    │
│  ✅ Problemas de integração entre componentes          │
│  ✅ Vulnerabilidades em bibliotecas compiladas         │
│  ✅ Falhas de autenticação/autorização complexas       │
│  ✅ Issues de lógica de negócio                        │
│  ✅ Problemas de session management                    │
│                                                         │
│  Exemplo: SAST não detecta que servidor está           │
│  rodando com configuração insegura ou que               │
│  autenticação pode ser bypassada em runtime            │
└─────────────────────────────────────────────────────────┘
```

**Dados Reais (2025)**:
- **60%** das vulnerabilidades críticas só podem ser encontradas por DAST
- **45%** das breaches em produção poderiam ter sido evitadas com DAST
- DAST encontra em média **30% mais vulnerabilidades** que SAST sozinho
- Empresas que usam DAST + SAST reduzem breaches em **80%**

**Fonte**: Gartner Security Report 2025, Verizon DBIR 2025

#### Benefícios do DAST

| Benefício | Descrição | Impacto |
|-----------|-----------|---------|
| **Teste Black-Box Real** | Simula ataque real sem conhecimento do código | Encontra vulnerabilidades que atacantes reais encontrariam |
| **Detecta Runtime Issues** | Testa comportamento em execução real | Encontra problemas de configuração, integração e runtime |
| **Independente de Linguagem** | Funciona com qualquer tecnologia | Pode testar aplicações legadas, closed-source, APIs |
| **Valida Configuração** | Testa servidor, rede, infraestrutura | Encontra misconfigurations que SAST não vê |
| **Testa Ambiente Real** | Executa em staging/produção | Valida segurança em condições reais de uso |
| **Menos False Positives** | Explora vulnerabilidades de verdade | ~5-10% false positives vs 20-40% do SAST |

### Contexto Histórico do DAST

A evolução do DAST acompanhou o crescimento da web e das aplicações modernas:

```
Anos 1990 ──────────────────────────────────────────── 2026+
 │                                                        │
 ├─ 1990s    🔍 Scanners de Rede Básicos                │
 │          ┌──────────────────────────────────┐        │
 │          │ • Nmap, Nessus (network scanning)│        │
 │          │ • Detecta portas abertas          │        │
 │          │ • Não entende aplicações web     │        │
 │          └──────────────────────────────────┘        │
 │                                                        │
 ├─ 2000    🌐 Web Application Scanners Iniciais        │
 │          ┌──────────────────────────────────┐        │
 │          │ • Nikto, WebInspect               │        │
 │          │ • Foco em vulnerabilidades web   │        │
 │          │ • SQL Injection, XSS básico       │        │
 │          │ • Muito lento (dias para scan)    │        │
 │          └──────────────────────────────────┘        │
 │                                                        │
 ├─ 2008    🔥 OWASP ZAP e Ferramentas Open Source      │
 │          ┌──────────────────────────────────┐        │
 │          │ • OWASP ZAP (2010), Arachni       │        │
 │          │ • Democratização do DAST          │        │
 │          │ • Proxies interceptadores         │        │
 │          │ • Maior acessibilidade            │        │
 │          └──────────────────────────────────┘        │
 │                                                        │
 ├─ 2012    ⚡ Burp Suite Professional                   │
 │          ┌──────────────────────────────────┐        │
 │          │ • Ferramenta padrão da indústria │        │
 │          │ • Scanner avançado                │        │
 │          │ • Extensível (plugins)            │        │
 │          │ • Workflow completo de pentest    │        │
 │          └──────────────────────────────────┘        │
 │                                                        │
 ├─ 2016    🤖 DAST Automatizado em CI/CD                │
 │          ┌──────────────────────────────────┐        │
 │          │ • Integração com pipelines       │        │
 │          │ • Scans automáticos em staging    │        │
 │          │ • APIs REST/GraphQL scanning      │        │
 │          │ • Shift-Left Security             │        │
 │          └──────────────────────────────────┘        │
 │                                                        │
 ├─ 2020    🧠 DAST com IA/ML                            │
 │          ┌──────────────────────────────────┐        │
 │          │ • Machine Learning para crawling │        │
 │          │ • Redução de false positives      │        │
 │          │ • Smart fuzzing                   │        │
 │          │ • Adaptive testing                │        │
 │          └──────────────────────────────────┘        │
 │                                                        │
 └─ 2026+   🚀 DAST Moderno                              │
           ┌──────────────────────────────────┐        │
           │ • API-first testing               │        │
           │ • Kubernetes/Container scanning   │        │
           │ • GraphQL/gRPC native support     │        │
           │ • Real-time vulnerability feed    │        │
           │ • Integration com WAF/SIEM        │        │
           │ • Continuous DAST em produção     │        │
           └──────────────────────────────────┘        │
```

**Por que DAST se tornou fundamental?**

- **APIs em Todo Lugar**: Explosão de APIs REST/GraphQL que precisam de testes dinâmicos
- **Microserviços**: Arquiteturas complexas com muitos pontos de integração
- **Cloud Native**: Containers, Kubernetes exigem testes em runtime
- **DevSecOps**: Necessidade de testes automatizados em pipelines
- **Compliance**: Muitos padrões (PCI-DSS, SOC2, ISO 27001) exigem DAST
- **Zero Trust**: Validar segurança em todos os endpoints

---

## 🔄 DAST vs Outras Metodologias

### Comparação: SAST vs DAST vs IAST

DAST não funciona isoladamente - é parte de uma estratégia completa de testes de segurança. Vamos entender as diferenças:

#### Tabela Comparativa Completa

| Aspecto | SAST | DAST | IAST |
|---------|------|------|------|
| **Quando executa** | Antes de executar (código estático) | Aplicação em execução | Aplicação em execução (instrumentado) |
| **O que analisa** | Código-fonte, bytecode | Aplicação rodando (black-box) | Código em execução (white-box) |
| **Visão** | Inside-out (de dentro para fora) | Outside-in (de fora para dentro) | Inside-out + Outside-in |
| **Acesso ao Código** | Requer código-fonte | Não requer código-fonte | Requer instrumentação |
| **Vantagens** | ✅ Precoce, barato, cobre todo código<br>✅ Encontra vulnerabilidades no código<br>✅ Integra facilmente no CI/CD<br>✅ Não requer app rodando | ✅ Testa comportamento real<br>✅ Encontra runtime issues<br>✅ Testa configuração<br>✅ Menos false positives<br>✅ Simula ataques reais | ✅ Combina SAST e DAST<br>✅ Muito preciso<br>✅ Context-aware<br>✅ Real-time feedback |
| **Limitações** | ❌ Muitos false positives<br>❌ Não testa runtime<br>❌ Não vê configuração<br>❌ Não testa integração | ❌ Precisa de app rodando<br>❌ Mais lento que SAST<br>❌ Não mostra código vulnerável<br>❌ Cobertura limitada a paths testados | ❌ Requer instrumentação<br>❌ Overhead de performance<br>❌ Complexo de configurar<br>❌ Pode não rodar em produção |
| **False Positives** | 20-40% | 5-10% | 2-5% |
| **Cobertura de Código** | 100% (analisa todo código) | Variável (só testa o que executa) | Variável (só testa o que executa) |
| **Velocidade** | Rápido-Médio (minutos) | Lento (horas) | Médio (depende de execução) |
| **Custo** | Baixo-Médio | Médio-Alto | Alto |
| **Exemplos de Ferramentas** | SonarQube, Semgrep, Checkmarx | OWASP ZAP, Burp Suite, Acunetix | Contrast Security, Veracode IAST |
| **Melhor Para** | Desenvolvimento (shift-left) | Staging/QA (pré-produção) | Integração contínua |

### Diagrama: Posicionamento no SDLC

```
┌─────────────────────────────────────────────────────────┐
│  METODOLOGIAS DE TESTE NO SDLC                         │
│                                                         │
│  Requisitos → Design → Desenvolvimento → Testes → Prod │
│                                                         │
│     │          │            │            │       │     │
│     │          │            ▼            │       │     │
│     │          │        ┌───────┐       │       │     │
│     │          │        │ SAST  │       │       │     │
│     │          │        │(Code) │       │       │     │
│     │          │        └───┬───┘       │       │     │
│     │          │            │            │       │     │
│     │          │            ▼            ▼       │     │
│     │          │        ┌───────┐   ┌───────┐  │     │
│     │          │        │  SCA  │   │ IAST  │  │     │
│     │          │        │(Deps) │   │(Instr)│  │     │
│     │          │        └───────┘   └───┬───┘  │     │
│     │          │            │            │       │     │
│     │          │            ▼            ▼       ▼     │
│     │          │                    ┌───────┐ ┌─────┐ │
│     │          │                    │ DAST  │ │Prod │ │
│     │          │                    │(Run)  │ │Mon. │ │
│     │          │                    └───────┘ └─────┘ │
│                                                         │
│  SAST: Encontra cedo (código)                         │
│  DAST: Valida execução real (runtime)                 │
│  IAST: Combina ambos (instrumentado)                  │
└─────────────────────────────────────────────────────────┘
```

### Exemplo Prático: SQL Injection

Vamos ver como cada metodologia detecta a mesma vulnerabilidade:

```java
// Código Vulnerável
@GetMapping("/users/{id}")
public User getUser(@PathVariable String id) {
    String query = "SELECT * FROM users WHERE id = " + id;
    return db.executeQuery(query);  // ❌ SQL Injection
}
```

**Como SAST detecta**:
```
✅ SAST (SonarQube):
- Analisa código-fonte
- Detecta concatenação de string em query SQL
- Reporta: "SQL Injection potencial na linha 3"
- Encontra: Durante desenvolvimento (antes de executar)
- Precisão: 80% (pode ser false positive se houver validação)
```

**Como DAST detecta**:
```
✅ DAST (OWASP ZAP):
- Testa aplicação rodando
- Envia payload: GET /users/1' OR '1'='1
- Observa resposta (retorna múltiplos usuários)
- Reporta: "SQL Injection confirmado - exploitável"
- Encontra: Durante testes (aplicação em execução)
- Precisão: 95% (confirma exploit real)
```

**Como IAST detecta**:
```
✅ IAST (Contrast Security):
- Instrumenta aplicação em execução
- Rastreia dados desde entrada até query
- Detecta: Input não sanitizado + query vulnerável
- Reporta: "SQL Injection na linha 3 - exploitável com payload X"
- Encontra: Durante testes (com código instrumentado)
- Precisão: 98% (melhor dos dois mundos)
```

### Quando Usar Cada Abordagem

**DAST é ideal quando**:
- ✅ Você quer validar segurança em runtime
- ✅ Precisa testar configuração de servidor/infraestrutura
- ✅ Quer simular ataques reais
- ✅ Precisa testar aplicações sem código-fonte (third-party, legado)
- ✅ Quer validar correções de vulnerabilidades em ambiente real
- ✅ Precisa testar autenticação/autorização complexa
- ✅ Quer testar APIs públicas

**DAST não é suficiente quando**:
- ❌ Você precisa encontrar vulnerabilidades durante desenvolvimento
- ❌ Precisa analisar código-fonte diretamente
- ❌ Quer cobertura de 100% do código (DAST só testa o que executa)
- ❌ Precisa de feedback instantâneo no commit

**Conclusão**: DAST deve ser combinado com SAST, SCA e IAST para cobertura completa!

### Matriz de Decisão: Qual Metodologia Usar?

| Cenário | Recomendação |
|---------|-------------|
| **Novo código sendo desenvolvido** | SAST (shift-left) + DAST em staging |
| **Código legado sem testes** | DAST primeiro (validar segurança atual) |
| **API pública REST/GraphQL** | DAST (testar endpoints expostos) |
| **Aplicação third-party** | DAST apenas (sem código-fonte) |
| **Microserviços complexos** | DAST (testar integração) + IAST |
| **Aplicação com dados sensíveis** | SAST + DAST + Pentest manual |
| **Pipeline CI/CD rápido** | SAST (rápido) + DAST incremental |
| **Validação pré-produção** | DAST completo + Security Review |

---

## 🔧 Ferramentas DAST Principais

### 1. OWASP ZAP (Zed Attack Proxy)

**Definição**: Ferramenta open-source líder mundial para testes de segurança em aplicações web. Mantida pela OWASP, é gratuita, multiplataforma e amplamente usada tanto por iniciantes quanto profissionais.

**Características principais**:
- ✅ **100% Open Source e Gratuito**
- ✅ **Proxy Interceptador**: Captura e modifica requisições HTTP/HTTPS
- ✅ **Scanner Automatizado**: Detecta vulnerabilidades OWASP Top 10
- ✅ **Spider/Crawler**: Mapeia automaticamente aplicação
- ✅ **API Scanning**: Suporta REST, SOAP, GraphQL
- ✅ **Fuzzing**: Testa inputs com payloads maliciosos
- ✅ **Integração CI/CD**: Linha de comando + Docker
- ✅ **Extensível**: Marketplace de plugins

**Quando usar**: 
- Times com orçamento limitado
- Aprendizado e treinamento
- Integração em pipelines CI/CD
- Testes automatizados de APIs
- Projetos open-source

**Exemplo prático - Scan Básico**:
```bash
# Instalação (Docker)
docker pull owasp/zap2docker-stable

# Scan básico de aplicação
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://exemplo.com \
  -r report.html

# Scan completo (mais demorado)
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t https://exemplo.com \
  -r report.html

# Scan de API com OpenAPI spec
docker run -t owasp/zap2docker-stable zap-api-scan.py \
  -t https://api.exemplo.com/openapi.json \
  -f openapi \
  -r api-report.html
```

**Exemplo prático - Integração CI/CD (GitHub Actions)**:
```yaml
# .github/workflows/zap-scan.yml
name: OWASP ZAP Scan

on:
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '0 2 * * *'  # Scan diário às 2h

jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Deploy to staging
        run: |
          # Deploy sua aplicação para staging
          # docker-compose up -d staging
      
      - name: Wait for app to be ready
        run: |
          timeout 60 bash -c 'until curl -s http://localhost:3000/health; do sleep 2; done'
      
      - name: OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:3000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
      
      - name: Upload ZAP Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: zap-report
          path: report_html.html
```

**Dashboard ZAP**:
```
┌─────────────────────────────────────────────────────────┐
│  OWASP ZAP SCAN RESULTS                                │
│                                                         │
│  Target: https://exemplo.com                           │
│  Scan Duration: 45 minutes                             │
│                                                         │
│  Vulnerabilities Found:                                │
│  ├─ High Risk: 3                                       │
│  │  ├─ SQL Injection (GET /users?id=)                 │
│  │  ├─ XSS Reflected (POST /search)                   │
│  │  └─ Authentication Bypass (GET /admin)             │
│  ├─ Medium Risk: 8                                     │
│  ├─ Low Risk: 15                                       │
│  └─ Informational: 22                                  │
│                                                         │
│  URLs Crawled: 342                                     │
│  Requests Sent: 1,847                                  │
└─────────────────────────────────────────────────────────┘
```

### 2. Burp Suite

**Definição**: Ferramenta profissional e padrão da indústria para testes de segurança web. Combina proxy interceptador com scanner automatizado e ferramentas de exploração manual.

**Características principais**:
- ✅ **Versões**: Community (grátis), Professional (pago ~$400/ano), Enterprise (corporativo)
- ✅ **Proxy Avançado**: Interceptação, modificação, replay de requisições
- ✅ **Scanner Profissional**: Muito preciso, baixo false positive (~5%)
- ✅ **Intruder**: Fuzzing e ataques automatizados customizados
- ✅ **Repeater**: Modifica e re-envia requisições manualmente
- ✅ **Sequencer**: Analisa qualidade de tokens/session IDs
- ✅ **Decoder/Comparer**: Manipula dados codificados
- ✅ **Extensível**: BApp Store com centenas de plugins
- ✅ **Colaboração**: Burp Collaborator para detectar blind vulnerabilities

**Quando usar**:
- Pentest profissional e auditorias
- Testes manuais profundos
- Bug bounty hunting
- Exploração de vulnerabilidades complexas
- Times com orçamento para ferramentas comerciais

**Exemplo prático - Workflow Típico**:
```
┌─────────────────────────────────────────────────────────┐
│         BURP SUITE WORKFLOW                            │
└─────────────────────────────────────────────────────────┘

1. CONFIGURAR PROXY
   ├─ Configurar navegador para usar Burp como proxy
   ├─ Burp escuta em localhost:8080
   └─ Instalar certificado CA do Burp

2. SPIDER/CRAWL
   ├─ Navegar manualmente na aplicação
   ├─ Burp mapeia automaticamente a aplicação
   └─ Target → Site map completo

3. SCAN AUTOMATIZADO
   ├─ Selecionar endpoints críticos
   ├─ Scanner → New Scan
   ├─ Configurar scan (passive/active)
   └─ Aguardar resultados

4. EXPLORAÇÃO MANUAL
   ├─ Proxy → HTTP history
   ├─ Encontrar requisição interessante
   ├─ Send to Repeater
   ├─ Modificar payload (SQL Injection, XSS, etc.)
   └─ Observar resposta

5. FUZZING (Intruder)
   ├─ Send to Intruder
   ├─ Configurar payloads (wordlists, números, etc.)
   ├─ Attack type (Sniper, Battering Ram, Pitchfork)
   └─ Analisar respostas (status codes, length, errors)

6. VALIDAR FINDINGS
   ├─ Confirmar vulnerabilidade
   ├─ Documentar exploit
   └─ Criar relatório
```

**Exemplo - Detectar SQL Injection com Burp**:
```http
# Requisição Original (Proxy → HTTP history)
GET /users?id=1 HTTP/1.1
Host: exemplo.com
Cookie: session=abc123

Response: {"id": 1, "name": "João", "email": "joao@exemplo.com"}

# Send to Repeater → Testar SQL Injection
GET /users?id=1' OR '1'='1 HTTP/1.1
Host: exemplo.com

Response: [{"id": 1, "name": "João"}, {"id": 2, "name": "Maria"}, ...]
✅ SQL Injection confirmado! Retorna múltiplos usuários

# Send to Intruder → Fuzzing para explorar
GET /users?id=§PAYLOAD§ HTTP/1.1
Payloads:
  - 1' OR '1'='1
  - 1' UNION SELECT NULL,NULL,NULL--
  - 1' AND 1=1--
  - ...

Análise:
  - Payload 2 retorna 200 OK, length 1524
  - Payload confirma 3 colunas na tabela
  - Exploit: 1' UNION SELECT username,password,email FROM admin--
```

### 3. Acunetix

**Definição**: Scanner DAST comercial enterprise-grade com foco em velocidade e precisão. Muito usado em empresas grandes para scans regulares e compliance.

**Características principais**:
- ✅ **Comercial** (caro, ~$5000-15000/ano)
- ✅ **Muito Rápido**: Scans completos em minutos
- ✅ **Baixíssimo False Positive**: ~2-3% (melhor da categoria)
- ✅ **Suporte Avançado**: JavaScript rendering, SPA, AJAX
- ✅ **Integração**: Jenkins, Azure DevOps, Jira
- ✅ **Compliance Reports**: PCI-DSS, HIPAA, SOC2
- ✅ **Network Scanning**: Combina web + network scans
- ✅ **API Scanning**: REST, SOAP, GraphQL, XML-RPC

**Quando usar**:
- Empresas grandes com muitas aplicações
- Necessidade de scans frequentes e rápidos
- Compliance rigoroso (PCI-DSS, HIPAA)
- Budget disponível para ferramenta comercial
- Times de segurança dedicados

**Exemplo - Configuração de Scan**:
```yaml
# Acunetix Scan Configuration
target:
  url: https://exemplo.com
  description: "Aplicação Produção"
  
scan_profile: "Full Scan"  # ou "Quick Scan", "High Risk"

authentication:
  type: "form_based"
  login_url: https://exemplo.com/login
  username: test_user
  password: $ACUNETIX_TEST_PASSWORD
  
crawl_configuration:
  max_crawl_depth: 10
  max_page_count: 1000
  spider_type: "advanced"  # JavaScript rendering
  
scan_options:
  enable_network_scan: true
  check_ssl_configuration: true
  test_http_methods: true
  
scheduling:
  frequency: "weekly"
  day_of_week: "sunday"
  time: "02:00"
  
notifications:
  email: security@exemplo.com
  slack_webhook: $SLACK_WEBHOOK
  send_on: ["scan_complete", "high_severity_found"]
```

### Comparação Rápida das 3 Ferramentas

| Aspecto | OWASP ZAP | Burp Suite Pro | Acunetix |
|---------|-----------|----------------|----------|
| **Custo** | Grátis | ~$400/ano | ~$5000-15000/ano |
| **Velocidade** | Médio (horas) | Médio-Lento (horas) | Muito Rápido (minutos) |
| **Precisão** | Média (10-15% FP) | Alta (5-10% FP) | Muito Alta (2-3% FP) |
| **False Positives** | Médios | Baixos | Muito Baixos |
| **Facilidade de Uso** | Alta | Média | Muito Alta |
| **Integração CI/CD** | Excelente | Boa | Excelente |
| **API Testing** | Bom | Excelente | Excelente |
| **JavaScript/SPA** | Limitado | Bom | Excelente |
| **Extensibilidade** | Alta (plugins) | Muito Alta (BApps) | Média |
| **Suporte** | Comunidade | Oficial | Oficial Premium |
| **Melhor Para** | Times pequenos/médios, aprendizado, CI/CD | Pentest profissional, exploração manual | Empresas grandes, compliance, scans frequentes |
| **Curva de Aprendizado** | Baixa | Média-Alta | Baixa |

### Ferramentas DAST Adicionais por Caso de Uso

#### Para APIs: Postman + Newman

**Definição**: Postman é ferramenta popular de desenvolvimento de APIs que também oferece testes de segurança.

**Uso Prático**:
```javascript
// Postman Collection - Security Tests
{
  "name": "API Security Tests",
  "item": [
    {
      "name": "Test SQL Injection",
      "request": {
        "method": "GET",
        "url": "{{baseUrl}}/users?id=1' OR '1'='1"
      },
      "event": [
        {
          "listen": "test",
          "script": {
            "exec": [
              "pm.test('Should not return multiple users', function() {",
              "  pm.expect(pm.response.json().length).to.equal(1);",
              "});"
            ]
          }
        }
      ]
    },
    {
      "name": "Test XSS",
      "request": {
        "method": "POST",
        "url": "{{baseUrl}}/comments",
        "body": {
          "mode": "raw",
          "raw": "{\"comment\": \"<script>alert('XSS')</script>\"}"
        }
      },
      "event": [
        {
          "listen": "test",
          "script": {
            "exec": [
              "pm.test('Should sanitize XSS payload', function() {",
              "  pm.expect(pm.response.text()).to.not.include('<script>');",
              "});"
            ]
          }
        }
      ]
    }
  ]
}
```

#### Para GraphQL: GraphQL Voyager + InQL Scanner

**Uso Prático**:
```bash
# InQL Scanner (Burp Suite Extension)
# Detecta vulnerabilidades específicas de GraphQL:
# - Introspection enabled
# - Deep query nesting (DoS)
# - Field duplication attacks
# - Batch query abuse

# Exemplo de ataque detectado
query {
  user(id: 1) {
    name
    posts {
      title
      comments {
        text
        author {
          posts {
            comments {
              # ... nested 100 levels (DoS)
            }
          }
        }
      }
    }
  }
}
```

#### Para Containers: Trivy + Anchore

**Uso Prático**:
```bash
# Trivy - Scanner de vulnerabilidades em containers
trivy image --severity HIGH,CRITICAL \
  --format json \
  --output results.json \
  myapp:latest

# Anchore - Análise profunda de imagens Docker
anchore-cli image add myapp:latest
anchore-cli image wait myapp:latest
anchore-cli image vuln myapp:latest all
```

---

## 📋 Tipos de Testes DAST

### 1. Passive Scanning (Análise Passiva)

**Definição**: Análise de tráfego HTTP/HTTPS sem enviar requisições adicionais ou modificar a aplicação. Apenas observa e analisa requisições/respostas existentes.

**Como Funciona**:
```
┌─────────────────────────────────────────────────────────┐
│         PASSIVE SCANNING WORKFLOW                      │
└─────────────────────────────────────────────────────────┘

1. Usuário ou Spider Navega na Aplicação
   │
   ▼
2. DAST Tool Intercepta e Registra Tráfego
   ├─ Requisições HTTP/HTTPS
   ├─ Respostas do servidor
   ├─ Headers
   ├─ Cookies
   └─ Conteúdo HTML/JSON
   │
   ▼
3. Análise Passiva (SEM enviar novas requisições)
   ├─ Analisa headers de segurança
   ├─ Detecta informações sensíveis expostas
   ├─ Verifica configurações SSL/TLS
   ├─ Identifica versões de software nos headers
   └─ Analisa cookies (Secure, HttpOnly, SameSite)
   │
   ▼
4. Reporta Findings
   └─ Vulnerabilidades encontradas sem ataques ativos
```

**O que Passive Scanning Detecta**:
- ❌ **Missing Security Headers**:
  - `X-Frame-Options` ausente → Clickjacking risk
  - `Content-Security-Policy` ausente → XSS risk
  - `Strict-Transport-Security` ausente → MitM risk
  - `X-Content-Type-Options` ausente → MIME sniffing risk

- ❌ **Informações Sensíveis Expostas**:
  - Versões de software em headers (`Server: Apache/2.4.1`)
  - Stack traces em páginas de erro
  - Comentários HTML com informações internas
  - Tokens/secrets expostos em JavaScript

- ❌ **Configurações Inseguras de Cookies**:
  - Cookie sem flag `Secure` (enviado via HTTP)
  - Cookie sem flag `HttpOnly` (acessível via JavaScript)
  - Cookie sem `SameSite` (CSRF risk)

- ❌ **Problemas de SSL/TLS**:
  - Certificado expirado ou inválido
  - Cipher suites fracos
  - Protocolos inseguros (SSLv3, TLS 1.0)

**Vantagens**:
- ✅ Seguro (não ataca aplicação)
- ✅ Rápido (análise em tempo real)
- ✅ Pode rodar em produção (sem risco)
- ✅ Não gera logs de ataque
- ✅ Não aumenta carga no servidor

**Limitações**:
- ❌ Não detecta vulnerabilidades que requerem exploração
- ❌ Limitado a análise de tráfego observado
- ❌ Não testa SQL Injection, XSS, etc. ativamente

**Exemplo Prático - OWASP ZAP Passive Scan**:
```bash
# Iniciar ZAP em modo daemon
zap.sh -daemon -port 8080

# Configurar navegador para usar ZAP como proxy (localhost:8080)

# Navegar manualmente na aplicação
# ZAP captura e analisa passivamente todo o tráfego

# Ver resultados de passive scanning
zap-cli alerts --alert-level Medium High

# Exemplo de output:
# Medium: Missing Anti-clickjacking Header
#   URL: https://exemplo.com/
#   Header 'X-Frame-Options' not found
#
# High: Cookie Without Secure Flag
#   URL: https://exemplo.com/login
#   Cookie 'session_id' set without Secure flag
```

### 2. Active Scanning (Análise Ativa)

**Definição**: Envia requisições maliciosas para testar vulnerabilidades, simulando ataques reais. Tenta explorar vulnerabilidades ativamente.

**Como Funciona**:
```
┌─────────────────────────────────────────────────────────┐
│         ACTIVE SCANNING WORKFLOW                       │
└─────────────────────────────────────────────────────────┘

1. Crawl/Spider da Aplicação
   ├─ Mapeia todos os endpoints
   ├─ Descobre formulários
   ├─ Identifica parâmetros de entrada
   └─ Constrói mapa de ataque
   │
   ▼
2. Identificação de Pontos de Injeção
   ├─ Parâmetros GET/POST
   ├─ Headers HTTP
   ├─ Cookies
   └─ File uploads
   │
   ▼
3. Envio de Payloads Maliciosos
   ├─ SQL Injection payloads
   ├─ XSS payloads
   ├─ Command Injection
   ├─ Path Traversal
   ├─ XXE payloads
   └─ ... centenas de payloads por vulnerabilidade
   │
   ▼
4. Análise de Respostas
   ├─ Detecta comportamento anormal
   ├─ Compara com baseline
   ├─ Confirma exploits
   └─ Classifica severidade
   │
   ▼
5. Reporta Vulnerabilidades Confirmadas
   └─ Vulnerabilidades exploitáveis com evidências
```

**O que Active Scanning Detecta**:
- ❌ **SQL Injection**: Payloads que manipulam queries
- ❌ **XSS**: Scripts que executam no navegador
- ❌ **Command Injection**: Comandos OS executados
- ❌ **Path Traversal**: Acesso a arquivos fora do escopo
- ❌ **XXE**: External entity injection em XML
- ❌ **SSRF**: Server-side request forgery
- ❌ **Authentication Bypass**: Acesso não autorizado
- ❌ **Authorization Issues**: Privilege escalation

**Vantagens**:
- ✅ Detecta vulnerabilidades reais e exploitáveis
- ✅ Confirma exploits com evidências
- ✅ Testa todas as OWASP Top 10
- ✅ Automatizado (não requer intervenção)

**Limitações**:
- ❌ Pode danificar aplicação (dados, estado)
- ❌ Lento (horas para scans completos)
- ❌ Gera muitos logs (ataques)
- ❌ Não deve rodar em produção (riscos)
- ❌ Pode ter false positives (5-10%)

**⚠️ ATENÇÃO**: Active scanning só deve ser executado em ambientes de teste/staging com autorização explícita!

**Exemplo Prático - OWASP ZAP Active Scan**:
```bash
# Scan ativo completo
zap-cli active-scan --recursive \
  --scanners all \
  -u https://staging.exemplo.com

# Scan ativo específico (apenas SQL Injection)
zap-cli active-scan \
  --scanners 40018,40019,40020,40021 \
  -u https://staging.exemplo.com/api/users

# Ver progresso
zap-cli status

# Ver alertas encontrados
zap-cli alerts --alert-level High

# Exemplo de output:
# High: SQL Injection
#   URL: https://staging.exemplo.com/api/users?id=1
#   Payload: 1' AND '1'='1
#   Evidence: SQL syntax error in response
#   Confidence: High
```

### 3. Authenticated Scanning (Análise Autenticada)

**Definição**: Testa aplicação após login, validando áreas protegidas e vulnerabilidades que só existem para usuários autenticados.

**Por Que É Importante**:
```
┌─────────────────────────────────────────────────────────┐
│   POR QUE AUTHENTICATED SCANNING É CRÍTICO             │
│                                                         │
│  60-80% das vulnerabilidades estão em áreas            │
│  autenticadas que scans não-autenticados não veem!     │
│                                                         │
│  Exemplos:                                             │
│  - Privilege Escalation (user → admin)                │
│  - IDOR (access other user's data)                    │
│  - Business logic flaws                               │
│  - Admin panel vulnerabilities                        │
│  - User profile manipulation                          │
└─────────────────────────────────────────────────────────┘
```

**Como Configurar**:
{% raw %}
```yaml
# OWASP ZAP Context Configuration
authentication:
  type: form_based
  login_url: https://exemplo.com/login
  login_request_data: "username={%username%}&password={%password%}"
  username_parameter: username
  password_parameter: password
  
  credentials:
    - username: test_user
      password: ${TEST_USER_PASSWORD}
    - username: admin_user
      password: ${ADMIN_USER_PASSWORD}

session_management:
  type: cookie_based
  session_token_name: sessionid

verification:
  logged_in_indicator: '<a href="/logout">Logout</a>'
  logged_out_indicator: '<form id="login">'
```
{% endraw %}

**Exemplo - Burp Suite Authenticated Scan**:
```
1. Configurar Session Handling Rules
   ├─ Project Options → Sessions
   ├─ Add → Rule Action: Run a macro
   └─ Macro: Login sequence (username/password)

2. Configurar Credentials
   ├─ Add username/password
   └─ Configure login URL

3. Executar Scan Autenticado
   ├─ Target → Site map
   ├─ Selecionar área autenticada
   ├─ Scanner → New Scan
   ├─ Select: Use configured credentials
   └─ Start scan

4. Verificar Sessão Durante Scan
   ├─ Burp mantém sessão ativa
   ├─ Re-autentica se sessão expirar
   └─ Testa áreas protegidas
```

### 4. API Scanning

**Definição**: Testes específicos para APIs REST, SOAP, GraphQL. Foca em vulnerabilidades únicas de APIs.

**Vulnerabilidades Específicas de APIs**:
- ❌ **Mass Assignment**: Campos não esperados aceitos
- ❌ **Broken Object Level Authorization (BOLA)**: Acesso a objetos de outros usuários
- ❌ **Excessive Data Exposure**: API retorna mais dados que necessário
- ❌ **Lack of Rate Limiting**: Permite abuse/brute force
- ❌ **Broken Authentication**: Tokens fracos, JWT inseguro
- ❌ **Injection**: SQL, NoSQL, Command Injection via API
- ❌ **Security Misconfiguration**: CORS, métodos HTTP desnecessários

**Exemplo - Testar BOLA com OWASP ZAP**:
```bash
# 1. Crawl da API com OpenAPI spec
zap-cli open-api -f https://api.exemplo.com/openapi.json

# 2. Configurar autenticação (usuário normal)
zap-cli context add api-context \
  --url "https://api.exemplo.com/*" \
  --auth-form-url https://api.exemplo.com/login \
  --auth-username user1 \
  --auth-password pass123

# 3. Active scan focado em APIs
zap-cli active-scan \
  --recursive \
  --context api-context \
  -u https://api.exemplo.com

# 4. Testes manuais de BOLA (Repeater)
# Request original (user1):
GET /api/users/123/orders HTTP/1.1
Authorization: Bearer <token_user1>
Response: [{"order_id": 456, "total": 100.00}]

# Testar acesso a dados de outro usuário (user2):
GET /api/users/789/orders HTTP/1.1
Authorization: Bearer <token_user1>
Expected: 403 Forbidden
Vulnerable: 200 OK [{"order_id": 999, "total": 500.00}]
✅ BOLA detected!
```

**GraphQL Specific Tests**:
```graphql
# 1. Introspection Query (deve estar desabilitado em prod)
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

# Se retornar schema completo = vulnerabilidade

# 2. Deep Query Nesting (DoS)
{
  user(id: 1) {
    posts {
      comments {
        author {
          posts {
            comments {
              # ... nested 100 levels
            }
          }
        }
      }
    }
  }
}

# Se não limitar profundidade = DoS risk

# 3. Batch Query Abuse
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  user3: user(id: 3) { name }
  # ... 1000 vezes
}

# Se não limitar batch = DoS risk
```

### 5. Compliance Scanning

**Definição**: Testes específicos para verificar conformidade com padrões de segurança (PCI-DSS, HIPAA, GDPR/LGPD, etc.).

**PCI-DSS Compliance Tests**:
- ✅ SSL/TLS configurado corretamente (req 4.1)
- ✅ Autenticação forte (req 8.2)
- ✅ Logs de auditoria (req 10.1)
- ✅ Dados de cartão não expostos (req 3.4)
- ✅ Vulnerabilidades conhecidas corrigidas (req 6.2)
- ✅ Firewall e segmentação de rede (req 1.2)

**LGPD Compliance Tests**:
- ✅ Dados pessoais criptografados
- ✅ Consentimento explícito implementado
- ✅ Direito ao esquecimento (exclusão de dados)
- ✅ Logs de acesso a dados sensíveis
- ✅ Notificação de breach implementada

**Exemplo - Acunetix Compliance Scan**:
```yaml
# PCI-DSS Compliance Scan Configuration
compliance_profile: PCI_DSS_3.2.1

checks:
  - ssl_tls_configuration
  - authentication_mechanisms
  - session_management
  - access_control
  - input_validation
  - error_handling
  - logging_monitoring
  - secure_transmission
  - cryptographic_controls

report_format: pdf
report_include:
  - executive_summary
  - compliance_status_by_requirement
  - failed_requirements_details
  - remediation_guidance
  - evidence_screenshots
```

---

## 🎯 Exemplos Práticos

### Exemplo 1: Scan Completo de Aplicação Web com OWASP ZAP

**Cenário**: Testar aplicação web Node.js/Express em staging antes de deploy para produção.

**Requisitos**:
- Aplicação rodando em https://staging.exemplo.com
- Credenciais de teste: `test_user` / `Test@123`
- OpenAPI spec disponível em `/api/openapi.json`

**Passos**:

**1. Preparar Ambiente**
```bash
# Instalar OWASP ZAP (Docker)
docker pull owasp/zap2docker-stable

# Criar diretório para resultados
mkdir zap-reports

# Definir variáveis
export TARGET_URL="https://staging.exemplo.com"
export ZAP_API_KEY="your-api-key-here"
```

**2. Executar Passive Scan Inicial (Seguro)**
```bash
# Baseline scan (passive + spider)
docker run -v $(pwd)/zap-reports:/zap/wrk/:rw \
  -t owasp/zap2docker-stable zap-baseline.py \
  -t $TARGET_URL \
  -r baseline-report.html \
  -J baseline-report.json

# Analisar resultados iniciais
cat zap-reports/baseline-report.json | jq '.site[].alerts[] | select(.riskcode | tonumber > 1)'
```

**3. Configurar Autenticação**
{% raw %}
```bash
# Criar arquivo de contexto com autenticação
cat > auth-config.yaml <<EOF
env:
  contexts:
    - name: staging-context
      urls:
        - $TARGET_URL
      authentication:
        method: form
        loginUrl: $TARGET_URL/login
        loginRequestData: 'username={%username%}&password={%password%}'
      users:
        - name: test_user
          credentials:
            username: test_user
            password: Test@123
      sessionManagement:
        method: cookie
        cookieName: connect.sid
EOF
```
{% endraw %}

**4. Executar Full Scan (Passive + Active)**
```bash
# Full scan com autenticação
docker run -v $(pwd)/zap-reports:/zap/wrk/:rw \
  -t owasp/zap2docker-stable zap-full-scan.py \
  -t $TARGET_URL \
  -r full-scan-report.html \
  -J full-scan-report.json \
  -n auth-config.yaml \
  -a  # Include alpha scanners
```

**5. Scan de API com OpenAPI**
```bash
# API scan específico
docker run -v $(pwd)/zap-reports:/zap/wrk/:rw \
  -t owasp/zap2docker-stable zap-api-scan.py \
  -t $TARGET_URL/api/openapi.json \
  -f openapi \
  -r api-scan-report.html \
  -J api-scan-report.json
```

**6. Analisar Resultados e Priorizar**
```bash
# Filtrar apenas High/Critical
cat zap-reports/full-scan-report.json | \
  jq '.site[].alerts[] | select(.riskcode | tonumber >= 3) | {
    risk: .riskdesc,
    alert: .alert,
    url: .url,
    description: .desc,
    solution: .solution
  }'

# Contar vulnerabilidades por severidade
echo "Critical: $(cat zap-reports/full-scan-report.json | jq '[.site[].alerts[] | select(.riskcode == "3")] | length')"
echo "High: $(cat zap-reports/full-scan-report.json | jq '[.site[].alerts[] | select(.riskcode == "2")] | length')"
echo "Medium: $(cat zap-reports/full-scan-report.json | jq '[.site[].alerts[] | select(.riskcode == "1")] | length')"
```

**Resultado esperado**: 
- Relatórios HTML/JSON gerados
- Lista de vulnerabilidades priorizadas
- Evidências de exploits confirmados
- Recomendações de correção

### Exemplo 2: Exploração Manual de SQL Injection com Burp Suite

**Cenário**: Validar manualmente suspeita de SQL Injection encontrada por DAST automatizado.

**Passos**:

**1. Configurar Burp Suite**
```
1. Iniciar Burp Suite Community/Pro
2. Proxy → Options → Proxy Listeners: localhost:8080
3. Configurar navegador para usar proxy
4. Proxy → Intercept: Intercept is on
```

**2. Capturar Requisição Vulnerável**
```http
# Navegar até: https://exemplo.com/users?id=1
# Burp captura:

GET /users?id=1 HTTP/1.1
Host: exemplo.com
User-Agent: Mozilla/5.0...
Cookie: session=abc123xyz
```

**3. Enviar para Repeater e Testar Payloads**
```http
# Test 1: Sintaxe SQL básica
GET /users?id=1' HTTP/1.1
Response: 500 Internal Server Error
SQL syntax error...
✅ Confirma vulnerabilidade!

# Test 2: Boolean-based blind
GET /users?id=1' AND '1'='1 HTTP/1.1
Response: 200 OK (usuário ID 1)

GET /users?id=1' AND '1'='2 HTTP/1.1
Response: 200 OK (vazio)
✅ Confirma SQL Injection blind!

# Test 3: Extrair dados (UNION)
GET /users?id=1' UNION SELECT NULL,NULL,NULL-- HTTP/1.1
Response: 200 OK
✅ Confirma 3 colunas!

# Test 4: Extrair dados sensíveis
GET /users?id=1' UNION SELECT username,password,email FROM admin-- HTTP/1.1
Response: 200 OK
{"users": [
  {"id": "admin", "name": "$2a$10$hashedpassword", "email": "admin@exemplo.com"}
]}
✅ Exploit confirmado! Dados de admin expostos!
```

**4. Automatizar com Intruder (Fuzzing)**
```
1. Send to Intruder (Ctrl+I)
2. Clear all positions (Clear §)
3. Add position: id=§1§
4. Payloads → Load: sqlmap-payloads.txt
5. Start attack
6. Analisar: Length, Status code, Response time
7. Payloads bem-sucedidos: Response length diferente
```

**5. Documentar Exploit**
```markdown
## SQL Injection Confirmado

### Detalhes
- **URL**: https://exemplo.com/users?id=1
- **Parâmetro**: id (GET)
- **Severidade**: CRITICAL
- **Impacto**: Acesso a todos os dados do banco

### Payload de Exploit
GET /users?id=1' UNION SELECT username,password,email FROM admin--

### Evidência
[Screenshot do Burp Repeater mostrando dados de admin retornados]

### Recomendação
Usar prepared statements:
```
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, id);
```
```

**Resultado esperado**:
- Vulnerabilidade confirmada manualmente
- Exploit documentado com evidências
- Impacto avaliado (acesso a dados de admin)
- Recomendação de correção fornecida

### Exemplo 3: DAST Automatizado em CI/CD com GitLab

**Cenário**: Integrar OWASP ZAP em pipeline GitLab CI para scans automatizados em cada merge request.

**Passos**:

**1. Criar Arquivo de Configuração ZAP**
```yaml
# .zap/rules.tsv
# Customizar regras e thresholds

10020	WARN	# Anti CSRF Tokens Scanner
10021	WARN	# Reflected XSS
40018	FAIL	# SQL Injection (Alta severidade bloqueia pipeline)
40019	FAIL	# SQL Injection - MySQL
10023	WARN	# Information Disclosure
```

**2. Configurar Pipeline GitLab CI**
```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - security-scan
  - deploy

variables:
  STAGING_URL: "https://staging-${CI_COMMIT_REF_SLUG}.exemplo.com"
  ZAP_VERSION: "stable"

# Build e deploy para staging
build:
  stage: build
  script:
    - docker build -t myapp:${CI_COMMIT_SHA} .
    - docker push myapp:${CI_COMMIT_SHA}

deploy-staging:
  stage: test
  script:
    - kubectl apply -f k8s/staging/
    - kubectl set image deployment/myapp myapp=myapp:${CI_COMMIT_SHA}
    - kubectl wait --for=condition=available --timeout=300s deployment/myapp
  environment:
    name: staging-${CI_COMMIT_REF_SLUG}
    url: ${STAGING_URL}

# DAST Scanning
dast-baseline:
  stage: security-scan
  image: owasp/zap2docker-${ZAP_VERSION}
  script:
    # Aguardar app estar pronta
    - timeout 60 bash -c 'until curl -sf ${STAGING_URL}/health; do sleep 2; done'
    
    # Baseline scan (passive)
    - |
      zap-baseline.py \
        -t ${STAGING_URL} \
        -r baseline-report.html \
        -J baseline-report.json \
        -c .zap/rules.tsv \
        || true
    
    # Analisar resultados
    - |
      if grep -q '"riskcode": "3"' baseline-report.json; then
        echo "❌ Critical vulnerabilities found! Blocking pipeline."
        exit 1
      fi
    
    - echo "✅ Baseline scan passed!"
  
  artifacts:
    reports:
      dast: baseline-report.json
    paths:
      - baseline-report.html
      - baseline-report.json
    expire_in: 1 week
    when: always
  
  allow_failure: false  # Bloqueia pipeline se encontrar Critical
  
  only:
    - merge_requests
    - main

# Full scan (apenas em schedules noturnos)
dast-full:
  stage: security-scan
  image: owasp/zap2docker-${ZAP_VERSION}
  script:
    - timeout 60 bash -c 'until curl -sf ${STAGING_URL}/health; do sleep 2; done'
    
    # Full scan (passive + active)
    - |
      zap-full-scan.py \
        -t ${STAGING_URL} \
        -r full-scan-report.html \
        -J full-scan-report.json \
        -c .zap/rules.tsv \
        -a \
        || true
    
    # Criar issue no GitLab para vulnerabilidades High+
    - python3 scripts/create_gitlab_issues.py full-scan-report.json
  
  artifacts:
    paths:
      - full-scan-report.html
      - full-scan-report.json
    expire_in: 30 days
    when: always
  
  only:
    - schedules  # Apenas em scans agendados (noturnos)

# API scan específico
dast-api:
  stage: security-scan
  image: owasp/zap2docker-${ZAP_VERSION}
  script:
    - |
      zap-api-scan.py \
        -t ${STAGING_URL}/api/openapi.json \
        -f openapi \
        -r api-scan-report.html \
        -J api-scan-report.json \
        || true
  
  artifacts:
    paths:
      - api-scan-report.html
      - api-scan-report.json
    expire_in: 1 week
  
  only:
    - merge_requests
    - main
```

**3. Script para Criar Issues Automaticamente**
```python
# scripts/create_gitlab_issues.py
import json
import sys
import os
import requests

def create_gitlab_issue(vulnerability):
    """Cria issue no GitLab para vulnerabilidade High/Critical"""
    gitlab_url = os.environ['CI_API_V4_URL']
    project_id = os.environ['CI_PROJECT_ID']
    token = os.environ['GITLAB_TOKEN']
    
    headers = {'PRIVATE-TOKEN': token}
    
    issue_data = {
        'title': f"[DAST] {vulnerability['alert']} - {vulnerability['riskdesc']}",
        'description': f"""
## Vulnerabilidade Detectada por DAST

**Severidade**: {vulnerability['riskdesc']}  
**URL**: {vulnerability['url']}  
**Parâmetro**: {vulnerability.get('param', 'N/A')}

### Descrição
{vulnerability['desc']}

### Solução
{vulnerability['solution']}

### Referências
{vulnerability.get('reference', 'N/A')}

---
*Detectado automaticamente em pipeline: {os.environ['CI_PIPELINE_URL']}*
*Relatório completo: {os.environ['CI_JOB_URL']}/artifacts/browse*
        """,
        'labels': ['security', 'dast', vulnerability['riskdesc'].lower()],
        'confidential': True
    }
    
    response = requests.post(
        f"{gitlab_url}/projects/{project_id}/issues",
        headers=headers,
        json=issue_data
    )
    
    if response.status_code == 201:
        print(f"✅ Issue criada: {response.json()['web_url']}")
    else:
        print(f"❌ Erro ao criar issue: {response.text}")

if __name__ == '__main__':
    report_file = sys.argv[1]
    
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    high_critical_vulns = [
        alert for site in report['site']
        for alert in site['alerts']
        if alert['riskcode'] in ['2', '3']  # High, Critical
    ]
    
    print(f"Encontradas {len(high_critical_vulns)} vulnerabilidades High/Critical")
    
    for vuln in high_critical_vulns:
        create_gitlab_issue(vuln)
```

**Resultado esperado**:
- DAST executado automaticamente em cada MR
- Pipeline bloqueado se vulnerabilidades Critical encontradas
- Issues criadas automaticamente no GitLab
- Relatórios disponíveis como artifacts
- Full scans noturnos agendados

---

## 🔄 Integração com CI/CD

### Configurando DAST no Pipeline

DAST deve fazer parte do seu pipeline de CI/CD, executando automaticamente em diferentes estágios:

```
┌─────────────────────────────────────────────────────────┐
│       DAST NO PIPELINE CI/CD - ESTRATÉGIA              │
└─────────────────────────────────────────────────────────┘

Commit → Build → Unit Tests → Deploy Staging → DAST → Deploy Prod
                                      │           │
                                      │           ├─ Baseline (Fast, MR)
                                      │           ├─ API Scan (Fast, MR)
                                      │           └─ Full Scan (Slow, Nightly)
                                      │
                                      └─ Aguarda app estar pronta
```

### Estratégias de DAST em CI/CD

#### 1. DAST em Merge Requests (Fast Feedback)

**Objetivo**: Feedback rápido (<15 min) para não bloquear desenvolvimento

**Configuração**:
```yaml
# GitHub Actions - DAST em PR
name: DAST Quick Scan

on:
  pull_request:
    branches: [main, develop]

jobs:
  dast-quick:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to ephemeral environment
        run: |
          # Deploy app para ambiente efêmero
          docker-compose -f docker-compose.staging.yml up -d
          timeout 60 bash -c 'until curl -sf http://localhost:3000/health; do sleep 2; done'
      
      - name: OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:3000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a -j'  # AJAX spider
          fail_action: true  # Falha pipeline se encontrar High/Critical
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: zap-baseline-report
          path: report_html.html
      
      - name: Comment PR with Summary
        if: always()
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('report_json.json', 'utf8');
            const data = JSON.parse(report);
            
            const criticalCount = data.site[0].alerts.filter(a => a.riskcode === '3').length;
            const highCount = data.site[0].alerts.filter(a => a.riskcode === '2').length;
            
            const comment = `## 🔒 DAST Scan Results
            
            - Critical: ${criticalCount}
            - High: ${highCount}
            
            [📄 Full Report](${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID})
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

#### 2. DAST Nightly (Comprehensive Scans)

**Objetivo**: Scan completo noturno com análise profunda

**Configuração**:
```yaml
# GitHub Actions - Full DAST Nightly
name: DAST Full Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Todos os dias às 2h
  workflow_dispatch:  # Permite execução manual

jobs:
  dast-full:
    runs-on: ubuntu-latest
    timeout-minutes: 180  # 3 horas
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to staging
        run: |
          kubectl config use-context staging
          kubectl apply -f k8s/
          kubectl wait --for=condition=available deployment/myapp --timeout=300s
      
      - name: OWASP ZAP Full Scan
        run: |
          docker run -v $(pwd):/zap/wrk/:rw \
            owasp/zap2docker-stable zap-full-scan.py \
            -t https://staging.exemplo.com \
            -r full-scan-report.html \
            -J full-scan-report.json \
            -n zap-auth-config.yaml \
            -a  # Include alpha scanners
      
      - name: Parse Results
        id: parse
        run: |
          CRITICAL=$(jq '[.site[].alerts[] | select(.riskcode == "3")] | length' full-scan-report.json)
          HIGH=$(jq '[.site[].alerts[] | select(.riskcode == "2")] | length' full-scan-report.json)
          echo "critical=$CRITICAL" >> $GITHUB_OUTPUT
          echo "high=$HIGH" >> $GITHUB_OUTPUT
      
      - name: Create GitHub Issues for Critical
        if: steps.parse.outputs.critical > 0
        run: |
          python3 scripts/create_github_issues.py full-scan-report.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Send Slack Notification
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: |
            DAST Full Scan completado!
            Critical: ${{ steps.parse.outputs.critical }}
            High: ${{ steps.parse.outputs.high }}
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
        if: always()
      
      - name: Upload to S3 (Historical Reports)
        run: |
          aws s3 cp full-scan-report.html \
            s3://security-reports/dast/$(date +%Y-%m-%d)-full-scan.html
```

#### 3. DAST em Deploy para Produção (Safety Check)

**Objetivo**: Validação final antes de produção

**Configuração**:
```yaml
# .gitlab-ci.yml - DAST Pre-Production
pre-production-scan:
  stage: pre-production
  image: owasp/zap2docker-stable
  script:
    # Scan em ambiente de staging (idêntico a produção)
    - |
      zap-baseline.py \
        -t https://pre-prod.exemplo.com \
        -r pre-prod-report.html \
        -J pre-prod-report.json \
        -c .zap/production-rules.tsv
    
    # Bloqueia deploy se encontrar Critical
    - |
      CRITICAL_COUNT=$(jq '[.site[].alerts[] | select(.riskcode == "3")] | length' pre-prod-report.json)
      if [ $CRITICAL_COUNT -gt 0 ]; then
        echo "❌ $CRITICAL_COUNT Critical vulnerabilities found!"
        echo "Deploy to production BLOCKED!"
        exit 1
      fi
    
    - echo "✅ Pre-production security check passed!"
  
  artifacts:
    paths:
      - pre-prod-report.html
    expire_in: 30 days
  
  allow_failure: false  # NEVER allow failure!
  
  only:
    - main  # Apenas em deploys para produção

production-deploy:
  stage: deploy
  script:
    - kubectl config use-context production
    - kubectl apply -f k8s/production/
  
  needs:
    - pre-production-scan  # Depende do scan passar
  
  only:
    - main
  
  when: manual  # Requer aprovação manual
```

### Estratégia de Regras e Thresholds

**Configurar diferentes thresholds por ambiente**:

```yaml
# .zap/rules-merge-request.tsv (Permissivo - Feedback Rápido)
# Rule_ID  Action  Threshold
10020      WARN    MEDIUM     # Anti-CSRF Tokens
10021      WARN    MEDIUM     # XSS Reflected
40018      FAIL    HIGH       # SQL Injection (bloqueia apenas High/Critical)
40019      FAIL    HIGH       # SQL Injection - MySQL
10023      INFO    LOW        # Information Disclosure

# .zap/rules-nightly.tsv (Rigoroso - Scan Completo)
# Rule_ID  Action  Threshold
10020      FAIL    MEDIUM     # Anti-CSRF Tokens
10021      FAIL    MEDIUM     # XSS Reflected
40018      FAIL    MEDIUM     # SQL Injection (bloqueia Medium+)
40019      FAIL    MEDIUM     # SQL Injection - MySQL
10023      WARN    LOW        # Information Disclosure

# .zap/rules-production.tsv (Muito Rigoroso - Pre-Prod)
# Rule_ID  Action  Threshold
10020      FAIL    LOW        # Anti-CSRF Tokens
10021      FAIL    LOW        # XSS Reflected
40018      FAIL    LOW        # SQL Injection (bloqueia tudo!)
40019      FAIL    LOW        # SQL Injection - MySQL
10023      FAIL    MEDIUM     # Information Disclosure
```

### Monitoramento e Métricas

**Dashboard de Segurança - Tracking de DAST**:

```python
# scripts/generate_dast_dashboard.py
import json
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

def generate_dast_dashboard(reports_dir):
    """Gera dashboard de métricas DAST ao longo do tempo"""
    
    # Coletar dados históricos
    metrics = {
        'dates': [],
        'critical': [],
        'high': [],
        'medium': [],
        'low': []
    }
    
    for report_file in sorted(os.listdir(reports_dir)):
        if not report_file.endswith('.json'):
            continue
        
        with open(os.path.join(reports_dir, report_file)) as f:
            report = json.load(f)
        
        date = report_file.split('-')[0]  # YYYY-MM-DD
        metrics['dates'].append(date)
        
        alerts = report['site'][0]['alerts']
        metrics['critical'].append(len([a for a in alerts if a['riskcode'] == '3']))
        metrics['high'].append(len([a for a in alerts if a['riskcode'] == '2']))
        metrics['medium'].append(len([a for a in alerts if a['riskcode'] == '1']))
        metrics['low'].append(len([a for a in alerts if a['riskcode'] == '0']))
    
    # Plotar gráfico de tendência
    plt.figure(figsize=(12, 6))
    plt.plot(metrics['dates'], metrics['critical'], 'r-', label='Critical', marker='o')
    plt.plot(metrics['dates'], metrics['high'], 'orange', label='High', marker='o')
    plt.plot(metrics['dates'], metrics['medium'], 'y-', label='Medium', marker='o')
    plt.xlabel('Data')
    plt.ylabel('Número de Vulnerabilidades')
    plt.title('Tendência de Vulnerabilidades DAST - Últimos 30 dias')
    plt.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('dast-trend.png')
    
    # Gerar relatório HTML
    html = f"""
    <html>
    <head><title>DAST Dashboard</title></head>
    <body>
      <h1>Dashboard DAST - {datetime.now().strftime('%Y-%m-%d')}</h1>
      <img src="dast-trend.png" />
      
      <h2>Estatísticas Últimos 7 Dias</h2>
      <table border="1">
        <tr>
          <th>Severidade</th>
          <th>Total</th>
          <th>Média/Dia</th>
        </tr>
        <tr>
          <td>Critical</td>
          <td>{sum(metrics['critical'][-7:])}</td>
          <td>{sum(metrics['critical'][-7:])/7:.1f}</td>
        </tr>
        <tr>
          <td>High</td>
          <td>{sum(metrics['high'][-7:])}</td>
          <td>{sum(metrics['high'][-7:])/7:.1f}</td>
        </tr>
      </table>
      
      <h2>Top 10 Vulnerabilidades Recorrentes</h2>
      <!-- ... -->
    </body>
    </html>
    """
    
    with open('dast-dashboard.html', 'w') as f:
        f.write(html)

if __name__ == '__main__':
    generate_dast_dashboard('/reports/dast/')
```

### Melhores Práticas de Integração CI/CD

1. **✅ Progressive Enhancement**:
   - Começar com baseline scans (rápidos, permissivos)
   - Gradualmente adicionar full scans
   - Aumentar rigor dos thresholds ao longo do tempo

2. **✅ Fail Fast, Fix Fast**:
   - Bloquear apenas Critical em MRs (feedback rápido)
   - Criar issues automaticamente para High+
   - Notificar time via Slack/Teams

3. **✅ Environment Parity**:
   - Staging deve ser idêntico a produção
   - Usar mesmos dados de teste
   - Mesma configuração de infraestrutura

4. **✅ Authenticated Scans**:
   - Sempre configurar autenticação
   - Testar com diferentes roles (user, admin)
   - Validar autorização adequada

5. **✅ Incremental Scanning**:
   - Scan completo noturno
   - Scan incremental em MRs (apenas código novo)
   - Priorizar endpoints críticos

6. **✅ Monitoring e Alerting**:
   - Dashboard de métricas (tendências)
   - Alertas para regressões (nova vulnerabilidade)
   - SLA de correção (Critical: 24h, High: 7 dias)

---

## 📋 Cheat Sheet: DAST

### Comandos Rápidos

**OWASP ZAP**:
```bash
# Baseline scan (rápido, passivo)
docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap-baseline.py \
  -t https://app.example.com -r report.html

# Full scan (ativo, completo)
docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap-full-scan.py \
  -t https://app.example.com -r report.html

# API scan
docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap-api-scan.py \
  -t https://api.example.com/openapi.json -f openapi
```

**Burp Suite (CLI)**:
```bash
# Scan com autenticação
burp-cli scan --url https://app.example.com \
  --credentials user:pass \
  --output report.xml
```

### Quando Usar DAST

✅ **Use DAST para**:
- Vulnerabilidades em runtime (misconfigurations, auth bypass)
- Testar aplicação como atacante (black box)
- Falhas de lógica de negócio (IDOR, race conditions)
- Validar correções de vulnerabilidades
- Compliance (evidências de testes dinâmicos)

❌ **NÃO use DAST para**:
- Vulnerabilidades em código-fonte (use SAST)
- Dependências vulneráveis (use SCA)
- Performance rápida (<5 min, use SAST)
- Cobertura de código (DAST não vê código)

### Quality Gate Sugerido

**Baseline Scan** (em cada PR - 10-15 min):
- Bloquear: Critical + High novas
- Avisar: Medium novas
- Informar: Low

**Full Scan** (noturno - 45-60 min):
- Bloquear: Critical
- Avisar: High
- Informar: Medium, Low

**Pre-Production Scan** (antes de deploy):
- Bloquear: Critical + High
- Revisar manualmente: Tudo

### Links Úteis

- [OWASP ZAP Docs](https://www.zaproxy.org/docs/)
- [Burp Suite Docs](https://portswigger.net/burp/documentation)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)

---

## 📝 Resumo

### Principais Conceitos

- **DAST (Dynamic Application Security Testing)**: Testa aplicações em execução, simulando ataques reais de hackers
- **Black-box Testing**: Testa sem acesso ao código-fonte, como atacante real
- **Runtime Vulnerabilities**: Encontra problemas que só aparecem em execução (configuração, integração, lógica de negócio)
- **Ferramentas DAST**: OWASP ZAP (open-source), Burp Suite (profissional), Acunetix (enterprise)
- **Tipos de Scan**: Passive (observa tráfego), Active (envia payloads maliciosos), Authenticated (testa áreas protegidas)
- **Complementa SAST**: DAST + SAST = cobertura completa de segurança
- **Integração CI/CD**: Scans automatizados em pipelines (baseline em MRs, full scan noturno)

### Pontos-Chave para Lembrar

- ✅ **DAST simula ataques reais**: Testa aplicação como hacker faria
- ✅ **Encontra o que SAST não vê**: Problemas de runtime, configuração, integração
- ✅ **Menos false positives que SAST**: ~5-10% vs 20-40% (confirma exploits reais)
- ✅ **Sempre use autenticação**: 60-80% das vulnerabilidades estão em áreas autenticadas
- ✅ **Não execute active scan em produção**: Risco de danificar dados/estado
- ✅ **Progressive enhancement**: Começar simples (baseline), aumentar rigor gradualmente
- ✅ **Combine com SAST**: DAST não substitui SAST, complementa!
- ✅ **API testing é crítico**: REST, GraphQL, SOAP têm vulnerabilidades únicas
- ✅ **Monitorar tendências**: Dashboard de métricas para acompanhar evolução
- ✅ **Automatizar tudo**: Scans em CI/CD, criação de issues, notificações

### Diferenças Chave: DAST vs SAST

| Característica | SAST | DAST |
|---------------|------|------|
| **Quando executar** | Durante desenvolvimento | Aplicação rodando |
| **Acesso ao código** | Requer código-fonte | Não requer código-fonte |
| **Velocidade** | Rápido (minutos) | Lento (horas) |
| **False Positives** | 20-40% | 5-10% |
| **Cobertura** | 100% do código | Apenas o que executa |
| **Encontra** | Vulnerabilidades no código | Vulnerabilidades em runtime |
| **Melhor para** | Shift-left, early detection | Validação final, exploits reais |

### Workflow Recomendado

```
1. SAST em cada commit (shift-left)
   └─ Encontra vulnerabilidades no código

2. DAST Baseline em cada MR (feedback rápido)
   └─ Valida segurança em runtime

3. DAST Full Scan noturno (análise profunda)
   └─ Scan completo com authenticated testing

4. DAST Pre-Production (safety check)
   └─ Validação final antes de produção

5. Pentest Manual (exploração profunda)
   └─ Valida correções e explora edge cases
```

### Próximos Passos

- Próxima aula: [Aula 2.3: Testes de Penetração (Pentest) Básico](./lesson-2-3.md)
- Praticar configurando OWASP ZAP em projetos reais
- Integrar DAST em pipeline CI/CD existente
- Explorar Burp Suite para testes manuais profissionais
- Combinar DAST com SAST para cobertura completa

---

## 💼 Aplicação no Contexto CWI

**📝 Nota:** Os cenários abaixo são exemplos hipotéticos criados para fins educacionais, ilustrando como os conceitos de DAST podem ser aplicados em diferentes contextos e setores.

### Cenário Hipotético 1: Cliente Financeiro (Open Banking)

**Situação**: API REST de Open Banking desenvolvida em Java/Spring Boot. Requisitos rigorosos de PCI-DSS e regulamentações do Banco Central.

**Papel do QA com DAST**:

1. **Configurar DAST apropriado para APIs financeiras**
   - Ferramenta: OWASP ZAP + Burp Suite Pro
   - Foco: SQL Injection, Broken Authentication, BOLA, Rate Limiting
   - Scan autenticado: Testar com diferentes roles (user, admin, auditor)

2. **Validar vulnerabilidades críticas para Open Banking**
   - **Broken Object Level Authorization (BOLA)**:
     ```bash
     # User 1 tenta acessar dados de User 2
     GET /api/accounts/user2_account_id HTTP/1.1
     Authorization: Bearer <user1_token>
     
     # Esperado: 403 Forbidden
     # Vulnerável: 200 OK com dados de User 2
     ```
   
   - **Rate Limiting**:
     ```bash
     # Testar brute force em endpoint de login
     for i in {1..1000}; do
       curl -X POST https://api.banco.com/login \
         -d "username=admin&password=test$i"
     done
     
     # Esperado: Rate limiting após 5 tentativas
     # Vulnerável: Todas as 1000 tentativas permitidas
     ```
   
   - **Token Security**:
     ```bash
     # Testar JWT fraco
     # Decodificar JWT e verificar:
     # - Algoritmo seguro (RS256, não "none")
     # - Expiração configurada
     # - Claims adequados
     ```

3. **Compliance PCI-DSS via DAST**
   ```yaml
   # Acunetix Scan - PCI-DSS Profile
   scan_profile: PCI_DSS_3.2.1
   
   checks:
     - req_4.1: SSL/TLS configuration
     - req_6.5: Injection flaws (SQL, XSS, etc.)
     - req_8.2: Strong authentication
     - req_10.1: Audit logging
     
   threshold:
     critical: 0  # Zero tolerance
     high: 0
   ```

4. **Integração CI/CD Rigorosa**
   ```yaml
   # .gitlab-ci.yml - Financeiro
   dast-api:
     script:
       # Scan de API com OpenAPI spec
       - zap-api-scan.py -t $API_URL/openapi.json
       
       # Testes manuais específicos (Burp Suite CLI)
       - burp-cli --config=financial-tests.json
       
       # Validação PCI-DSS
       - python validate_pci_dss.py
       
       # Zero tolerance - qualquer finding bloqueia
       - |
         if [ $(jq '.vulnerabilities | length' report.json) -gt 0 ]; then
           echo "❌ Vulnerabilities found! Deploy BLOCKED!"
           exit 1
         fi
   ```

**Exemplo de Finding Crítico**:
```
Finding: Broken Object Level Authorization (BOLA)
Severity: CRITICAL 🔴
URL: /api/v1/accounts/{account_id}/transactions

Exploit:
  User A (ID: 12345) consegue acessar transações de User B (ID: 67890)
  
  Request:
    GET /api/v1/accounts/67890/transactions
    Authorization: Bearer <token_user_12345>
  
  Response: 200 OK
    [{"id": 999, "amount": 5000.00, "description": "Salário"}]
  
Impact: 
  - Violação de privacidade (LGPD)
  - Exposição de dados financeiros sensíveis
  - Não conformidade com PCI-DSS Req 7.1
  
Recommendation:
  Validar que account_id pertence ao usuário autenticado:
  
  @GetMapping("/api/v1/accounts/{accountId}/transactions")
  public List<Transaction> getTransactions(@PathVariable String accountId) {
      String authenticatedUserId = SecurityContext.getUserId();
      Account account = accountRepository.findById(accountId);
      
      if (!account.getUserId().equals(authenticatedUserId)) {
          throw new ForbiddenException("Cannot access other user's data");
      }
      
      return transactionRepository.findByAccountId(accountId);
  }
```

### Cenário Hipotético 2: Plataforma Educacional (EdTech)

**Situação**: Plataforma web Django com área administrativa e portal de alunos. Dados sensíveis de menores (LGPD).

**Papel do QA com DAST**:

1. **Configurar DAST para testar áreas autenticadas**
   ```yaml
   # OWASP ZAP Context - EdTech
   contexts:
     - name: student-context
       authentication:
         login_url: /login/student
         username: student_test
         password: ${STUDENT_PASSWORD}
     
     - name: teacher-context
       authentication:
         login_url: /login/teacher
         username: teacher_test
         password: ${TEACHER_PASSWORD}
     
     - name: admin-context
       authentication:
         login_url: /admin/login
         username: admin_test
         password: ${ADMIN_PASSWORD}
   ```

2. **Testar Privilege Escalation**
   ```python
   # Teste: Student não pode acessar área de Teacher
   
   # 1. Login como student
   session = requests.Session()
   session.post('https://escola.com/login/student', 
                data={'username': 'student', 'password': 'pass'})
   
   # 2. Tentar acessar área de teacher
   response = session.get('https://escola.com/teacher/grades/edit')
   
   # Esperado: 403 Forbidden
   # Vulnerável: 200 OK (student consegue editar notas!)
   
   # ✅ DAST automaticamente testa esses cenários
   ```

3. **Validar XSS em Área de Comentários**
   ```http
   # DAST envia payloads XSS automaticamente:
   
   POST /forum/comments HTTP/1.1
   Content-Type: application/json
   
   {
     "comment": "<script>alert('XSS')</script>"
   }
   
   # Resposta:
   <div class="comment">
     <script>alert('XSS')</script>  ← ❌ VULNERÁVEL!
   </div>
   
   # Correção implementada:
   <div class="comment">
     &lt;script&gt;alert('XSS')&lt;/script&gt;  ← ✅ SANITIZADO
   </div>
   ```

4. **LGPD Compliance Testing**
   ```bash
   # Testar se dados pessoais são expostos em logs
   grep -r "cpf\|rg\|email" /var/log/app/ 
   
   # Testar se direito ao esquecimento funciona
   # 1. Criar conta de teste
   # 2. Solicitar exclusão de dados
   # 3. Verificar se todos os dados foram removidos (inclusive backups)
   ```

**Exemplo de Finding Crítico**:
```
Finding: Privilege Escalation - Student to Teacher
Severity: CRITICAL 🔴
URL: /teacher/grades/edit

Exploit:
  Aluno consegue modificar suas próprias notas acessando URL de professor
  
  Steps:
    1. Login como student (credentials: student1/pass123)
    2. Acessar diretamente: /teacher/grades/edit?student_id=student1
    3. Modificar nota de 5.0 para 10.0
    4. Salvar alterações
  
  Evidence:
    - Request interceptado mostra 200 OK
    - Nota foi alterada no banco de dados
    - Nenhuma validação de autorização presente
  
Impact:
  - Alunos podem manipular suas próprias notas
  - Comprometimento da integridade acadêmica
  - Violação de políticas educacionais
  
Recommendation:
  Implementar autorização adequada:
  
  @login_required
  @user_passes_test(lambda u: u.is_teacher)  # ← Adicionar verificação
  def edit_grades(request, student_id):
      # Apenas teachers podem editar notas
      if not request.user.is_teacher:
          return HttpResponseForbidden()
      
      # ... resto do código
```

### Cenário Hipotético 3: Ecommerce

**Situação**: Plataforma ecommerce Node.js/Express com checkout e pagamentos. Compliance PCI-DSS para processamento de cartões.

**Papel do QA com DAST**:

1. **Testar Manipulação de Preços**
   ```javascript
   // DAST detecta price manipulation automaticamente:
   
   // Request original (legítima):
   POST /api/checkout HTTP/1.1
   {
     "product_id": 123,
     "quantity": 1,
     "price": 99.99  // ← Preço vem do cliente!
   }
   
   // DAST modifica automaticamente:
   POST /api/checkout HTTP/1.1
   {
     "product_id": 123,
     "quantity": 1,
     "price": 0.01  // ← Preço manipulado!
   }
   
   // Se resposta for 200 OK com order_total: 0.01
   // ✅ DAST detecta vulnerabilidade!
   ```

2. **Testar SQL Injection em Busca de Produtos**
   ```bash
   # OWASP ZAP fuzzing automático:
   
   GET /products/search?q=test HTTP/1.1
   # Payload 1: test' OR '1'='1
   # Payload 2: test'; DROP TABLE products--
   # Payload 3: test' UNION SELECT password FROM users--
   # ... 100+ payloads testados automaticamente
   
   # Se algum payload retornar dados inesperados:
   # ✅ SQL Injection detectado!
   ```

3. **Testar Checkout Flow Completo**
   ```yaml
   # Burp Suite Macro - Automated Checkout Test
   macro:
     - name: Complete Checkout Flow
       steps:
         - action: add_to_cart
           url: /api/cart/add
           data: {"product_id": 123, "quantity": 1}
         
         - action: proceed_to_checkout
           url: /checkout
         
         - action: enter_shipping
           url: /checkout/shipping
           data: {"address": "...", "city": "..."}
         
         - action: enter_payment
           url: /checkout/payment
           data: {"card_token": "tok_test_..."}
         
         - action: complete_order
           url: /checkout/complete
       
       security_checks:
         - verify_ssl_all_steps
         - verify_no_card_data_exposed
         - verify_csrf_protection
         - verify_rate_limiting
   ```

4. **PCI-DSS Compliance Validation**
   ```bash
   # Acunetix PCI-DSS Automated Tests
   
   # Req 2.2: Remove default accounts
   curl -X POST https://ecommerce.com/admin/login \
     -d "username=admin&password=admin"
   # Expected: 401 Unauthorized
   
   # Req 4.1: Encrypt transmission of cardholder data
   nmap --script ssl-enum-ciphers ecommerce.com
   # Expected: Only strong ciphers (TLS 1.2+, no weak ciphers)
   
   # Req 6.5.1: Test for injection flaws
   # ✅ DAST automaticamente testa SQL, XSS, Command Injection
   
   # Req 8.2: Strong authentication
   # Test weak password policy
   curl -X POST https://ecommerce.com/register \
     -d "username=test&password=123"
   # Expected: 400 Bad Request (password too weak)
   ```

**Exemplo de Finding Crítico**:
```
Finding: Price Manipulation in Checkout
Severity: CRITICAL 🔴
URL: /api/checkout

Exploit:
  Cliente pode modificar preço de produtos no checkout
  
  Vulnerable Request:
    POST /api/checkout HTTP/1.1
    Content-Type: application/json
    
    {
      "product_id": 123,
      "quantity": 1,
      "price": 0.01  ← Preço manipulado (original: $999.99)
    }
  
  Response: 200 OK
    {
      "order_id": 789,
      "total": 0.01,  ← Aceita preço manipulado!
      "status": "confirmed"
    }
  
Impact:
  - Perda financeira direta
  - Cliente paga $0.01 por produto de $999.99
  - Não conformidade com PCI-DSS Req 6.5.8
  - Fraude em larga escala possível
  
Recommendation:
  NUNCA confiar em preço vindo do cliente:
  
  app.post('/api/checkout', async (req, res) => {
    const { product_id, quantity } = req.body;
    
    // ✅ Buscar preço do servidor
    const product = await Product.findById(product_id);
    const price = product.price;  // Preço do banco
    
    // ❌ NUNCA usar: const price = req.body.price;
    
    const total = price * quantity;
    
    const order = await Order.create({
      product_id,
      quantity,
      price: price,  // Preço validado server-side
      total: total
    });
    
    res.json({ order_id: order.id, total: total });
  });
```

### Matriz de Prioridades por Setor

| Vulnerabilidade DAST | Financeiro | Educacional | Ecommerce |
|---------------------|------------|-------------|-----------|
| **BOLA/IDOR** | 🔴 CRÍTICA | 🔴 CRÍTICA | 🔴 CRÍTICA |
| **Price Manipulation** | 🟡 MÉDIA | 🟡 MÉDIA | 🔴 CRÍTICA |
| **SQL Injection** | 🔴 CRÍTICA | 🔴 CRÍTICA | 🔴 CRÍTICA |
| **XSS** | 🟠 ALTA | 🔴 CRÍTICA | 🟠 ALTA |
| **Privilege Escalation** | 🔴 CRÍTICA | 🔴 CRÍTICA | 🟠 ALTA |
| **Rate Limiting** | 🔴 CRÍTICA | 🟠 ALTA | 🟠 ALTA |
| **Authentication Bypass** | 🔴 CRÍTICA | 🔴 CRÍTICA | 🔴 CRÍTICA |

**Legenda**: 🔴 Crítica | 🟠 Alta | 🟡 Média

---

**Duração**: 90 minutos  
**Aula Anterior**: [Aula 2.1: SAST - Static Application Security Testing](./lesson-2-1.md)  
**Próxima Aula**: [Aula 2.3: Testes de Penetração (Pentest) Básico](./lesson-2-3.md)  
**Voltar ao Módulo**: [Módulo 2: Testes de Segurança na Prática](../index.md)

---

## ❌ Erros Comuns que QAs Cometem com DAST

### 1. **Executar Full Scan em produção sem autorização**

**Por quê é erro**: DAST ativo pode causar DoS, corrupção de dados, alertas falsos para SOC.

**Impacto**: Produção cai → Perda de receita → Demissão.

**Solução**: SEMPRE use ambiente staging/QA. Produção apenas com autorização escrita de C-Level e em janela de manutenção.

### 2. **Não autenticar DAST (testa apenas público)**

**Por quê é erro**: 70% das vulnerabilidades estão atrás de autenticação (IDOR, privilege escalation).

**Impacto**: False sense of security → Vulnerabilidades críticas não detectadas.

**Solução**: Configure credenciais de teste em ZAP/Burp. Teste com usuários de diferentes roles (user, admin, guest).

### 3. **Ignorar findings "Informational" e "Low"**

**Por quê é erro**: Informational pode revelar information disclosure crítico (version leakage, stack traces).

**Impacto**: Atacante usa info para exploração targeted.

**Solução**: Revise TODOS os findings. Informational pode ser Critical dependendo do contexto.

### 4. **Aceitar todos os findings ZAP sem validar (trust automation blindly)**

**Por quê é erro**: DAST tem 20-30% false positive rate.

**Impacto**: Time corrige vulnerabilidades inexistentes → Perda de tempo.

**Solução**: SEMPRE reproduza manualmente antes de criar ticket. Use Burp Suite para investigar.

### 5. **Escanear aplicação sem avisar Dev/Ops (surprise scan)**

**Por quê é erro**: DAST ativo gera toneladas de requests → Alertas SOC/WAF → Incident response desnecessário.

**Impacto**: Time de Ops escalona incident → War room → Desgaste de relações.

**Solução**: Comunique ANTES de scans. Whitelist IPs de scanner no WAF/IDS.

---

## 📖 Recursos Adicionais

**Dúvida sobre algum termo técnico?**  
Consulte o [📖 Glossário do Módulo 2](/modules/testes-seguranca-pratica/glossario/) com mais de 80 definições de termos de segurança (DAST, False Positive, OWASP ZAP, Burp Suite, Spider, Active Scan, etc.).

---
