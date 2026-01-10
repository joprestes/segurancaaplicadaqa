---
layout: lesson
title: "Aula 2.1: SAST: Static Application Security Testing"
slug: sast-testes-estaticos
module: module-2
lesson_id: lesson-2-1
duration: "90 minutos"
level: "Intermediário"
prerequisites: ["lesson-1-5"]
image: "assets/images/podcasts/2.1-SAST_Testes_Estaticos.png"
permalink: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
---

# Aula 2.1: SAST: Static Application Security Testing

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Compreender o que é SAST e sua importância no processo de testes de segurança
- Diferenciar SAST de outras metodologias de teste (DAST, IAST, SCA)
- Identificar as principais ferramentas SAST disponíveis no mercado
- Executar análise estática de código em projetos reais
- Interpretar resultados de SAST e priorizar vulnerabilidades
- Integrar SAST em pipelines CI/CD
- Configurar regras customizadas em ferramentas SAST

---

## 📚 Introdução ao SAST

### O que é SAST?

**SAST (Static Application Security Testing)** é uma metodologia de teste de segurança que analisa o código-fonte, bytecode ou binários de uma aplicação **sem executá-la**. SAST identifica vulnerabilidades através da análise estática do código, procurando por padrões inseguros, más práticas e vulnerabilidades conhecidas.

#### 🎭 Analogia: Inspetor de Código vs Teste de Estrada

Imagine comprar um carro:

**SAST = Inspetor que examina o carro parado**:
- O inspetor abre o capô e examina o motor, sem ligar o carro
- Verifica se há peças soltas, vazamentos, fios expostos
- Identifica problemas potenciais antes de sair na estrada
- **Vantagem**: Encontra problemas antes de usar
- **Limitação**: Não testa como o carro funciona em movimento

**DAST = Teste de Estrada**:
- Testa o carro em movimento, em condições reais
- Verifica como o carro se comporta na prática
- **Vantagem**: Encontra problemas que só aparecem em uso real
- **Limitação**: Precisa que o carro esteja funcionando

Na segurança de software:
- **SAST** analisa código estático, sem executar
- **DAST** testa aplicação em execução (será abordado na próxima aula)

### Contexto Histórico do SAST

A análise estática de código existe desde os primórdios da programação, mas SAST como disciplina específica de segurança evoluiu significativamente:

```
Anos 1970-1980 ──────────────────────────────────────────── 2024+
 │                                                             │
 ├─ 1970s    📦 Lint (Original)                              │
 │          ┌─────────────────────────────────────┐          │
 │          │ • Análise de estilo de código      │          │
 │          │ • Detecção de bugs básicos         │          │
 │          │ • Foco em qualidade, não segurança │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 ├─ 1990s    🔍 Code Review Manual                            │
 │          ┌─────────────────────────────────────┐          │
 │          │ • Revisão humana de código         │          │
 │          │ • Encontra problemas de segurança   │          │
 │          │ • Lento e caro                     │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 ├─ 2000s    🔥 SAST Comercial Inicial                        │
 │          ┌─────────────────────────────────────┐          │
 │          │ • Ferramentas comerciais (Checkmarx)│          │
 │          │ • Foco em vulnerabilidades OWASP    │          │
 │          │ • Integração com IDEs              │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 ├─ 2010s    📈 SAST Open Source                             │
 │          ┌─────────────────────────────────────┐          │
 │          │ • SonarQube com security rules      │          │
 │          │ • Bandit (Python), Brakeman (Ruby) │          │
 │          │ • ESLint Security Plugin            │          │
 │          │ • Acessibilidade aumentada          │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 ├─ 2020    ⚡ Rules as Code (Semgrep)                       │
 │          ┌─────────────────────────────────────┐          │
 │          │ • Regras customizadas fáceis        │          │
 │          │ • Fast scanning                     │          │
 │          │ • Developer-friendly                │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 └─ 2024+    🚀 SAST Moderno                                  │
            ┌─────────────────────────────────────┐          │
            │ • AI/ML para reduzir false positives│          │
            │ • Integração nativa com CI/CD       │          │
            │ • Real-time scanning em IDEs        │          │
            │ • Análise de IaC (Infrastructure)   │          │
            │ • Integração com SCA e DAST         │          │
            └─────────────────────────────────────┘          │
```

**Por que SAST se tornou fundamental?**

- **Shift-Left**: Encontra vulnerabilidades cedo (durante desenvolvimento)
- **Custo-Benefício**: Corrigir durante dev é 10-100x mais barato que em produção
- **Escalabilidade**: Automatiza o que antes era revisão manual
- **Padronização**: Regras consistentes aplicadas a todo o código
- **Compliance**: Muitos padrões (PCI-DSS, SOC2) exigem análise estática

### Por que SAST é Importante?

#### O Custo de Vulnerabilidades Encontradas por SAST vs Produção

```
┌─────────────────────────────────────────────────────────┐
│  CUSTO DE CORRIGIR VULNERABILIDADE POR MÉTODO          │
│                                                         │
│  SAST (Dev)    Code Review    Testes    DAST    Prod   │
│     │              │            │         │       │     │
│     $50          $200        $500    $2,000  $50,000│
│                                                         │
│  SAST encontra problemas quando são mais baratos!      │
└─────────────────────────────────────────────────────────┘
```

**Dados Reais (2024)**:
- Vulnerabilidade encontrada por **SAST durante desenvolvimento**: $50-200 para corrigir
- Vulnerabilidade encontrada em **code review manual**: $200-500
- Vulnerabilidade encontrada em **testes de segurança**: $500-2,000
- Vulnerabilidade encontrada por **DAST em staging**: $2,000-10,000
- Vulnerabilidade encontrada em **produção (breach)**: $50,000-500,000+

**Fonte**: OWASP, SANS Institute, IBM Security

#### Benefícios do SAST

| Benefício | Descrição | Impacto |
|-----------|-----------|---------|
| **Detecção Precoce** | Encontra vulnerabilidades durante desenvolvimento | Redução de 80-90% de bugs em produção |
| **Custo-Benefício** | Correção durante dev é muito mais barata | Economia de 10-100x vs produção |
| **Cobertura Completa** | Analisa todo o código, não apenas o que é executado | Encontra código morto, branches não testados |
| **Automação** | Integra no workflow de desenvolvimento | Não depende de revisão manual |
| **Educação** | Ensina desenvolvedores padrões seguros | Melhora cultura de segurança |
| **Compliance** | Atende requisitos de padrões de segurança | PCI-DSS, SOC2, ISO 27001 |

### O que você vai aprender

- **Fundamentos de SAST**: Como funciona análise estática
- **Ferramentas SAST**: SonarQube, Semgrep, Checkmarx, ferramentas específicas por linguagem
- **Configuração Prática**: Setup de ferramentas SAST em projetos
- **Interpretação de Resultados**: Como priorizar e validar findings
- **False Positives vs True Positives**: Como diferenciar e tratar
- **Integração CI/CD**: Automatizar scans em pipelines
- **Regras Customizadas**: Criar regras específicas para seu projeto

---

## 🔄 SAST vs Outras Metodologias de Teste

### Comparação: SAST, DAST, IAST, SCA

SAST não é a única forma de testar segurança. É importante entender diferenças:

#### Tabela Comparativa Completa

| Aspecto | SAST | DAST | IAST | SCA |
|---------|------|------|------|-----|
| **Quando Executa** | Antes de executar (código estático) | Aplicação em execução | Aplicação em execução (instrumentado) | Análise de dependências |
| **O que Analisa** | Código-fonte, bytecode | Aplicação rodando (black-box) | Código em execução (instrumentado) | Bibliotecas e dependências |
| **Quando Usar** | Durante desenvolvimento | Testes de integração/staging | Testes de integração/staging | Durante desenvolvimento |
| **Vantagens** | Precoce, barato, cobre todo código | Testa comportamento real, encontra runtime issues | Combina SAST e DAST | Encontra vulnerabilidades em libs |
| **Limitações** | False positives, não testa runtime | Só testa o que executa, precisa de app rodando | Overhead de performance, complexidade | Não encontra bugs no código próprio |
| **Exemplos de Ferramentas** | SonarQube, Semgrep, Checkmarx | OWASP ZAP, Burp Suite | Contrast Security, Veracode | Snyk, Dependabot, npm audit |
| **Tempo de Execução** | Minutos a horas | Minutos a horas | Contínuo durante execução | Minutos |
| **Custo** | Baixo-Médio (open source disponível) | Baixo-Médio | Alto | Baixo (muitas gratuitas) |
| **False Positives** | Muitos (20-40%) | Poucos (5-10%) | Médios (10-15%) | Muito poucos (<5%) |
| **Precisão** | Média-Alta (depende de ferramenta) | Alta | Muito Alta | Muito Alta |

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
│     │          │        │(Código│       │       │     │
│     │          │        │Estático)      │       │     │
│     │          │        └───────┘       │       │     │
│     │          │            │            │       │     │
│     │          │            ▼            ▼       │     │
│     │          │        ┌───────┐   ┌───────┐  │     │
│     │          │        │  SCA  │   │ IAST  │  │     │
│     │          │        │(Deps) │   │(App   │  │     │
│     │          │        │       │   │Instrumentada)│ │
│     │          │        └───────┘   └───────┘  │     │
│     │          │            │            │       │     │
│     │          │            ▼            ▼       ▼     │
│     │          │                    ┌───────┐ ┌─────┐ │
│     │          │                    │ DAST  │ │Prod │ │
│     │          │                    │(App   │ │(Breach│
│     │          │                    │Rodando)│ │Response)│
│     │          │                    └───────┘ └─────┘ │
│                                                         │
│  SAST: Mais cedo = Mais barato                         │
└─────────────────────────────────────────────────────────┘
```

### Quando Usar Cada Abordagem

**SAST é ideal quando**:
- ✅ Você quer encontrar vulnerabilidades durante desenvolvimento
- ✅ Precisa analisar todo o código, incluindo branches não testados
- ✅ Quer educar desenvolvedores sobre padrões inseguros
- ✅ Precisa atender compliance que exige análise estática
- ✅ Tem orçamento limitado (muitas ferramentas open source)

**SAST não é suficiente quando**:
- ❌ Você precisa testar comportamento em runtime
- ❌ Precisa validar configuração de servidor
- ❌ Quer testar autenticação/autorização complexa
- ❌ Precisa encontrar problemas de infraestrutura

**Conclusão**: SAST deve ser combinado com DAST, IAST e SCA para cobertura completa!

---

## 🔍 Conceitos Teóricos

### Como Funciona SAST?

#### Processo de Análise Estática

SAST funciona em múltiplas camadas de análise:

```
┌─────────────────────────────────────────────────────────┐
│              PROCESSO DE ANÁLISE SAST                  │
└─────────────────────────────────────────────────────────┘

1. Parse do Código
   │
   ▼
   ┌─────────────────────────────────────┐
   │ • Lexical Analysis (tokens)        │
   │ • Syntax Analysis (AST)            │
   │ • Semantic Analysis (símbolos)     │
   └─────────────────────────────────────┘
   │
   ▼
2. Análise de Padrões
   │
   ▼
   ┌─────────────────────────────────────┐
   │ • Data Flow Analysis (taint)       │
   │ • Control Flow Analysis            │
   │ • Pattern Matching (regras)        │
   │ • Machine Learning (algumas tools) │
   └─────────────────────────────────────┘
   │
   ▼
3. Detecção de Vulnerabilidades
   │
   ▼
   ┌─────────────────────────────────────┐
   │ • SQL Injection                    │
   │ • XSS (Cross-Site Scripting)       │
   │ • Command Injection                │
   │ • Path Traversal                   │
   │ • Insecure Deserialization         │
   │ • Hardcoded Secrets                │
   │ • E muito mais...                  │
   └─────────────────────────────────────┘
   │
   ▼
4. Geração de Report
   │
   ▼
   ┌─────────────────────────────────────┐
   │ • Severidade (Critical/High/Med/Low)│
   │ • Localização (arquivo, linha)     │
   │ • Descrição do problema            │
   │ • Recomendações de correção        │
   │ • CWE (Common Weakness Enumeration)│
   │ • OWASP Top 10 mapping             │
   └─────────────────────────────────────┘
```

#### Tipos de Análise SAST

**1. Pattern Matching (Matching de Padrões)**
- Procura por padrões conhecidos de código inseguro
- Exemplo: Procura por `eval()`, `exec()`, `SQL` concatenado
- **Vantagem**: Rápido, fácil de implementar
- **Desvantagem**: Muitos false positives, não entende contexto

**2. Data Flow Analysis (Análise de Fluxo de Dados)**
- Rastreia dados de entrada (tainted) até uso (sink)
- Exemplo: Rastreia input do usuário até query SQL
- **Vantagem**: Encontra vulnerabilidades reais, menos false positives
- **Desvantagem**: Mais lento, complexo

**3. Control Flow Analysis (Análise de Fluxo de Controle)**
- Analisa caminhos de execução do código
- Exemplo: Verifica se autenticação sempre acontece antes de acesso
- **Vantagem**: Encontra problemas de lógica
- **Desvantagem**: Muito complexo, pode não encontrar todos os caminhos

**4. Taint Analysis (Análise de Contaminação)**
- Tipo especial de data flow que rastreia dados não confiáveis
- **Source (Fonte)**: Onde dados não confiáveis entram (ex: `request.getParameter()`)
- **Sink (Ralo)**: Onde dados não confiáveis são usados de forma perigosa (ex: `executeQuery()`)
- **Sanitizer**: Funções que "limpam" dados (ex: `escapeHtml()`)

**Diagrama de Taint Analysis**:

```
┌─────────────────────────────────────────────────────────┐
│           EXEMPLO: TAINT ANALYSIS - SQL INJECTION      │
└─────────────────────────────────────────────────────────┘

Source (Fonte)
┌──────────────┐
│ userInput =  │  ← Dados não confiáveis entram
│ request.get  │
│ Parameter()  │
└──────┬───────┘
       │
       │ Taint propagates
       ▼
┌──────────────────────┐
│ query = "SELECT *    │
│ FROM users WHERE id="│
│ + userInput          │  ← Dados contaminados usados
└──────┬───────────────┘     sem sanitização
       │
       │ Tainted data reaches sink
       ▼
┌──────────────┐
│ db.execute   │  ← SINK: Execução perigosa
│ (query)      │     ⚠️ VULNERABILIDADE DETECTADA!
└──────────────┘

SAST detecta: "Tainted data from Source reaches Sink 
without sanitization → SQL Injection vulnerability"
```

### Principais Ferramentas SAST

#### 1. SonarQube

**Definição**: Plataforma open-source que combina análise de qualidade de código com segurança. Analisa código em mais de 25 linguagens e fornece métricas de qualidade, bugs, code smells e vulnerabilidades de segurança.

**Características Principais**:
- ✅ Open-source (Community Edition) + versões comerciais
- ✅ Suporta 25+ linguagens (Java, JavaScript, Python, C#, PHP, etc.)
- ✅ Integração com IDEs (IntelliJ, VS Code, Eclipse)
- ✅ Integração CI/CD (Jenkins, GitLab CI, GitHub Actions)
- ✅ Dashboards e relatórios visuais
- ✅ Regras de segurança baseadas em OWASP, CWE, SANS Top 25
- ✅ Quality Gates (bloqueia merge se não passar critérios)

**Analogia**:
SonarQube é como um "checkup completo" de código. Assim como um médico faz exames diversos (sangue, pressão, raio-X) para ter visão completa da saúde, SonarQube faz múltiplas análises (bugs, segurança, qualidade, duplicação) para ter visão completa da saúde do código.

**Exemplo de Configuração Básica**:

```yaml
# sonar-project.properties
sonar.projectKey=meu-projeto
sonar.projectName=Meu Projeto
sonar.projectVersion=1.0
sonar.sources=src
sonar.language=java
sonar.sourceEncoding=UTF-8

# Regras de segurança
sonar.security.hotspots=high,medium
```

**Dashboard SonarQube**:
```
┌─────────────────────────────────────────────────────────┐
│  SONARQUBE DASHBOARD                                   │
│                                                         │
│  Vulnerabilidades de Segurança: 23                     │
│  ├─ Critical: 2                                        │
│  ├─ High: 8                                            │
│  ├─ Medium: 10                                         │
│  └─ Low: 3                                             │
│                                                         │
│  Security Hotspots: 45                                 │
│  Bugs: 127                                             │
│  Code Smells: 342                                      │
│                                                         │
│  Cobertura de Testes: 78%                              │
│  Duplicação: 3.2%                                      │
│                                                         │
│  Quality Gate: ✅ PASSED                               │
└─────────────────────────────────────────────────────────┘
```

#### 2. Semgrep

**Definição**: Ferramenta open-source de análise estática que usa "rules as code" - regras escritas em YAML que são fáceis de criar e customizar. Foca em velocidade e simplicidade.

**Características Principais**:
- ✅ Open-source e gratuito
- ✅ Muito rápido (segundos para projetos grandes)
- ✅ Rules as code (regras em YAML, fáceis de criar)
- ✅ Suporta 20+ linguagens
- ✅ Regras pré-construídas (OWASP, PCI-DSS, SOC2)
- ✅ Integração CI/CD nativa
- ✅ Sem necessidade de servidor (CLI tool)

**Analogia**:
Semgrep é como um "detector de metais" rápido e portátil. Você pode usá-lo rapidamente em qualquer lugar, configurar facilmente o que procurar (regras), e ele encontra problemas rapidamente. Não é tão completo quanto um "raio-X" (SonarQube), mas é muito mais rápido e prático.

**Exemplo de Regra Semgrep**:

```yaml
# regras/sql-injection.yaml
rules:
  - id: sql-injection
    patterns:
      - pattern-either:
          - pattern: $X.executeQuery("...$Y...")
          - pattern: $X.execute("...$Y...")
    message: "Potential SQL Injection. User input '$Y' is directly concatenated into SQL query."
    languages: [java, python, javascript]
    severity: ERROR
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 – Injection"
```

**Uso Prático**:

```bash
# Scan básico
semgrep --config=auto .

# Scan com regras customizadas
semgrep --config=regras/ .

# Scan com saída JSON
semgrep --config=auto --json --output=results.json .
```

#### 3. Checkmarx

**Definição**: Ferramenta comercial enterprise-grade de SAST que oferece análise profunda de código-fonte com suporte a mais de 35 linguagens e 80 frameworks.

**Características Principais**:
- ✅ Comercial (enterprise, mais caro)
- ✅ Suporte extensivo (35+ linguagens, 80+ frameworks)
- ✅ Análise muito profunda (data flow, control flow)
- ✅ Menos false positives (usando AI/ML)
- ✅ Integração IDE em tempo real
- ✅ "Best Fix Location" (sugere melhor lugar para corrigir)
- ✅ Compliance mapping (PCI-DSS, OWASP, etc.)

**Analogia**:
Checkmarx é como um "laboratório médico completo" com todos os exames possíveis. É caro, mas oferece análise muito profunda e precisa. Ideal para empresas grandes que precisam de cobertura completa e precisão máxima.

**Comparação Rápida das 3 Ferramentas**:

| Aspecto | SonarQube | Semgrep | Checkmarx |
|---------|-----------|---------|-----------|
| **Custo** | Grátis (Community) ou Pago | Grátis | Pago (caro) |
| **Velocidade** | Médio (minutos) | Muito Rápido (segundos) | Lento (horas) |
| **Precisão** | Média-Alta | Média | Muito Alta |
| **False Positives** | Médios (20-30%) | Médios (15-25%) | Baixos (5-10%) |
| **Facilidade de Uso** | Média | Alta | Média |
| **Customização** | Média | Muito Alta (YAML) | Média |
| **Suporte de Linguagens** | 25+ | 20+ | 35+ |
| **Melhor Para** | Equipes médias/grandes | Desenvolvedores individuais/startups | Empresas grandes |

### Ferramentas SAST Específicas por Linguagem

Além das ferramentas universais, existem ferramentas específicas otimizadas para cada linguagem:

#### Python: Bandit

**Definição**: Ferramenta SAST específica para Python que procura por problemas de segurança comuns.

**Uso Prático**:

```bash
# Instalação
pip install bandit

# Scan básico
bandit -r src/

# Scan com saída HTML
bandit -r src/ -f html -o report.html

# Scan com configuração customizada
bandit -r src/ -c bandit.yaml
```

**Exemplo de Saída**:

```
Issue: [B506:yaml_load] Use of unsafe yaml load. Allows arbitrary code execution.
Severity: High   Confidence: High
Location: src/config.py:15
  14  import yaml
  15  config = yaml.load(open('config.yaml'))  # ← VULNERABILIDADE
```

#### Ruby: Brakeman

**Definição**: Analisador estático de segurança para aplicações Ruby on Rails.

**Uso Prático**:

```bash
# Instalação (Gemfile)
gem 'brakeman'

# Scan
brakeman

# Scan com JSON
brakeman -f json -o report.json
```

#### JavaScript/TypeScript: ESLint Security Plugin

**Definição**: Plugin do ESLint que adiciona regras de segurança para JavaScript/TypeScript.

**Configuração**:

```javascript
// .eslintrc.js
module.exports = {
  plugins: ['security'],
  extends: ['plugin:security/recommended'],
  rules: {
    'security/detect-object-injection': 'error',
    'security/detect-non-literal-fs-filename': 'warn'
  }
};
```

#### Java: SpotBugs + FindSecBugs

**Definição**: SpotBugs encontra bugs, FindSecBugs adiciona regras de segurança.

**Integração Maven**:

```xml
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <configuration>
    <plugins>
      <plugin>
        <groupId>com.h3xstream.findsecbugs</groupId>
        <artifactId>findsecbugs-plugin</artifactId>
      </plugin>
    </plugins>
  </configuration>
</plugin>
```

### Interpretação de Resultados SAST

#### Severidade de Vulnerabilidades

SAST classifica vulnerabilidades por severidade:

```
┌─────────────────────────────────────────────────────────┐
│         CLASSIFICAÇÃO DE SEVERIDADE                    │
└─────────────────────────────────────────────────────────┘

CRITICAL (Crítico) 🔴
├─ Vulnerabilidade que permite:
│  • Remote Code Execution (RCE)
│  • SQL Injection com acesso a dados sensíveis
│  • Autenticação bypass completo
│  • Exposição de secrets/chaves
└─ Ação: Corrigir IMEDIATAMENTE, bloquear deploy

HIGH (Alto) 🟠
├─ Vulnerabilidade que permite:
│  • Privilege Escalation
│  • Cross-Site Scripting (XSS) em área autenticada
│  • Path Traversal que expõe arquivos
│  • Insecure Deserialization
└─ Ação: Corrigir em 1-2 sprints

MEDIUM (Médio) 🟡
├─ Vulnerabilidade que permite:
│  • Information Disclosure (sem dados sensíveis)
│  • XSS em área pública
│  • Weak Cryptography
│  • Missing Security Headers
└─ Ação: Corrigir quando possível

LOW (Baixo) 🟢
├─ Vulnerabilidades menores:
│  • Code Quality issues
│  • Best Practices não seguidas
│  • Security Hotspots (potenciais problemas)
└─ Ação: Endereçar gradualmente
```

#### False Positives vs True Positives

**False Positive**: SAST reporta vulnerabilidade que não existe na prática.

**Exemplo de False Positive**:

```python
# SAST detecta: "Hardcoded password"
password = "default_password_123"  # ← Flagged

# Mas na prática:
if password == "default_password_123":
    raise Exception("Must change default password")  # ← Não é vulnerabilidade!
```

**True Positive**: SAST reporta vulnerabilidade real.

**Exemplo de True Positive**:

```python
# SAST detecta: "SQL Injection"
user_id = request.get('id')  # ← User input
query = f"SELECT * FROM users WHERE id = {user_id}"  # ← VULNERÁVEL
db.execute(query)  # ← SQL Injection confirmado
```

#### Como Validar Findings

**Processo de Validação**:

```
1. SAST Reporta Finding
   │
   ▼
2. Analisar Contexto
   ├─ Ler código ao redor
   ├─ Verificar se dados são sanitizados
   └─ Verificar se há controles de acesso
   │
   ├─ É False Positive? → Marcar como "Won't Fix" / "False Positive"
   │
   └─ É True Positive? → Continuar
      │
      ▼
3. Priorizar
   ├─ Severidade (Critical > High > Medium > Low)
   ├─ Exploitability (fácil explorar?)
   ├─ Impacto (dados sensíveis afetados?)
   └─ Contexto (código em produção?)
   │
   ▼
4. Corrigir ou Aceitar Risco
   ├─ Corrigir vulnerabilidade
   ├─ Documentar risco aceito (com justificativa)
   └─ Criar issue de tracking
```

**Template de Validação**:

```markdown
## Finding: SQL Injection em UserService.getUser()

**Severidade SAST**: Critical
**CWE**: CWE-89 (SQL Injection)
**Localização**: `src/services/UserService.java:45`

**Código Flagado**:
```java
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);
```

**Análise**:
- [ ] Dados são validados antes de usar?
- [ ] Há sanitização (prepared statements)?
- [ ] Código está em produção?
- [ ] Acesso requer autenticação?

**Decisão**:
- [ ] True Positive - Corrigir imediatamente
- [ ] False Positive - Marcar como resolvido (razão: ...)
- [ ] Aceitar Risco - Documentar (razão: ...)

**Ação**: [Descrever ação tomada]
```

---

## 🛠️ Exemplos Práticos Completos

### Exemplo 1: Configurar SonarQube em Projeto Node.js

**Contexto**: Configurar SonarQube para analisar projeto Node.js/TypeScript.

**Passo 1: Instalar SonarQube (Docker)**

```bash
# Baixar e executar SonarQube
docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community

# Acessar: http://localhost:9000
# Login padrão: admin/admin (solicita troca na primeira vez)
```

**Passo 2: Instalar SonarScanner**

```bash
# macOS
brew install sonar-scanner

# Ou usar Docker
docker pull sonarsource/sonar-scanner-cli
```

**Passo 3: Configurar Projeto**

```properties
# sonar-project.properties
sonar.projectKey=meu-projeto-nodejs
sonar.projectName=Meu Projeto Node.js
sonar.projectVersion=1.0

# Código fonte
sonar.sources=src
sonar.tests=test
sonar.sourceEncoding=UTF-8

# Linguagem
sonar.language=js
sonar.javascript.lcov.reportPaths=coverage/lcov.info

# Exclusões
sonar.exclusions=**/node_modules/**,**/dist/**,**/*.spec.ts

# Regras de segurança
sonar.security.hotspots=high,medium
```

**Passo 4: Configurar Quality Gate**

No SonarQube Dashboard:
- Vá em Quality Gates
- Configure:
  - Security Rating: A ou B
  - Security Hotspots: 0 Critical/High
  - Vulnerabilities: 0 Critical, máximo 5 High

**Passo 5: Executar Scan**

```bash
# Gerar token no SonarQube (My Account > Security)
export SONAR_TOKEN=seu_token_aqui

# Executar scan
sonar-scanner \
  -Dsonar.projectKey=meu-projeto-nodejs \
  -Dsonar.sources=src \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=$SONAR_TOKEN
```

**Passo 6: Integrar no CI/CD (GitHub Actions)**

```yaml
# .github/workflows/sonar.yml
name: SonarQube Analysis

on:
  pull_request:
  push:
    branches: [main]

jobs:
  sonar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests with coverage
        run: npm test -- --coverage
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
```

### Exemplo 2: Configurar Semgrep em Projeto Python

**Contexto**: Configurar Semgrep para projeto Python com regras customizadas.

**Passo 1: Instalar Semgrep**

```bash
# Instalação
pip install semgrep

# Ou via Homebrew (macOS)
brew install semgrep
```

**Passo 2: Criar Configuração**

```yaml
# .semgrep.yml
rules:
  # Regras OWASP
  - id: owasp-python
    config: p/owasp-top-ten
  
  # Regras customizadas
  - id: hardcoded-secrets
    languages: [python]
    severity: ERROR
    patterns:
      - pattern: |
          $X = "...$SECRET..."
        where:
          - pattern-inside: |
              $SECRET = $PATTERN
          - metavariable-regex:
              metavariable: $SECRET
              regex: (password|secret|api_key|token|credential)
    message: "Hardcoded secret detected: $SECRET"
    metadata:
      cwe: "CWE-798: Use of Hard-coded Credentials"
  
  - id: sql-injection-django
    languages: [python]
    severity: ERROR
    patterns:
      - pattern: |
          $MODEL.objects.raw("...$USER_INPUT...")
      - pattern: |
          $MODEL.objects.extra(where=["...$USER_INPUT..."])
    message: "Potential SQL Injection. Use parameterized queries instead."
    metadata:
      cwe: "CWE-89: SQL Injection"
```

**Passo 3: Executar Scan**

```bash
# Scan básico (usa regras padrão)
semgrep --config=auto src/

# Scan com configuração customizada
semgrep --config=.semgrep.yml src/

# Scan com saída JSON para integração
semgrep --config=auto --json --output=results.json src/

# Scan apenas regras de segurança
semgrep --config=p/security-audit src/
```

**Passo 4: Integrar em Pre-commit Hook**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config=auto', '--error']
```

**Passo 5: Exemplo de Finding**

```python
# src/auth.py (código vulnerável)
import os

# SAST detecta: Hardcoded secret
API_KEY = "sk_live_1234567890abcdef"  # ← Flagged por Semgrep

def authenticate(user_id, password):
    user_input = request.get('user_id')  # ← User input
    
    # SAST detecta: SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_input}"  # ← Flagged
    return db.execute(query)
```

**Saída Semgrep**:

```
src/auth.py
  hardcoded-secrets
    Line 4: API_KEY = "sk_live_1234567890abcdef"
    Message: Hardcoded secret detected: API_KEY
    Severity: ERROR
    CWE: CWE-798

  sql-injection-django
    Line 10: query = f"SELECT * FROM users WHERE id = {user_input}"
    Message: Potential SQL Injection. Use parameterized queries instead.
    Severity: ERROR
    CWE: CWE-89
```

### Exemplo 3: Integração SAST no CI/CD (GitLab CI)

**Contexto**: Configurar pipeline GitLab CI que executa múltiplas ferramentas SAST.

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - security

# Job de SAST com múltiplas ferramentas
sast:
  stage: security
  image: node:18
  script:
    # 1. ESLint Security Plugin (JavaScript)
    - npm install
    - npm run lint:security || true
    
    # 2. Semgrep (universal)
    - pip install semgrep
    - semgrep --config=auto --json --output=semgrep.json . || true
    
    # 3. Bandit (se projeto Python)
    - pip install bandit || true
    - bandit -r . -f json -o bandit.json || true
    
    # 4. SonarQube (se configurado)
    - sonar-scanner || true
    
    # 5. Agregar resultados
    - python scripts/aggregate_sast_results.py
    
  artifacts:
    reports:
      sast: sast-report.json
    paths:
      - semgrep.json
      - bandit.json
      - sast-report.html
    expire_in: 1 week
  
  allow_failure: false  # Falha pipeline se encontrar Critical
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Job para validar findings
sast-validation:
  stage: security
  image: python:3.9
  script:
    - python scripts/validate_sast_findings.py
  needs:
    - sast
  allow_failure: true
```

### Exemplo 4: Criar Regra Customizada Semgrep

**Contexto**: Criar regra para detectar uso inseguro de `eval()` em JavaScript.

**Regra Customizada**:

```yaml
# regras/eval-injection.yaml
rules:
  - id: eval-injection
    languages: [javascript, typescript]
    severity: ERROR
    message: "Use of eval() is dangerous and can lead to code injection. Use JSON.parse() or alternative safe methods."
    patterns:
      - pattern-either:
          - pattern: eval($EXPR)
          - pattern: Function($EXPR)
          - pattern: setTimeout($EXPR, ...)
          - pattern: setInterval($EXPR, ...)
    exceptions:
      - pattern: eval("true")  # Permite casos específicos
    metadata:
      cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
      owasp: "A03:2021 – Injection"
      category: security
      technology:
        - javascript
        - typescript
```

**Uso da Regra**:

```bash
# Executar apenas regra customizada
semgrep --config=regras/eval-injection.yaml src/

# Executar todas as regras (incluindo custom)
semgrep --config=auto --config=regras/ src/
```

**Exemplo de Código que Seria Flagado**:

```javascript
// ❌ VULNERÁVEL - Será flagado
const userInput = request.body.code;
eval(userInput);  // ← Flagged: eval-injection

// ✅ SEGURO - Não será flagado
const data = request.body.data;
const parsed = JSON.parse(data);  // OK
```

---

## ✅ Padrões e Boas Práticas

### Boas Práticas de SAST

1. **Execute SAST cedo e frequentemente**
   - **Por quê**: Encontrar problemas cedo reduz custo de correção drasticamente
   - **Como**: Integrar em pre-commit hooks e CI/CD
   - **Exemplo**: `pre-commit run semgrep` antes de cada commit
   - **Benefício**: Problemas são corrigidos antes de chegar ao repositório

2. **Configure Quality Gates apropriados**
   - **Por quê**: Previne merge de código com vulnerabilidades críticas
   - **Como**: Bloquear merge se encontrar Critical/High não corrigidos
   - **Exemplo**: SonarQube Quality Gate com "0 Critical vulnerabilities"
   - **Benefício**: Vulnerabilidades críticas nunca chegam à produção

3. **Tune regras para seu contexto**
   - **Por quê**: Reduz false positives e foca em problemas reais
   - **Como**: Desabilitar regras não aplicáveis, criar regras customizadas
   - **Exemplo**: Desabilitar regras de Python em projeto Java
   - **Benefício**: Menos ruído, mais sinal útil

4. **Valide findings antes de corrigir**
   - **Por quê**: Nem tudo que SAST reporta é vulnerabilidade real
   - **Como**: Processo de triagem que valida cada finding
   - **Exemplo**: Checklist de validação para cada Critical/High
   - **Benefício**: Evita trabalho desnecessário corrigindo false positives

5. **Priorize por risco real**
   - **Por quê**: Nem todas as vulnerabilidades têm mesmo impacto
   - **Como**: Considerar exploitability, impacto, contexto
   - **Exemplo**: SQL Injection em área pública > XSS em área admin
   - **Benefício**: Foca esforço onde realmente importa

6. **Combine múltiplas ferramentas**
   - **Por quê**: Cada ferramenta tem pontos fortes diferentes
   - **Como**: Usar SonarQube + Semgrep + ferramentas específicas de linguagem
   - **Exemplo**: SonarQube para cobertura completa + Semgrep para velocidade
   - **Benefício**: Cobertura máxima de vulnerabilidades

7. **Documente decisões de risco aceito**
   - **Por quê**: Transparência e rastreabilidade são importantes
   - **Como**: Documentar por que vulnerabilidade não será corrigida
   - **Exemplo**: "XSS Low em área interna: risco aceito, requer autenticação"
   - **Benefício**: Compliance e auditoria facilitadas

8. **Use SAST para educar desenvolvedores**
   - **Por quê**: SAST é ótima ferramenta de aprendizado
   - **Como**: Mostrar findings em code reviews, sessões de treinamento
   - **Exemplo**: "Veja como SAST detectou este SQL Injection..."
   - **Benefício**: Desenvolvedores aprendem padrões seguros

9. **Mantenha ferramentas atualizadas**
   - **Por quê**: Novas vulnerabilidades e regras são adicionadas constantemente
   - **Como**: Atualizar regras e versões de ferramentas regularmente
   - **Exemplo**: Atualizar Semgrep rules mensalmente
   - **Benefício**: Detecta vulnerabilidades mais recentes

10. **Integre com ferramentas de tracking**
    - **Por quê**: Rastreabilidade e gestão de vulnerabilidades
    - **Como**: Integrar SAST com Jira, GitHub Issues, etc.
    - **Exemplo**: Criar issue automaticamente para cada Critical
    - **Benefício**: Nenhuma vulnerabilidade fica esquecida

### Anti-padrões Comuns

1. **Não ignore todos os findings de uma vez**
   - **Problema**: Marcar tudo como "Won't Fix" sem análise
   - **Solução**: Validar cada finding individualmente
   - **Impacto**: Vulnerabilidades reais podem passar despercebidas

2. **Não execute SAST apenas antes do release**
   - **Problema**: Encontrar problemas tarde, quando correção é cara
   - **Solução**: Executar continuamente (CI/CD, pre-commit)
   - **Impacto**: Correções tardias são caras e podem causar atrasos

3. **Não confie cegamente em SAST**
   - **Problema**: SAST não encontra tudo (especialmente problemas de runtime)
   - **Solução**: Combinar com DAST, IAST, testes manuais
   - **Impacto**: Falsa sensação de segurança

4. **Não configure Quality Gates muito rígidos inicialmente**
   - **Problema**: Bloqueia todo desenvolvimento se código legado tem problemas
   - **Solução**: Começar permissivo, apertar gradualmente
   - **Impacto**: Desenvolvedores podem desabilitar SAST se muito restritivo

5. **Não trate todos os findings com mesma prioridade**
   - **Problema**: Critical e Low recebem mesma atenção
   - **Solução**: Priorizar por severidade e contexto
   - **Impacto**: Recursos mal alocados, problemas críticos podem não ser corrigidos

6. **Não use apenas ferramentas open-source sem avaliar**
   - **Problema**: Ferramentas gratuitas podem não ser suficientes
   - **Solução**: Avaliar necessidade de ferramentas comerciais
   - **Impacto**: Pode faltar cobertura em projetos enterprise

7. **Não execute SAST sem contexto de negócio**
   - **Problema**: Tratar vulnerabilidade em código não usado igual a código crítico
   - **Solução**: Considerar contexto (código ativo? em produção? dados sensíveis?)
   - **Impacto**: Priorização incorreta de esforços

8. **Não mantenha regras desatualizadas**
   - **Problema**: Regras antigas podem não detectar vulnerabilidades novas
   - **Solução**: Atualizar regras regularmente
   - **Impacto**: Vulnerabilidades novas não são detectadas

---

## 🎓 Exercícios Práticos

### Exercício 1: Configurar SonarQube em Projeto Próprio (Básico)

**Objetivo**: Configurar SonarQube do zero em um projeto existente.

**Descrição**:
1. Instale SonarQube usando Docker
2. Configure projeto no SonarQube
3. Execute primeiro scan
4. Analise resultados e identifique top 5 vulnerabilidades

**Arquivo**: `exercises/exercise-2-1-1-sonarqube-setup.md`

---

### Exercício 2: Criar Regras Customizadas Semgrep (Intermediário)

**Objetivo**: Criar regras customizadas para padrões específicos do seu projeto.

**Descrição**:
1. Identifique padrão inseguro comum no seu código
2. Crie regra Semgrep para detectar esse padrão
3. Teste regra em código existente
4. Documente regra e adicione ao repositório

**Arquivo**: `exercises/exercise-2-1-2-semgrep-custom-rules.md`

---

### Exercício 3: Integrar SAST no CI/CD (Intermediário)

**Objetivo**: Integrar ferramentas SAST no pipeline de CI/CD.

**Descrição**:
1. Escolha ferramenta SAST apropriada para seu projeto
2. Configure no GitHub Actions / GitLab CI / Jenkins
3. Configure Quality Gate que bloqueia merge se Critical encontrado
4. Teste pipeline com código vulnerável

**Arquivo**: `exercises/exercise-2-1-3-sast-cicd.md`

---

### Exercício 4: Validar e Priorizar Findings SAST (Avançado)

**Objetivo**: Criar processo de triagem de findings SAST.

**Descrição**:
1. Execute SAST em projeto real
2. Para cada finding Critical/High:
   - Valide se é True Positive ou False Positive
   - Analise contexto e impacto
   - Priorize por risco real
   - Documente decisão
3. Crie dashboard de vulnerabilidades priorizadas

**Arquivo**: `exercises/exercise-2-1-4-validate-findings.md`

---

### Exercício 5: Comparar Ferramentas SAST (Avançado)

**Objetivo**: Comparar diferentes ferramentas SAST no mesmo projeto.

**Descrição**:
1. Execute 2-3 ferramentas SAST diferentes no mesmo projeto
2. Compare:
   - Número de findings por severidade
   - False positive rate (validação manual)
   - Tempo de execução
   - Facilidade de configuração
   - Custo
3. Crie relatório comparativo com recomendação

**Arquivo**: `exercises/exercise-2-1-5-compare-sast-tools.md`

---

## 📚 Referências Externas

### Documentação Oficial

- **[OWASP - Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)**: Lista completa de ferramentas SAST
- **[SonarQube Documentation](https://docs.sonarqube.org/latest/)**: Documentação completa do SonarQube
- **[Semgrep Documentation](https://semgrep.dev/docs/)**: Documentação oficial do Semgrep
- **[Checkmarx SAST Documentation](https://checkmarx.com/resource/documents/)**: Documentação do Checkmarx
- **[CWE - Common Weakness Enumeration](https://cwe.mitre.org/)**: Lista completa de vulnerabilidades de software

### Artigos e Tutoriais

- **[OWASP Top 10](https://owasp.org/www-project-top-ten/)**: Top 10 vulnerabilidades web mais críticas
- **[SAST vs DAST: What's the Difference?](https://www.synopsys.com/blogs/software-security/sast-vs-dast/)**: Comparação detalhada
- **[Reducing False Positives in SAST](https://www.veracode.com/blog/secure-development/how-reduce-false-positives-sast-tools)**: Guia prático
- **[SAST Best Practices](https://www.checkmarx.com/knowledge/knowledge-base/sast-best-practices/)**: Melhores práticas

### Ferramentas e Recursos

- **[Semgrep Registry](https://semgrep.dev/r)**: Regras prontas do Semgrep
- **[SonarQube Rules](https://rules.sonarsource.com/)**: Catálogo de regras SonarQube
- **[Bandit Rules](https://bandit.readthedocs.io/en/latest/plugins/index.html)**: Regras disponíveis no Bandit
- **[FindSecBugs](https://find-sec-bugs.github.io/)**: Plugin de segurança para SpotBugs (Java)

### Comunidade

- **[OWASP Community](https://owasp.org/www-community/)**: Comunidade global de segurança
- **[Semgrep Slack](https://r2c.dev/slack)**: Comunidade Semgrep
- **[SonarSource Community](https://community.sonarsource.com/)**: Fórum da comunidade SonarSource

---

## 📝 Resumo

### Principais Conceitos

- **SAST**: Análise estática de código sem executar aplicação
- **Ferramentas Principais**: SonarQube (completo), Semgrep (rápido), Checkmarx (enterprise)
- **Tipos de Análise**: Pattern matching, data flow, control flow, taint analysis
- **Severidade**: Critical, High, Medium, Low
- **False Positives**: Findings que não são vulnerabilidades reais - precisam validação
- **Quality Gates**: Bloqueiam merge se critérios de segurança não atendidos

### Pontos-Chave para Lembrar

- ✅ **Execute SAST cedo**: Integre em CI/CD e pre-commit hooks
- ✅ **Valide findings**: Nem tudo que SAST reporta é vulnerabilidade real
- ✅ **Priorize por risco**: Considere severidade, exploitability, impacto, contexto
- ✅ **Combine ferramentas**: Use múltiplas ferramentas para cobertura máxima
- ✅ **Configure Quality Gates**: Bloqueie código vulnerável antes de merge
- ✅ **Tune regras**: Customize para reduzir false positives
- ✅ **Mantenha atualizado**: Atualize regras e ferramentas regularmente
- ✅ **Use para educar**: SAST é ótima ferramenta de aprendizado para devs

### Próximos Passos

- Próxima aula: DAST - Testes Dinâmicos (aplicação em execução)
- Praticar configurando SAST em projetos reais
- Explorar regras customizadas para padrões específicos do seu contexto
- Integrar SAST com outras ferramentas (SCA, DAST) para cobertura completa

---

## ✅ Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Contexto histórico do SAST
- [x] Comparação detalhada com outras metodologias (DAST, IAST, SCA)
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos (SonarQube, Semgrep, CI/CD)
- [x] Tabelas comparativas de ferramentas
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 1.5: Fundamentos de Segurança em QA](./lesson-1-5.md)  
**Próxima Aula**: [Aula 2.2: DAST - Testes Dinâmicos](./lesson-2-2.md)  
**Voltar ao Módulo**: [Módulo 2: Testes de Segurança na Prática](../index.md)