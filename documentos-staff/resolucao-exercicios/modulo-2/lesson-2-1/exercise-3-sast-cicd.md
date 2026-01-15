---
exercise_id: lesson-2-1-exercise-3-sast-cicd
title: "Exercício 2.1.3: Integrar SAST no CI/CD"
lesson_id: lesson-2-1
module: module-2
difficulty: "Intermediário"
last_updated: 2025-01-15
---

# Exercício 2.1.3: Integrar SAST no CI/CD

## 📋 Enunciado Completo

Este exercício tem como objetivo **integrar ferramentas SAST em pipeline CI/CD** com Quality Gates que bloqueiam merge quando vulnerabilidades críticas são encontradas.

### Tarefa Principal

1. Escolher ferramenta SAST apropriada para seu projeto
2. Configurar no GitHub Actions / GitLab CI / Jenkins
3. Configurar Quality Gate que bloqueia merge se Critical encontrado
4. Testar pipeline com código vulnerável (deve falhar)
5. Testar pipeline com código seguro (deve passar)

---

## ✅ Soluções Detalhadas

### Passo 1: Escolher Ferramenta SAST

**Solução Esperada:**

**1.1. Avaliação por Linguagem:**
- JavaScript/TypeScript: Semgrep ou ESLint Security Plugin
- Python: Semgrep ou Bandit
- Java: SonarQube ou FindSecBugs
- Multi-linguagem: SonarQube ou Semgrep

**1.2. Justificativa (Exemplo):**
- Ferramenta escolhida: Semgrep
- Justificativa: Projeto multi-linguagem (Python + JavaScript), Semgrep suporta ambas, rápido, fácil de configurar

### Passo 2: Configurar GitHub Actions

**Solução Esperada - Workflow Completo:**

**2.1. Arquivo `.github/workflows/sast.yml`:**
```yaml
name: SAST Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run Semgrep
        id: semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            auto
            p/security-audit
            p/owasp-top-ten
          generateSarif: "1"
          fail_on_severity: error
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: semgrep.sarif
      
      - name: Check Semgrep results
        if: steps.semgrep.outcome == 'failure'
        run: |
          echo "❌ Semgrep found Critical/High findings. Pipeline failed."
          echo "Please review findings and fix vulnerabilities before merging."
          exit 1
```

**2.2. Validação de Quality Gate:**
```yaml
      - name: Validate Quality Gate
        run: |
          # Verificar se há findings Critical/High
          if [ -f semgrep.json ]; then
            critical_count=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' semgrep.json)
            if [ "$critical_count" -gt 0 ]; then
              echo "❌ Found $critical_count Critical findings. Pipeline blocked."
              exit 1
            fi
          fi
```

### Passo 3: Configurar GitLab CI

**Solução Esperada:**

**3.1. Arquivo `.gitlab-ci.yml`:**
```yaml
stages:
  - build
  - security

variables:
  SEMGREP_CONFIG: "p/security-audit p/owasp-top-ten"

sast:
  stage: security
  image: node:18
  before_script:
    - apt-get update -qq && apt-get install -y -qq python3-pip
    - pip3 install semgrep
  
  script:
    - semgrep --config=$SEMGREP_CONFIG --json --output=semgrep.json . || true
    - python3 scripts/check_critical_findings.py || exit 1
    
  artifacts:
    reports:
      sast: sast-report.json
    paths:
      - semgrep.json
    expire_in: 1 week
    when: always
  
  allow_failure: false
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

**3.2. Script de Validação:**
```python
# scripts/check_critical_findings.py
import json
import sys

with open('semgrep.json') as f:
    data = json.load(f)

critical_count = sum(1 for r in data.get('results', []) 
                     if r.get('extra', {}).get('severity') == 'ERROR')

if critical_count > 0:
    print(f"❌ Found {critical_count} Critical findings. Pipeline blocked.")
    sys.exit(1)
else:
    print("✅ No Critical findings found. Pipeline passed.")
    sys.exit(0)
```

### Passo 4: Quality Gate

**Solução Esperada:**

**4.1. Quality Gate Básico:**
```yaml
# Quality Gate: Bloquear se encontrar Critical
Quality Gate:
  - New Vulnerabilities: 0 Critical
  - New Vulnerabilities: Máximo 5 High
```

**4.2. Quality Gate Gradual (Recomendado):**
```yaml
# Semana 1-2: Permissivo
- New Vulnerabilities: 0 Critical apenas

# Semana 3-4: Médio
- New Vulnerabilities: 0 Critical, máx 10 High

# Mês 2+: Rigoroso
- New Vulnerabilities: 0 Critical, máx 5 High
- Security Rating: A ou B
```

### Passo 5: Testar Pipeline

**5.1. Teste 1: Código Seguro (Deve Passar)**

**Código de Teste:**
```python
# src/auth.py (código seguro)
def login(username, password):
    # ✅ Validação de entrada
    if not username or not password:
        raise ValueError("Invalid credentials")
    
    # ✅ Prepared statement
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    user = db.execute(query, (username, password))
    
    return user
```

**Resultado Esperado:**
- Pipeline passa ✅
- Semgrep não encontra vulnerabilities críticas
- Merge permitido

**5.2. Teste 2: Código Vulnerável (Deve Falhar)**

**Código de Teste:**
```python
# src/auth.py (código vulnerável)
def login(username, password):
    # ❌ SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = db.execute(query)
    
    return user
```

**Resultado Esperado:**
- Pipeline falha ❌
- Semgrep encontra SQL Injection (Critical)
- Merge bloqueado
- Mensagem: "Found 1 Critical findings. Pipeline blocked."

**5.3. Teste 3: Corrigir e Re-testar**

**Código Corrigido:**
```python
# src/auth.py (código corrigido)
def login(username, password):
    # ✅ Validação
    if not username or not password:
        raise ValueError("Invalid credentials")
    
    # ✅ Prepared statement
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    user = db.execute(query, (username, password))
    
    return user
```

**Resultado Esperado:**
- Pipeline passa ✅
- Semgrep não encontra vulnerabilities
- Merge permitido

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (60 pontos)

**Configuração CI/CD:**
- [ ] Ferramenta SAST escolhida e justificada (10 pontos)
- [ ] Pipeline CI/CD configurado (GitHub Actions/GitLab CI) (15 pontos)
- [ ] SAST integrado no pipeline (15 pontos)
- [ ] Quality Gate configurado (10 pontos)

**Teste de Pipeline:**
- [ ] Pipeline testado com código vulnerável (falha) (5 pontos)
- [ ] Pipeline testado com código seguro (passa) (5 pontos)

### ⭐ Importantes (25 pontos)

**Quality Gate Funcional:**
- [ ] Quality Gate bloqueia merge quando Critical encontrado (10 pontos)
- [ ] Mensagens de erro são claras (5 pontos)

**Integração Completa:**
- [ ] Notificações configuradas (opcional mas recomendado) (5 pontos)
- [ ] Relatórios salvos como artifacts (5 pontos)
- [ ] Script de validação funciona corretamente (5 pontos)

### 💡 Bônus (15 pontos)

**Integração Avançada:**
- [ ] Múltiplas ferramentas SAST integradas (5 pontos)
- [ ] Quality Gate gradual implementado (5 pontos)
- [ ] Dashboard de segurança configurado (5 pontos)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Integração CI/CD**: Aluno integra SAST no pipeline?
2. **Quality Gates**: Aluno configura Quality Gates apropriados?
3. **Teste**: Aluno valida que pipeline funciona corretamente?
4. **Automação**: Aluno automatiza validação de findings?

### Erros Comuns

1. **Erro: Pipeline Sempre Falha**
   - **Situação**: Quality Gate muito rígido desde início
   - **Feedback**: "Boa configuração! Se pipeline está sempre falhando, comece permissivo (apenas Critical) e aperte gradualmente. Isso permite adaptação do time sem bloqueios constantes."

2. **Erro: Pipeline Não Bloqueia**
   - **Situação**: SAST encontra vulnerabilities mas pipeline passa
   - **Feedback**: "SAST configurado corretamente! Para bloquear pipeline, configure `fail_on_severity: error` ou adicione script de validação que falha se encontrar Critical findings."

3. **Erro: Não Funciona em PR**
   - **Situação**: SAST não executa em Pull Requests
   - **Feedback**: "Pipeline está quase correto! Verifique triggers: `on: pull_request:` deve estar configurado. Também verifique permissões do GitHub token se necessário."

### Dicas para Feedback

- ✅ **Reconheça**: Pipeline funcional, Quality Gate configurado, testes realizados
- ❌ **Corrija**: Quality Gate incorreto, falta de validação, erros de configuração
- 💡 **Incentive**: Múltiplas ferramentas, notificações, dashboard

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
