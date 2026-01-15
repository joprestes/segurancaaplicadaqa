---
layout: exercise
title: "Exercício 2.1.3: Integrar SAST no CI/CD"
slug: "sast-cicd"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-1-exercise-3-sast-cicd/
lesson_url: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
---

## Objetivo

Este exercício tem como objetivo **integrar ferramentas SAST em pipeline CI/CD** com Quality Gates que bloqueiam merge quando vulnerabilidades críticas são encontradas.

Ao completar este exercício, você será capaz de:

- Configurar SAST em GitHub Actions / GitLab CI / Jenkins
- Configurar Quality Gates apropriados
- Bloquear merge/pipeline quando Critical vulnerabilities são encontradas
- Configurar notificações e relatórios
- Testar pipeline com código vulnerável

---

## Descrição

Você vai configurar uma ferramenta SAST (Semgrep, SonarQube, ou ferramenta específica de linguagem) em um pipeline CI/CD real, configurar Quality Gates, e validar que o pipeline bloqueia código vulnerável.

### Contexto

Integrar SAST no CI/CD garante que vulnerabilidades sejam detectadas antes do merge, prevenindo que código inseguro chegue à branch principal e produção.

### Tarefa Principal

1. Escolher ferramenta SAST apropriada para seu projeto
2. Configurar no GitHub Actions / GitLab CI / Jenkins
3. Configurar Quality Gate que bloqueia merge se Critical encontrado
4. Testar pipeline com código vulnerável (deve falhar)
5. Testar pipeline com código seguro (deve passar)

---

## Requisitos

### Passo 1: Escolher Ferramenta SAST

**1.1. Avaliar Opções**

Escolha a ferramenta SAST apropriada para seu projeto:

| Linguagem | Ferramentas Recomendadas |
|-----------|-------------------------|
| **JavaScript/TypeScript** | Semgrep, ESLint Security Plugin |
| **Python** | Semgrep, Bandit |
| **Java** | SonarQube, FindSecBugs |
| **C#** | SonarQube, Semgrep |
| **Multi-linguagem** | SonarQube, Semgrep |

**1.2. Decisão**

- Ferramenta escolhida: _______________
- Justificativa: _______________

### Passo 2: Configurar GitHub Actions (Opção A)

**2.1. Criar Workflow Básico**

Criar arquivo `.github/workflows/sast.yml`:

```yaml
name: SAST Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    # Scan diário às 2h da manhã
    - cron: '0 2 * * *'

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
      
      - name: Setup Node.js (se projeto Node.js)
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      # Passo 2.2: Adicionar ferramenta SAST específica
```

**2.2. Adicionar Semgrep**

```yaml
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            auto
            p/security-audit
            p/owasp-top-ten
            regras/  # Regras customizadas (se houver)
          generateSarif: "1"
          fail_on_severity: error
```

**2.3. Adicionar ESLint Security (JavaScript/TypeScript)**

```yaml
      - name: Run ESLint Security
        run: |
          npm install --save-dev eslint-plugin-security
          npm run lint:security || true
      
      - name: Upload ESLint results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: eslint-security-results
          path: eslint-security-report.json
```

**2.4. Adicionar Bandit (Python)**

```yaml
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install Bandit
        run: pip install bandit
      
      - name: Run Bandit
        run: |
          bandit -r . -f json -o bandit.json || true
          bandit -r . -f txt -o bandit.txt || true
      
      - name: Check for Critical findings
        run: |
          if [ -f bandit.json ]; then
            critical_count=$(python3 -c "import json; data=json.load(open('bandit.json')); print(sum(1 for r in data.get('results', []) if r.get('issue_severity') == 'HIGH'))")
            if [ "$critical_count" -gt 0 ]; then
              echo "⚠️ Found $critical_count High/Critical findings. Failing pipeline."
              exit 1
            fi
          fi
```

**2.5. Configurar Quality Gate**

Adicionar job para validar findings:

```yaml
  validate-sast:
    runs-on: ubuntu-latest
    needs: sast
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Download SAST results
        uses: actions/download-artifact@v3
        with:
          name: semgrep-results
          path: results/
      
      - name: Check for Critical vulnerabilities
        run: |
          python3 scripts/check_critical_findings.py results/
          if [ $? -ne 0 ]; then
            echo "❌ Critical vulnerabilities found. Pipeline failed."
            exit 1
          else
            echo "✅ No critical vulnerabilities. Pipeline passed."
          fi
```

**2.6. Workflow Completo GitHub Actions**

```yaml
# .github/workflows/sast.yml
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
      
      - name: Run ESLint Security
        continue-on-error: true
        run: |
          npm run lint:security > eslint-security-report.json 2>&1 || true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: semgrep.sarif
      
      - name: Check Semgrep results
        if: steps.semgrep.outcome == 'failure'
        run: |
          echo "❌ Semgrep found Critical/High findings. Pipeline failed."
          exit 1
      
      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '✅ SAST scan completed. No critical vulnerabilities found.'
            })
```

### Passo 3: Configurar GitLab CI (Opção B)

**3.1. Criar Pipeline GitLab CI**

Criar arquivo `.gitlab-ci.yml`:

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - security

variables:
  SEMGREP_CONFIG: "p/security-audit p/owasp-top-ten"

sast:
  stage: security
  image: node:18
  before_script:
    - apt-get update -qq && apt-get install -y -qq python3-pip
    - pip3 install semgrep bandit || true
  
  script:
    # Semgrep
    - echo "🔍 Running Semgrep..."
    - semgrep --config=$SEMGREP_CONFIG --json --output=semgrep.json . || true
    
    # ESLint Security
    - echo "🔍 Running ESLint Security..."
    - npm install
    - npm run lint:security > eslint-security-report.json 2>&1 || true
    
    # Bandit (se Python)
    - echo "🔍 Running Bandit..."
    - bandit -r . -f json -o bandit.json || true
    - bandit -r . -f txt -o bandit.txt || true
    
    # Validar Critical findings
    - python3 scripts/check_critical_findings.py || exit 1
    
  artifacts:
    reports:
      sast: sast-report.json
    paths:
      - semgrep.json
      - bandit.json
      - eslint-security-report.json
    expire_in: 1 week
    when: always
  
  allow_failure: false  # Falha pipeline se encontrar Critical
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Passo 4: Criar Script de Validação

**4.1. Script Python para Validar Findings**

Criar arquivo `scripts/check_critical_findings.py`:

```python
#!/usr/bin/env python3
"""
Script para validar findings SAST e falhar pipeline se Critical encontrado.
"""

import json
import sys
import glob
from pathlib import Path

def check_semgrep_results(semgrep_file='semgrep.json'):
    """Verifica resultados do Semgrep."""
    if not Path(semgrep_file).exists():
        print(f"⚠️ {semgrep_file} not found. Skipping.")
        return 0
    
    with open(semgrep_file) as f:
        data = json.load(f)
    
    critical_count = 0
    high_count = 0
    
    for result in data.get('results', []):
        severity = result.get('extra', {}).get('severity', '').upper()
        if severity == 'ERROR' or severity == 'CRITICAL':
            critical_count += 1
        elif severity == 'WARNING' or severity == 'HIGH':
            high_count += 1
    
    print(f"📊 Semgrep Results:")
    print(f"   Critical: {critical_count}")
    print(f"   High: {high_count}")
    
    return critical_count

def check_bandit_results(bandit_file='bandit.json'):
    """Verifica resultados do Bandit."""
    if not Path(bandit_file).exists():
        print(f"⚠️ {bandit_file} not found. Skipping.")
        return 0
    
    with open(bandit_file) as f:
        data = json.load(f)
    
    critical_count = 0
    
    for result in data.get('results', []):
        severity = result.get('issue_severity', '').upper()
        confidence = result.get('issue_confidence', '').upper()
        
        if severity == 'HIGH' and confidence == 'HIGH':
            critical_count += 1
    
    print(f"📊 Bandit Results:")
    print(f"   Critical: {critical_count}")
    
    return critical_count

def main():
    """Valida findings e falha pipeline se Critical encontrado."""
    print("🔍 Checking SAST results for Critical vulnerabilities...")
    
    total_critical = 0
    
    # Verificar Semgrep
    total_critical += check_semgrep_results('semgrep.json')
    
    # Verificar Bandit
    total_critical += check_bandit_results('bandit.json')
    
    # Resultado final
    if total_critical > 0:
        print(f"\n❌ FAILED: Found {total_critical} Critical vulnerabilities!")
        print("Pipeline blocked. Please fix Critical vulnerabilities before merging.")
        sys.exit(1)
    else:
        print("\n✅ SUCCESS: No Critical vulnerabilities found.")
        sys.exit(0)

if __name__ == '__main__':
    main()
```

**4.2. Tornar Script Executável**

```bash
chmod +x scripts/check_critical_findings.py
```

### Passo 5: Configurar Quality Gate

**5.1. Definir Critérios do Quality Gate**

Criar arquivo `.github/workflows/sast-quality-gate.yml`:

```yaml
# Critérios do Quality Gate
quality_gate:
  # Bloquear se encontrar qualquer Critical
  critical: 0
  
  # Bloquear se encontrar mais de 2 High
  high_max: 2
  
  # Permitir até 10 Medium
  medium_max: 10
  
  # Low não bloqueiam
  low_max: unlimited
```

**5.2. Atualizar Script de Validação**

Adicionar validação de Quality Gate ao script Python:

```python
QUALITY_GATE = {
    'critical': 0,
    'high_max': 2,
    'medium_max': 10,
}

# No final do script:
if critical_count > QUALITY_GATE['critical']:
    print(f"❌ Quality Gate failed: Critical count ({critical_count}) exceeds limit ({QUALITY_GATE['critical']})")
    sys.exit(1)
```

### Passo 6: Testar Pipeline

**6.1. Teste 1: Pipeline com Código Seguro**

1. Commitar código seguro (sem vulnerabilidades conhecidas)
2. Criar Pull Request
3. Verificar que pipeline passa ✅
4. Verificar que SAST não encontra Critical vulnerabilities

**6.2. Teste 2: Pipeline com Código Vulnerável**

1. Adicionar código vulnerável propositalmente:

```python
# src/test_vulnerable.py
def vulnerable_function():
    # SQL Injection
    user_input = request.get('id')
    query = f"SELECT * FROM users WHERE id = {user_input}"
    db.execute(query)
    
    # Hardcoded secret
    api_key = "sk_live_1234567890abcdef"
    
    return {"status": "ok"}
```

2. Commitar e criar Pull Request
3. Verificar que pipeline **falha** ❌
4. Verificar que SAST detecta vulnerabilidades
5. Verificar que merge está bloqueado

**6.3. Teste 3: Corrigir Vulnerabilidade**

1. Corrigir código vulnerável:

```python
# src/test_vulnerable.py
import os

def safe_function():
    # ✅ Prepared Statement
    user_input = request.get('id')
    query = "SELECT * FROM users WHERE id = ?"
    db.execute(query, (user_input,))
    
    # ✅ Environment variable
    api_key = os.getenv("API_KEY")
    
    return {"status": "ok"}
```

2. Commitar correção
3. Verificar que pipeline **passa** ✅
4. Verificar que SAST não encontra vulnerabilidades
5. Verificar que merge está permitido

### Passo 7: Configurar Notificações (Opcional)

**7.1. Notificações no GitHub**

O workflow já está configurado para:
- Comentar em Pull Requests com resultados
- Upload SARIF para GitHub Security tab

**7.2. Notificações via Slack/Email**

Adicionar step ao workflow:

```yaml
      - name: Notify on failure
        if: failure()
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: "SAST scan found Critical vulnerabilities! Pipeline blocked."
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

---

## Dicas

1. **Comece simples**: Configure uma ferramenta SAST primeiro, depois adicione mais
2. **Quality Gate progressivo**: Comece permissivo (só Critical), depois aperte gradualmente
3. **Teste com código real**: Use código vulnerável real para validar que funciona
4. **Documente critérios**: Documente por que Quality Gate está configurado assim
5. **Comunique mudanças**: Avise time antes de bloquear pipeline pela primeira vez
6. **False positives**: Configure exceções para false positives conhecidos

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] Pipeline CI/CD configurado (GitHub Actions / GitLab CI / Jenkins)
- [ ] Ferramenta SAST configurada no pipeline
- [ ] Quality Gate configurado (bloqueia se Critical encontrado)
- [ ] Pipeline testado com código seguro (deve passar)
- [ ] Pipeline testado com código vulnerável (deve falhar)
- [ ] Pipeline testado com correção (deve passar após correção)
- [ ] Script de validação criado e funcionando
- [ ] Notificações configuradas (opcional)

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Exercício 2.1.4: Validar e Priorizar Findings SAST
- Configurar SAST em outros projetos
- Integrar múltiplas ferramentas SAST no mesmo pipeline
- Configurar SAST em diferentes ambientes (dev, staging, prod)

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Pipeline para projeto financeiro hipotético

- **Quality Gate rigoroso**: 0 Critical, máximo 1 High
- **Bloqueio automático**: Pipeline falha imediatamente se Critical encontrado
- **Notificações**: Time de segurança notificado imediatamente
- **Compliance**: Todos os findings devem ser corrigidos antes de deploy em produção

Configure o pipeline com esses critérios mais rigorosos.

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Arquivo de workflow CI/CD configurado
2. Screenshot do pipeline passando (código seguro)
3. Screenshot do pipeline falhando (código vulnerável)
4. Documentação do Quality Gate configurado
5. Dúvidas ou desafios encontrados

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 2.1 (SAST), Conhecimento básico de CI/CD (GitHub Actions/GitLab CI)
