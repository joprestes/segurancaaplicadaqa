---
layout: exercise
title: "Exercício 2.2.3: Integrar DAST no CI/CD"
slug: "dast-cicd"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-3-dast-cicd/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

## Objetivo

Este exercício tem como objetivo **integrar ferramentas DAST em pipeline CI/CD** com Quality Gates que bloqueiam deploy quando vulnerabilidades críticas são encontradas.

Ao completar este exercício, você será capaz de:

- Configurar OWASP ZAP em GitHub Actions / GitLab CI / Jenkins
- Configurar Quality Gates apropriados
- Bloquear deploy/pipeline quando Critical vulnerabilities são encontradas
- Configurar notificações e relatórios
- Testar pipeline com aplicação vulnerável

---

## Descrição

Você vai configurar OWASP ZAP em um pipeline CI/CD real, configurar Quality Gates, e validar que o pipeline bloqueia aplicação vulnerável.

### Contexto

Integrar DAST no CI/CD garante que vulnerabilidades sejam detectadas antes do deploy, prevenindo que aplicações inseguras cheguem à produção.

### Tarefa Principal

1. Escolher ferramenta DAST apropriada (OWASP ZAP)
2. Configurar no GitHub Actions / GitLab CI / Jenkins
3. Configurar Quality Gate que bloqueia deploy se Critical encontrado
4. Testar pipeline com aplicação vulnerável (deve falhar)
5. Testar pipeline com aplicação segura (deve passar)

---

## Pré-requisitos

- Pipeline CI/CD configurável
- Aplicação disponível em ambiente de teste
- Conhecimento básico de YAML

---

## Passo a Passo

### Passo 1: Escolher Ferramenta DAST

**1.1. Avaliar Opções**

Para este exercício, usaremos **OWASP ZAP** (gratuito e open-source).

**1.2. Decisão**

- Ferramenta escolhida: OWASP ZAP
- Justificativa: Gratuito, open-source, fácil integração com CI/CD

### Passo 2: Configurar GitHub Actions (Opção A)

**2.1. Criar Workflow Básico**

Criar arquivo `.github/workflows/dast.yml`:

```yaml
name: DAST Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    # Scan diário às 2h da manhã
    - cron: '0 2 * * *'

jobs:
  dast:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Start application
        run: |
          docker-compose up -d app
          sleep 30  # Aguardar aplicação iniciar
      
      # Passo 2.2: Adicionar OWASP ZAP
```

**2.2. Adicionar OWASP ZAP Baseline Scan**

```yaml
      - name: Run OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: 'http://app:3000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
```

**2.3. Adicionar OWASP ZAP Full Scan**

```yaml
      - name: Run OWASP ZAP Full Scan
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: 'http://app:3000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-J'
```

**2.4. Workflow Completo GitHub Actions**

```yaml
# .github/workflows/dast.yml
name: DAST Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  dast:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Start application
        run: |
          docker-compose up -d app
          sleep 30  # Aguardar aplicação iniciar
      
      - name: Run OWASP ZAP Baseline Scan
        id: zap-baseline
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: 'http://app:3000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
      
      - name: Run OWASP ZAP Full Scan
        id: zap-full
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: 'http://app:3000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-J'
      
      - name: Upload ZAP results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: zap-results
          path: |
            zap-report.json
            zap-report.html
      
      - name: Check ZAP results
        if: steps.zap-full.outcome == 'failure'
        run: |
          echo "❌ OWASP ZAP found Critical/High findings. Pipeline failed."
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
              body: '✅ DAST scan completed. No critical vulnerabilities found.'
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
  APP_URL: "http://app:3000"

dast:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - apk add --no-cache docker-compose
    - docker-compose up -d app
    - sleep 30  # Aguardar aplicação iniciar
  
  script:
    # OWASP ZAP Baseline Scan
    - echo "🔍 Running OWASP ZAP Baseline Scan..."
    - |
      docker run --rm \
        -v $(pwd):/zap/wrk/:rw \
        -t owasp/zap2docker-stable zap-baseline.py \
        -t $APP_URL \
        -J zap-baseline.json \
        -r zap-baseline.html || true
    
    # OWASP ZAP Full Scan
    - echo "🔍 Running OWASP ZAP Full Scan..."
    - |
      docker run --rm \
        -v $(pwd):/zap/wrk/:rw \
        -t owasp/zap2docker-stable zap-full-scan.py \
        -t $APP_URL \
        -J zap-full.json \
        -r zap-full.html || true
    
    # Validar Critical findings
    - python3 scripts/check_critical_findings.py zap-full.json || exit 1
    
  artifacts:
    reports:
      sast: zap-full.json
    paths:
      - zap-baseline.json
      - zap-baseline.html
      - zap-full.json
      - zap-full.html
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
Script para validar findings DAST e falhar pipeline se Critical encontrado.
"""

import json
import sys
from pathlib import Path

def check_zap_results(zap_file='zap-full.json'):
    """Verifica resultados do OWASP ZAP."""
    if not Path(zap_file).exists():
        print(f"⚠️ {zap_file} not found. Skipping.")
        return 0
    
    with open(zap_file) as f:
        data = json.load(f)
    
    critical_count = 0
    high_count = 0
    
    # OWASP ZAP estrutura pode variar
    # Ajustar conforme formato do relatório
    alerts = data.get('site', [{}])[0].get('alerts', [])
    
    for alert in alerts:
        risk = alert.get('risk', '').upper()
        if risk == 'HIGH':
            critical_count += 1
        elif risk == 'MEDIUM':
            high_count += 1
    
    print(f"📊 OWASP ZAP Results:")
    print(f"   Critical/High: {critical_count}")
    print(f"   Medium: {high_count}")
    
    return critical_count

def main():
    """Valida findings e falha pipeline se Critical encontrado."""
    print("🔍 Checking DAST results for Critical vulnerabilities...")
    
    total_critical = check_zap_results('zap-full.json')
    
    # Resultado final
    if total_critical > 0:
        print(f"\n❌ FAILED: Found {total_critical} Critical vulnerabilities!")
        print("Pipeline blocked. Please fix Critical vulnerabilities before deploying.")
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

Criar arquivo `.github/workflows/dast-quality-gate.yml`:

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

### Passo 6: Testar Pipeline

**6.1. Teste 1: Pipeline com Aplicação Segura**

1. Commitar código seguro (sem vulnerabilidades conhecidas)
2. Criar Pull Request
3. Verificar que pipeline passa ✅
4. Verificar que DAST não encontra Critical vulnerabilities

**6.2. Teste 2: Pipeline com Aplicação Vulnerável**

1. Adicionar vulnerabilidade propositalmente (ex: SQL Injection em endpoint)
2. Commitar e criar Pull Request
3. Verificar que pipeline **falha** ❌
4. Verificar que DAST detecta vulnerabilidades
5. Verificar que merge está bloqueado

**6.3. Teste 3: Corrigir Vulnerabilidade**

1. Corrigir vulnerabilidade
2. Commitar correção
3. Verificar que pipeline **passa** ✅
4. Verificar que DAST não encontra vulnerabilidades
5. Verificar que merge está permitido

---

## Dicas

1. **Comece simples**: Configure scan passivo primeiro, depois adicione scan ativo
2. **Quality Gate progressivo**: Comece permissivo (só Critical), depois aperte gradualmente
3. **Teste com aplicação real**: Use aplicação vulnerável real para validar que funciona
4. **Documente critérios**: Documente por que Quality Gate está configurado assim
5. **Comunique mudanças**: Avise time antes de bloquear pipeline pela primeira vez
6. **False positives**: Configure exceções para false positives conhecidos

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] Pipeline CI/CD configurado (GitHub Actions / GitLab CI / Jenkins)
- [ ] OWASP ZAP configurado no pipeline
- [ ] Quality Gate configurado (bloqueia se Critical encontrado)
- [ ] Pipeline testado com aplicação segura (deve passar)
- [ ] Pipeline testado com aplicação vulnerável (deve falhar)
- [ ] Pipeline testado com correção (deve passar após correção)
- [ ] Script de validação criado e funcionando
- [ ] Notificações configuradas (opcional)

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Exercício 2.2.4: Validar e Priorizar Findings DAST
- Configurar DAST em outros projetos
- Integrar múltiplas ferramentas DAST no mesmo pipeline
- Configurar DAST em diferentes ambientes (dev, staging, prod)

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
2. Screenshot do pipeline passando (aplicação segura)
3. Screenshot do pipeline falhando (aplicação vulnerável)
4. Documentação do Quality Gate configurado
5. Dúvidas ou desafios encontrados

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 2.2 (DAST), Conhecimento básico de CI/CD (GitHub Actions/GitLab CI)
