---
exercise_id: lesson-2-2-exercise-3-dast-cicd
title: "Exercício 2.2.3: Integrar DAST no CI/CD"
lesson_id: lesson-2-2
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-14
---

# Exercício 2.2.3: Integrar DAST no CI/CD

## 📋 Enunciado Completo

Este exercício tem como objetivo **integrar ferramentas DAST em pipeline CI/CD** com Quality Gates que bloqueiam deploy quando vulnerabilidades críticas são encontradas.

### Tarefa Principal

1. Escolher ferramenta DAST apropriada (OWASP ZAP)
2. Configurar no GitHub Actions / GitLab CI / Jenkins
3. Configurar Quality Gate que bloqueia deploy se Critical encontrado
4. Testar pipeline com aplicação vulnerável (deve falhar)
5. Testar pipeline com aplicação segura (deve passar)

---

## ✅ Soluções Detalhadas

### Passo 1: Escolher Ferramenta DAST

**Solução Esperada:**
- Ferramenta escolhida: OWASP ZAP
- Justificativa: Gratuito, open-source, fácil integração com CI/CD

### Passo 2: Configurar GitHub Actions

**Solução Esperada - Workflow Completo:**

**2.1. Arquivo `.github/workflows/dast.yml`:**
```yaml
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
```

**Validação Técnica:**
- ✅ Workflow executa sem erros
- ✅ Aplicação inicia antes do scan
- ✅ Scan executa corretamente
- ✅ Pipeline falha quando Critical encontrado

### Passo 3: Configurar GitLab CI

**Solução Esperada:**

**3.1. Arquivo `.gitlab-ci.yml`:**
```yaml
dast:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - apk add --no-cache docker-compose
    - docker-compose up -d app
    - sleep 30
  script:
    - docker run --rm -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-full-scan.py -t http://app:3000 -J zap-full.json
    - python3 scripts/check_critical_findings.py zap-full.json || exit 1
  allow_failure: false
```

### Passo 4: Criar Script de Validação

**Solução Esperada:**

**4.1. Script `scripts/check_critical_findings.py`:**
```python
#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def check_zap_results(zap_file='zap-full.json'):
    if not Path(zap_file).exists():
        return 0
    
    with open(zap_file) as f:
        data = json.load(f)
    
    alerts = data.get('site', [{}])[0].get('alerts', [])
    critical_count = sum(1 for alert in alerts if alert.get('risk', '').upper() == 'HIGH')
    
    if critical_count > 0:
        print(f"❌ Found {critical_count} Critical/High vulnerabilities!")
        sys.exit(1)
    else:
        print("✅ No Critical vulnerabilities found.")
        sys.exit(0)

if __name__ == '__main__':
    check_zap_results()
```

**Validação:**
- ✅ Script valida findings corretamente
- ✅ Pipeline falha quando Critical encontrado
- ✅ Pipeline passa quando não há Critical

### Passo 5: Testar Pipeline

**Solução Esperada:**

**5.1. Teste com Aplicação Segura:**
- Pipeline deve passar ✅
- Scan executa sem erros
- Nenhum Critical encontrado

**5.2. Teste com Aplicação Vulnerável:**
- Pipeline deve falhar ❌
- Scan encontra vulnerabilidades
- Merge bloqueado

**5.3. Teste com Correção:**
- Pipeline deve passar após correção ✅
- Vulnerabilidades corrigidas
- Merge permitido

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Configuração Técnica:**
- [ ] Pipeline CI/CD configurado (GitHub Actions / GitLab CI)
- [ ] OWASP ZAP configurado no pipeline
- [ ] Aplicação inicia antes do scan
- [ ] Scan executa corretamente

**Quality Gate:**
- [ ] Quality Gate configurado (bloqueia se Critical encontrado)
- [ ] Pipeline testado com aplicação segura (deve passar)
- [ ] Pipeline testado com aplicação vulnerável (deve falhar)

### ⭐ Importantes (Recomendados para Resposta Completa)

**Script de Validação:**
- [ ] Script de validação criado e funcionando
- [ ] Script valida findings corretamente
- [ ] Pipeline falha quando Critical encontrado

**Testes:**
- [ ] Pipeline testado com correção (deve passar após correção)
- [ ] Notificações configuradas (opcional)

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Otimização:**
- [ ] Scan otimizado para performance
- [ ] Estratégia de scan passivo + ativo
- [ ] Quality Gate gradual documentado

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Integração CI/CD**: Aluno consegue integrar DAST no pipeline?
2. **Quality Gate**: Aluno entende como bloquear deploy quando vulnerável?
3. **Automação**: Aluno automatiza validação de findings?

### Erros Comuns

1. **Erro: Não Aguardar Aplicação Iniciar**
   - **Feedback**: "Boa configuração do pipeline! Lembre-se de aguardar aplicação iniciar antes do scan (ex: `sleep 30`). Sem isso, scan pode falhar porque aplicação não está pronta."

2. **Erro: Quality Gate Muito Rígido Inicialmente**
   - **Feedback**: "Ótimo trabalho configurando Quality Gate! Para adoção gradual, comece permissivo (só Critical) e aperte gradualmente. Isso evita bloquear time desde o início."

---

---

## 📝 CRÉDITOS

═══════════════════════════════════════════════════════
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Baseado em**: Aula 2.2: DAST: Dynamic Application Security Testing  
**Referência**: Módulo 2 - Testes de Segurança na Prática  
**Data de revisão**: Janeiro/2026
═══════════════════════════════════════════════════════
