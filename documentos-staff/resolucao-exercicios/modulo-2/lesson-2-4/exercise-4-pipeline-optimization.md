---
exercise_id: lesson-2-4-exercise-4-pipeline-optimization
title: "Exercício 2.4.4: Otimização de Pipeline de Segurança"
lesson_id: lesson-2-4
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.4.4: Otimização de Pipeline de Segurança

## 📋 Enunciado
Pipeline de segurança demora 45 minutos (inviável). Otimize para < 10 minutos mantendo cobertura.

### Situação Atual
- SAST: 15min (scan completo do repo)
- DAST: 25min (ZAP Full Scan)
- SCA: 5min (dependências)
- Total: 45min ❌

### Meta
- Total: < 10min ✅
- Manter cobertura de segurança

---

## ✅ Estratégias de Otimização

### 1. SAST Incremental (15min → 2min)

**Problema**: Scanneia TODO o código em cada PR (mesmo linhas antigas)

**Solução**: Scan apenas código alterado (diff)

```yaml
# Semgrep Incremental
- name: Get changed files
  id: changed-files
  uses: tj-actions/changed-files@v44
  with:
    files: |
      **/*.js
      **/*.ts
      **/*.py

- name: Semgrep (incremental)
  if: steps.changed-files.outputs.any_changed == 'true'
  run: |
    semgrep scan \
      --config=auto \
      --paths-from-stdin \
      <<< "${{ steps.changed-files.outputs.all_changed_files }}"
```

**Resultado**: 15min → 2min (87% redução)

---

### 2. DAST Paralelo + Targeted (25min → 5min)

**Problema**: ZAP Full Scan de toda aplicação (spider infinito)

**Solução**: Scan apenas endpoints alterados + autenticação pré-configurada

```yaml
# ZAP API Scan (não Spider)
- name: Generate OpenAPI spec from changes
  run: |
    # Se mudou endpoints, gera OpenAPI spec apenas dos novos
    npm run openapi:generate -- --changed-only

- name: ZAP API Scan (targeted)
  uses: zaproxy/action-api-scan@v0.7.0
  with:
    target: .openapi.yml  # Apenas endpoints no spec
    cmd_options: '-a -j'  # Autenticado, JSON context

# Scan paralelo: Frontend + Backend
frontend-dast:
  steps:
    - name: ZAP Baseline (frontend)
      run: zap-baseline.py -t https://staging.app.com -r report-fe.html

backend-dast:
  steps:
    - name: ZAP API Scan (backend)
      run: zap-api-scan.py -t api.openapi.yml -r report-be.json
```

**Resultado**: 25min → 5min (80% redução)

---

### 3. Cache de Dependências (SCA: 5min → 1min)

**Problema**: npm install/pip install em cada run

**Solução**: Cache de dependências

```yaml
- name: Setup Node with cache
  uses: actions/setup-node@v4
  with:
    node-version: '18'
    cache: 'npm'  # ⬅️ Cache automático

- name: Cache Semgrep rules
  uses: actions/cache@v4
  with:
    path: ~/.semgrep/cache
    key: semgrep-${{ hashFiles('.semgrep/**') }}

- name: Cache SonarQube analysis
  uses: actions/cache@v4
  with:
    path: .scannerwork
    key: sonar-${{ github.sha }}
```

**Resultado**: 5min → 1min (80% redução)

---

### 4. Jobs Paralelos (Não Sequenciais)

**Problema**: SAST → SCA → DAST (sequencial)

**Solução**: Paralelizar jobs independentes

```yaml
jobs:
  sast:
    runs-on: ubuntu-latest
    # Executa paralelamente
  
  sca:
    runs-on: ubuntu-latest
    # Executa paralelamente
  
  dast:
    runs-on: ubuntu-latest
    needs: [deploy]  # Só depende do deploy
    # Executa paralelamente com SAST/SCA
```

**Resultado**: 15min → 6min (jobs paralelos)

---

### 5. Scan Diferenciado por Branch

**Problema**: Mesma profundidade de scan em feature branch e main

**Solução**: Scan leve em feature, completo em main/release

```yaml
on:
  pull_request:
    # Feature branch: FAST (baseline)
  
  push:
    branches: [main]
    # Main: FULL (completo)

jobs:
  security-scan:
    steps:
      - name: Semgrep
        run: |
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            semgrep scan --config=p/security-audit  # Rápido
          else
            semgrep scan --config=auto  # Completo
          fi
```

---

### 6. Matriz de Otimização Final

```yaml
# Pipeline Otimizado: < 10min
name: Security Pipeline (Optimized)

on: [push, pull_request]

jobs:
  # 1. SAST Incremental (2min)
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Get changed files
        id: files
        uses: tj-actions/changed-files@v44
      
      - name: Semgrep (incremental)
        if: steps.files.outputs.any_changed == 'true'
        run: |
          semgrep scan \
            --config=p/security-audit \
            --json \
            --paths-from-stdin \
            <<< "${{ steps.files.outputs.all_changed_files }}"
  
  # 2. SCA com cache (1min)
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          cache: 'npm'
      
      - run: npm ci  # Usa cache
      - run: npm audit --json > audit.json
      - run: |
          CRITICAL=$(jq '.metadata.vulnerabilities.critical' audit.json)
          if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
  
  # 3. Deploy (2min)
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: npm run deploy:staging
  
  # 4. DAST Targeted (5min) - paralelo com SAST/SCA
  dast:
    runs-on: ubuntu-latest
    needs: [deploy]
    steps:
      - name: ZAP API Scan
        uses: zaproxy/action-api-scan@v0.7.0
        with:
          target: api.openapi.yml
          cmd_options: '-T 5'  # Timeout 5min

# Total: max(2min SAST, 1min SCA) + 2min deploy + 5min DAST = 9min ✅
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **Incremental Scanning**: Scan apenas código alterado
2. **Paralelização**: Jobs independentes em paralelo
3. **Cache**: Reusar downloads/compilações
4. **Targeted Testing**: Testar apenas áreas alteradas

### Erros Comuns

**Erro 1: "Otimizou mas perdeu cobertura"**
- **Problema**: Scan incremental ignora vulnerabilidades antigas
- **Feedback**: "Otimização ≠ reduzir cobertura. Use: 1) Incremental em feature branches (rápido), 2) Full scan em main/release (completo), 3) Scan noturno full (segurança). Velocidade em DEV, completude em PROD."

**Erro 2: "Jobs paralelos mas com dependências"**
- **Problema**: DAST rodando antes do deploy (corrida de condições)
- **Feedback**: "Mapeie dependências reais: DAST needs [deploy], SCA needs [], SAST needs []. Paralelizar jobs com dependências = falhas intermitentes. Use `needs:` corretamente."

**Erro 3: "Cache quebrado (sempre miss)"**
- **Problema**: Cache key incorreto ou path errado
- **Feedback**: "Valide cache: 1) Key deve mudar quando dependências mudam (`hashFiles('package-lock.json')`), 2) Path deve ser exato (`~/.npm`, não `~/npm`), 3) Logs do CI mostram 'Cache hit' ou 'Cache miss'. Debug antes de assumir que funciona."

**Erro 4: "Scan incremental ignora arquivos críticos"**
- **Problema**: Alterou `auth.js` mas incremental não scaneou (glob incorreto)
- **Feedback**: "Configure globs corretamente: `**/*.{js,ts,jsx,tsx}` (não `*.js`). Valide: faça PR mudando 1 arquivo crítico, veja se scan detectou. Incremental falho = falsa sensação de segurança."

### Feedback Construtivo

**Para otimização profissional:**
> "Excelente otimização! 45min → 9min mantendo cobertura. Estratégia sólida: incremental + paralelo + cache + targeted. Próximo nível: 1) Métricas de pipeline (track tempo ao longo do tempo), 2) Self-hosted runners (mais rápidos que GitHub-hosted), 3) Pré-commit hooks (detecta antes de push)."

**Para otimização parcial:**
> "Boa redução de tempo! Para chegar < 10min: 1) Paralelizar SAST/SCA (não sequencial), 2) Adicionar cache de dependências, 3) DAST targeted (não full scan). Otimizou partes, agora otimize sistema completo."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
