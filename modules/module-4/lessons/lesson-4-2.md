---
layout: lesson
title: "Aula 4.2: Pipeline de Segurança"
slug: pipeline-seguranca
module: module-4
lesson_id: lesson-4-2
duration: "120 minutos"
level: "Avançado"
prerequisites: ["lesson-4-1"]
exercises: []
image: "assets/images/podcasts/4.2-Pipeline_Seguranca.png"
permalink: /modules/seguranca-cicd-devsecops/lessons/pipeline-seguranca/
---

# Aula 4.2: Pipeline de Segurança

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Construir um pipeline CI/CD completo com segurança integrada
- Configurar ferramentas SAST, DAST e SCA em workflows
- Implementar quality gates de segurança
- Criar dashboards de segurança para monitoramento
- Integrar testes de segurança automatizados no pipeline
- Implementar secret scanning e IaC scanning
- Otimizar performance de pipelines de segurança

## 📚 Arquitetura de Pipeline Seguro

### Visão Geral de um Pipeline DevSecOps

```
┌─────────────────────────────────────────────────────────┐
│  PIPELINE DEVSECOPS COMPLETO                            │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. PRE-COMMIT (Local)                                 │
│     └─ Hook: Secret scanning local                      │
│                                                          │
│  2. COMMIT (CI Trigger)                                 │
│     ├─ SAST (Static Analysis)                           │
│     ├─ SCA (Dependency Scanning)                        │
│     ├─ Secret Scanning                                  │
│     └─ IaC Scanning                                     │
│                                                          │
│  3. BUILD                                              │
│     ├─ Container Image Build                            │
│     └─ Container Scanning (Trivy)                       │
│                                                          │
│  4. TEST                                               │
│     ├─ Unit Tests                                       │
│     ├─ Integration Tests                                │
│     └─ Security Tests                                   │
│                                                          │
│  5. DEPLOY STAGING                                      │
│     ├─ Deploy para ambiente de staging                  │
│     └─ DAST (Dynamic Analysis)                          │
│                                                          │
│  6. QUALITY GATES                                      │
│     ├─ Security Gate: Bloqueia se vulnerabilidades     │
│     │   críticas/altas encontradas                      │
│     └─ Performance Gate: Valida métricas                │
│                                                          │
│  7. DEPLOY PRODUCTION                                   │
│     └─ Deploy para produção (se gates passaram)        │
│                                                          │
│  8. POST-DEPLOY                                         │
│     ├─ Runtime Protection                               │
│     └─ Continuous Monitoring                            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Componentes Principais

#### 1. SAST (Static Application Security Testing)

**O que é**: Análise estática do código-fonte para encontrar vulnerabilidades sem executar o código.

**Quando executar**: A cada commit (fast feedback)

**Ferramentas populares**:
- **Semgrep**: Rápido, customizável, open-source
- **SonarQube**: Completo, enterprise, com quality gates
- **Checkmarx**: Enterprise, análise profunda
- **CodeQL**: GitHub, análise baseada em queries

#### 2. SCA (Software Composition Analysis)

**O que é**: Escaneamento de dependências para encontrar vulnerabilidades conhecidas (CVEs).

**Quando executar**: A cada commit (identifica dependências vulneráveis)

**Ferramentas populares**:
- **Snyk**: Moderno, integrado, cria PRs automáticos
- **Dependabot**: Integrado ao GitHub, alertas automáticos
- **WhiteSource**: Enterprise, suporte amplo
- **OWASP Dependency-Check**: Open-source, local

#### 3. Secret Scanning

**O que é**: Detecção de secrets (API keys, passwords, tokens) commitados no código.

**Quando executar**: A cada commit (crítico - secrets expostos)

**Ferramentas populares**:
- **GitGuardian**: Cloud-based, excelente detecção
- **TruffleHog**: Open-source, scanner local
- **GitLeaks**: CLI tool, integração fácil
- **detect-secrets**: Framework customizável

#### 4. IaC Scanning (Infrastructure as Code)

**O que é**: Análise de arquivos de infraestrutura (Terraform, CloudFormation) para encontrar configurações inseguras.

**Quando executar**: Antes de merge (evita infraestrutura insegura)

**Ferramentas populares**:
- **Checkov**: Políticas extensas, múltiplos formatos
- **TFSec**: Especializado em Terraform
- **Terrascan**: Policy as code, multi-cloud
- **Kics**: Fast, open-source

#### 5. Container Scanning

**O que é**: Análise de imagens Docker/container para encontrar vulnerabilidades em dependências do sistema operacional.

**Quando executar**: Após build de imagem (antes de push)

**Ferramentas populares**:
- **Trivy**: Rápido, fácil de usar, open-source
- **Clair**: Análise profunda, open-source
- **Aqua Security**: Enterprise, runtime protection
- **Snyk Container**: Integrado, suporte amplo

#### 6. DAST (Dynamic Application Security Testing)

**O que é**: Testes de segurança na aplicação em execução (runtime).

**Quando executar**: Após deploy em staging (antes de produção)

**Ferramentas populares**:
- **OWASP ZAP**: Open-source, extensível
- **Burp Suite**: Profissional, análise profunda
- **StackHawk**: Moderno, CI/CD friendly
- **Nuclei**: Fast, template-based

---

## 🛠️ Implementação Prática: GitHub Actions

### Pipeline Completo com GitHub Actions

{% raw %}
```yaml
name: DevSecOps Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  NODE_VERSION: '18'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # ============================================================
  # STAGE 1: Static Security Analysis
  # ============================================================
  
  sast:
    name: SAST - Static Application Security Testing
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
          generateSarif: "1"
      
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
  
  sca:
    name: SCA - Software Composition Analysis
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      - name: Upload Snyk results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: snyk.sarif
  
  secret-scan:
    name: Secret Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for secret scanning
      
      - name: Run GitGuardian scan
        uses: GitGuardian/ggshield-action@master
        env:
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
        with:
          fail_on_secrets: true
          mode: scan-path
          paths: |
            .
            !node_modules
            !.git
  
  iac-scan:
    name: IaC Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: infrastructure/
          framework: terraform
          output_format: sarif
          output_file_path: checkov.sarif
      
      - name: Upload IaC scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov.sarif
  
  # ============================================================
  # STAGE 2: Build and Container Security
  # ============================================================
  
  build:
    name: Build Application
    needs: [sast, sca, secret-scan, iac-scan]
    runs-on: ubuntu-latest
    outputs:
      image-tag: ${{ steps.meta.outputs.tags }}
      image-digest: ${{ steps.build.outputs.digest }}
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=sha,prefix={{branch}}-
      
      - name: Build and push Docker image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
  
  container-scan:
    name: Container Security Scanning
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ needs.build.outputs.image-tag }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
  
  # ============================================================
  # STAGE 3: Testing (including Security Tests)
  # ============================================================
  
  test:
    name: Run Tests
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run unit tests
        run: npm run test:unit
      
      - name: Run integration tests
        run: npm run test:integration
      
      - name: Run security tests
        run: npm run test:security
        env:
          TEST_ENV: staging
  
  # ============================================================
  # STAGE 4: Deploy to Staging
  # ============================================================
  
  deploy-staging:
    name: Deploy to Staging
    needs: [test, container-scan]
    runs-on: ubuntu-latest
    environment:
      name: staging
      url: https://staging.myapp.com
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/myapp \
            myapp=${{ needs.build.outputs.image-tag }} \
            --namespace=staging
      
      - name: Wait for deployment
        run: kubectl rollout status deployment/myapp -n staging
  
  # ============================================================
  # STAGE 5: DAST (Dynamic Analysis)
  # ============================================================
  
  dast:
    name: DAST - Dynamic Application Security Testing
    needs: deploy-staging
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Run OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: 'https://staging.myapp.com'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
      
      - name: Run OWASP ZAP Full Scan
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: 'https://staging.myapp.com'
          rules_file_name: '.zap/rules.tsv'
      
      - name: Upload ZAP results
        uses: actions/upload-artifact@v4
        with:
          name: zap-results
          path: report_html.html
  
  # ============================================================
  # STAGE 6: Quality Gates
  # ============================================================
  
  security-gate:
    name: Security Quality Gate
    needs: [sast, sca, container-scan, dast]
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Aggregate security results
        run: |
          # Verificar se há vulnerabilidades críticas
          CRITICAL_VULNS=$(jq '.vulnerabilities[] | select(.severity == "CRITICAL")' security-report.json | wc -l)
          
          if [ "$CRITICAL_VULNS" -gt 0 ]; then
            echo "❌ Security Gate Failed: $CRITICAL_VULNS critical vulnerabilities found"
            exit 1
          fi
          
          # Verificar se há vulnerabilidades altas
          HIGH_VULNS=$(jq '.vulnerabilities[] | select(.severity == "HIGH")' security-report.json | wc -l)
          
          if [ "$HIGH_VULNS" -gt 5 ]; then
            echo "⚠️ Security Gate Warning: $HIGH_VULNS high vulnerabilities found"
            # Não falha, mas alerta
          fi
          
          echo "✅ Security Gate Passed"
      
      - name: Generate security report
        run: |
          echo "## Security Scan Results" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Tool | Status | Vulnerabilities |" >> $GITHUB_STEP_SUMMARY
          echo "|------|--------|-----------------|" >> $GITHUB_STEP_SUMMARY
          echo "| SAST | ✅ Passed | 0 Critical |" >> $GITHUB_STEP_SUMMARY
          echo "| SCA | ✅ Passed | 2 High |" >> $GITHUB_STEP_SUMMARY
          echo "| Container Scan | ✅ Passed | 0 Critical |" >> $GITHUB_STEP_SUMMARY
          echo "| DAST | ✅ Passed | 0 Critical |" >> $GITHUB_STEP_SUMMARY
  
  # ============================================================
  # STAGE 7: Deploy to Production (if gates pass)
  # ============================================================
  
  deploy-production:
    name: Deploy to Production
    needs: [security-gate]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://myapp.com
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/myapp \
            myapp=${{ needs.build.outputs.image-tag }} \
            --namespace=production
      
      - name: Wait for deployment
        run: kubectl rollout status deployment/myapp -n production
      
      - name: Run smoke tests
        run: npm run test:smoke
        env:
          TEST_ENV: production
```
{% endraw %}

---

## 🔒 Quality Gates de Segurança

### O que são Quality Gates?

**Quality Gates** são verificações automáticas que **bloqueiam** o deploy se critérios de segurança não forem atendidos.

### Tipos de Quality Gates

#### 1. Gate por Severidade

```yaml
security-gate:
  rules:
    critical: 0      # Bloqueia se houver vulnerabilidades críticas
    high: 5          # Bloqueia se houver mais de 5 vulnerabilidades altas
    medium: 20       # Alerta se houver mais de 20 vulnerabilidades médias
```

#### 2. Gate por Score

```yaml
security-score-gate:
  minimum-score: 8.0  # Bloqueia se security score < 8.0
```

#### 3. Gate por Compliance

```yaml
compliance-gate:
  pci-dss: required   # Bloqueia se não atender PCI-DSS
  lgpd: required      # Bloqueia se não atender LGPD
```

### Implementação Prática

```yaml
security-gate:
  name: Security Quality Gate
  runs-on: ubuntu-latest
  steps:
    - name: Collect security results
      run: |
        # Agregar resultados de todas as ferramentas
        python scripts/aggregate-security-results.py \
          --sast results/semgrep.json \
          --sca results/snyk.json \
          --container results/trivy.json \
          --dast results/zap.json \
          --output aggregated.json
    
    - name: Evaluate quality gate
      run: |
        CRITICAL=$(jq '.summary.critical' aggregated.json)
        HIGH=$(jq '.summary.high' aggregated.json)
        
        if [ "$CRITICAL" -gt 0 ]; then
          echo "❌ Gate Failed: $CRITICAL critical vulnerabilities"
          exit 1
        fi
        
        if [ "$HIGH" -gt 5 ]; then
          echo "❌ Gate Failed: $HIGH high vulnerabilities (max: 5)"
          exit 1
        fi
        
        echo "✅ Security Gate Passed"
```

---

## 📊 Dashboards de Segurança

### Como Criar Dashboard

**Opções**:

1. **GitHub Security Tab** (nativo)
   - Integração automática com SARIF
   - Visualização de vulnerabilidades
   - Tracking de correções

2. **Grafana + Prometheus**
   - Métricas customizadas
   - Dashboards visuais
   - Alertas

3. **Elastic Stack (ELK)**
   - Logs de segurança
   - Análise de tendências
   - Search avançado

4. **Snyk Dashboard** (se usar Snyk)
   - Visualização integrada
   - Trends e métricas
   - Reports

### Exemplo: Dashboard Simples com GitHub Actions

```yaml
generate-dashboard:
  name: Generate Security Dashboard
  runs-on: ubuntu-latest
  steps:
    - name: Generate dashboard markdown
      run: |
        cat > security-dashboard.md << EOF
        # Security Dashboard - $(date +%Y-%m-%d)
        
        ## Vulnerability Summary
        
        | Severity | Count | Trend |
        |----------|-------|-------|
        | Critical | $CRITICAL | $CRITICAL_TREND |
        | High | $HIGH | $HIGH_TREND |
        | Medium | $MEDIUM | $MEDIUM_TREND |
        | Low | $LOW | $LOW_TREND |
        
        ## Tools Status
        
        | Tool | Status | Last Scan |
        |------|--------|-----------|
        | SAST (Semgrep) | ✅ | $(date) |
        | SCA (Snyk) | ✅ | $(date) |
        | Container (Trivy) | ✅ | $(date) |
        | DAST (ZAP) | ✅ | $(date) |
        
        ## Trends
        
        \`\`\`
        Vulnerabilities (Last 30 days)
        Critical: ████░░░░░░░░ (4)
        High:     ████████░░░░ (8)
        Medium:   ████████████ (12)
        \`\`\`
        EOF
      
      - name: Upload dashboard
        uses: actions/upload-artifact@v4
        with:
          name: security-dashboard
          path: security-dashboard.md
```

---

## ⚡ Otimização de Performance

### Problema: Pipelines Lentos

**Impacto**:
- ⏱️ Desenvolvedores esperam muito tempo
- 💰 Custo computacional alto
- 😞 Frustração e perda de produtividade

### Estratégias de Otimização

#### 1. Execução Paralela

```yaml
# ✅ BOM: Execução paralela
jobs:
  sast:
    # Executa em paralelo
  sca:
    # Executa em paralelo
  secret-scan:
    # Executa em paralelo

# ❌ RUIM: Execução sequencial
jobs:
  sast:
    # ...
  sca:
    needs: sast  # Espera sast terminar
  secret-scan:
    needs: sca  # Espera sca terminar
```

#### 2. Cache de Dependências

{% raw %}
```yaml
- name: Cache npm dependencies
  uses: actions/cache@v4
  with:
    path: ~/.npm
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      ${{ runner.os }}-node-
```
{% endraw %}

#### 3. Executar apenas em Arquivos Alterados

```yaml
- name: Run SAST only on changed files
  run: |
    CHANGED_FILES=$(git diff --name-only HEAD~1 HEAD | grep -E '\.(js|ts|py)$' || true)
    
    if [ -n "$CHANGED_FILES" ]; then
      semgrep --config=auto $CHANGED_FILES
    else
      echo "No code files changed, skipping SAST"
    fi
```

#### 4. Timeouts e Circuit Breakers

```yaml
- name: Run DAST with timeout
  timeout-minutes: 30  # Falha se demorar mais que 30 minutos
  run: |
    zap-baseline.py -t https://staging.myapp.com
```

---

## 💼 Exemplos Práticos CWI

### Caso 1: Pipeline Financeiro (PCI-DSS)

```yaml
pci-dss-pipeline:
  stages:
    - name: PCI-DSS Compliance Checks
      steps:
        - Run PCI-DSS validator
        - Check encryption at rest
        - Validate no PAN storage
        - Verify secure transmission
    
    - name: Security Scanning
      steps:
        - SAST (SonarQube)
        - SCA (Snyk)
        - Container Scan (Trivy)
    
    - name: DAST
      steps:
        - OWASP ZAP (PCI-DSS mode)
        - Penetration testing automation
    
    - name: PCI-DSS Gate
      rules:
        - pci-dss-compliance: required
        - critical-vulns: 0
        - high-vulns: 0  # Zero tolerância em financeiro
```

### Caso 2: Pipeline EdTech (LGPD)

```yaml
lgpd-pipeline:
  stages:
    - name: LGPD Compliance Checks
      steps:
        - Validate data minimization
        - Check consent management
        - Verify data retention policies
        - Validate encryption for minors' data
    
    - name: Security Scanning
      steps:
        - SAST (Semgrep)
        - SCA (Dependabot)
        - Secret Scanning (GitGuardian)
    
    - name: Privacy Tests
      steps:
        - Test data access controls
        - Validate data deletion
        - Check data portability
```

---

## 📝 Resumo da Aula

### Principais Conceitos

1. **Pipeline DevSecOps**: Integra segurança em cada etapa do CI/CD
2. **Ferramentas**: SAST, SCA, Secret Scanning, IaC Scanning, Container Scanning, DAST
3. **Quality Gates**: Bloqueiam deploy se critérios não atendidos
4. **Dashboards**: Visualização de métricas de segurança
5. **Otimização**: Execução paralela, cache, análise incremental

### Próximos Passos

Na próxima aula (4.3), você aprenderá sobre:
- Segurança de containers Docker
- Scanning de vulnerabilidades em imagens
- Segurança em Kubernetes (RBAC, policies)
- Runtime security

---

## 📚 Recursos Adicionais

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [Semgrep Rules](https://semgrep.dev/r)
- [Snyk Documentation](https://docs.snyk.io/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)

---

**Duração da Aula**: 120 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Aula 4.1 (DevSecOps: Cultura e Práticas), conhecimento básico de CI/CD
