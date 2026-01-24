---
exercise_id: lesson-2-4-exercise-1-github-actions-sast
title: "Exercício 2.4.1: GitHub Actions SAST"
lesson_id: lesson-2-4
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.4.1: GitHub Actions SAST no Pipeline

## 📋 Enunciado
Configure GitHub Actions para executar SonarQube ou Semgrep automaticamente em cada push/PR.

### Requisitos
1. Workflow YAML configurado
2. SAST executado em PRs
3. Falha se vulnerabilidades críticas
4. Comentário automático no PR com resultados

---

## ✅ Solução Completa

### Workflow GitHub Actions + Semgrep

```yaml
# .github/workflows/security-scan.yml
name: Security SAST Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  semgrep-scan:
    name: Semgrep Security Scan
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/javascript
          generateSarif: true
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
      
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
      
      - name: Check for critical vulnerabilities
        run: |
          CRITICAL=$(jq '[.runs[].results[] | select(.level=="error")] | length' semgrep.sarif)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ CRITICAL: $CRITICAL vulnerabilidades críticas encontradas"
            exit 1
          fi
      
      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const sarif = JSON.parse(fs.readFileSync('semgrep.sarif'));
            const results = sarif.runs[0].results;
            
            const critical = results.filter(r => r.level === 'error').length;
            const warning = results.filter(r => r.level === 'warning').length;
            
            const body = `## 🔒 Security Scan Results
            
            - ❌ **Critical**: ${critical}
            - ⚠️ **Warnings**: ${warning}
            
            ${critical > 0 ? '❌ **PR BLOCKED** - Corrija vulnerabilidades críticas' : '✅ Nenhuma vulnerabilidade crítica'}
            
            Veja detalhes na aba [Security](https://github.com/${{ github.repository }}/security/code-scanning)`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

### Alternativa: SonarQube Cloud

```yaml
# .github/workflows/sonarqube.yml
name: SonarQube Analysis

on:
  push:
    branches: [main]
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  sonarqube:
    name: SonarQube Scan
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.projectKey=my-project
            -Dsonar.qualitygate.wait=true
      
      - name: Check Quality Gate
        run: |
          STATUS=$(curl -s -u "${{ secrets.SONAR_TOKEN }}:" \
            "${{ secrets.SONAR_HOST_URL }}/api/qualitygate/project_status?projectKey=my-project" \
            | jq -r '.projectStatus.status')
          
          if [ "$STATUS" != "OK" ]; then
            echo "❌ Quality Gate falhou: $STATUS"
            exit 1
          fi
```

### Configuração de Secrets

```bash
# No GitHub: Settings > Secrets and variables > Actions

# Para Semgrep Cloud (opcional, mas recomendado)
SEMGREP_APP_TOKEN=<seu_token_semgrep>

# Para SonarQube
SONAR_TOKEN=<seu_token_sonar>
SONAR_HOST_URL=https://sonarcloud.io
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **CI/CD Security**: Integração de SAST no pipeline
2. **Shift-Left**: Detectar vulnerabilidades ANTES do merge
3. **Quality Gates**: Bloquear PR se falhar segurança
4. **SARIF**: Formato padrão para resultados de segurança

### Erros Comuns

**Erro 1: "Workflow não executou"**
- **Causa**: Arquivo YAML com erro de sintaxe ou path incorreto
- **Feedback**: "Valide YAML em yamllint.com. Arquivo deve estar em `.github/workflows/`. Teste localmente com `act` (GitHub Actions local runner) antes de commitar."

**Erro 2: "SAST sempre passa (não bloqueia PR)"**
- **Causa**: Não verifica resultados ou não faz `exit 1` em falha
- **Feedback**: "Seu workflow executa scan mas não VALIDA resultados. Adicione step que: 1) Parse resultados (jq/grep), 2) Conte vulnerabilidades críticas, 3) `exit 1` se > 0. Sem isso, PR passa mesmo com SQL Injection."

**Erro 3: "Secrets expostos no código"**
- **Causa**: Token hardcoded no YAML
- **Feedback**: "⚠️ CRÍTICO: Token no código é vulnerabilidade! Use GitHub Secrets: Settings > Secrets > New secret. No YAML use `${{ secrets.NOME_SECRET }}`. NUNCA commite tokens."

**Erro 4: "Scan demora 30 minutos (timeout)"**
- **Causa**: Scan de diretórios desnecessários (node_modules, vendor, build)
- **Feedback**: "Otimize scan: 1) Exclua `node_modules/`, `build/`, `dist/` (config do Semgrep), 2) Use cache de dependências, 3) Rode apenas em arquivos alterados (PR incremental). Scan deve levar < 5min."

**Erro 5: "Não comentou no PR"**
- **Causa**: Permissões insuficientes ou não configurou github-script
- **Feedback**: "Adicione `permissions: pull-requests: write` no job. Use action `actions/github-script@v7` para comentar. Veja exemplo na solução completa."

**Erro 6: "Quality Gate não configurado"**
- **Causa**: SonarQube sem regras de bloqueio
- **Feedback**: "No SonarQube: Quality Gates > Create > Conditions: 'Security Rating is worse than A' = FAIL. Sem Quality Gate, scan é informativo (não bloqueia nada)."

### Feedback Construtivo

**Para implementação profissional:**
> "Excelente automação! Workflow executando Semgrep em PRs, bloqueando merges com vulnerabilidades críticas, e comentando resultados. Isso é Shift-Left na prática. Próximo nível: 1) Incremental scan (apenas diff do PR), 2) Custom rules para seu contexto, 3) Métricas de tendência (vulnerabilidades ao longo do tempo)."

**Para implementação básica:**
> "Bom início! SAST rodando no pipeline. Para melhorar: 1) Adicione bloqueio de PR (exit 1 se crítico), 2) Comente resultados no PR (developer experience), 3) Configure Quality Gate no SonarQube, 4) Use cache para acelerar (< 5min). Funcionalidade está correta, agora usabilidade."

**Para dificuldades:**
> "GitHub Actions pode ser confuso na primeira vez. Comece simples: 1) Use template pronto (Semgrep Action ou SonarQube Action), 2) Teste workflow manualmente (Actions tab), 3) Adicione apenas 1 step de cada vez (debug incremental). Se travar, cole erro completo e analisamos juntos."

### Contexto Pedagógico

**Por que é fundamental:**
- **Shift-Left Security**: Detectar vulnerabilidades no código ANTES de produção
- **Developer Experience**: Feedback imediato (não espera semanas por security review)
- **Compliance**: Muitos frameworks (SOC2, ISO27001) exigem SAST automatizado
- **Cultura**: Normaliza segurança como parte do desenvolvimento

**Conexão com carreira:**
- DevSecOps Engineers configuram esses pipelines
- QA Automation deve saber integrar SAST em CI/CD
- Habilidade valorizada em empresas maduras (GitLab, GitHub, fintech)

**Habilidades desenvolvidas:**
- GitHub Actions workflow development (YAML, secrets, artifacts)
- Integração de ferramentas SAST (Semgrep, SonarQube)
- Quality Gates e enforcement automatizado
- Debugging de pipelines CI/CD
- Otimização de performance (cache, incremental scans)

**Estatísticas da indústria:**
- 78% das empresas usam SAST automatizado no CI/CD (DevOps Research, 2025)
- Integração de SAST reduz vulnerabilidades em produção em 65% (Forrester, 2024)
- Times com SAST no CI têm 50% menos débito técnico de segurança (DORA, 2025)

**Comparação de ferramentas CI/CD:**

| Plataforma | Prós | Contras | SAST Support |
|------------|------|---------|--------------|
| **GitHub Actions** | Nativo GitHub, marketplace rico, grátis (open-source) | Vendor lock-in | ✅ Excelente (Semgrep, SonarQube, CodeQL) |
| **GitLab CI** | CI/CD integrado, auto-devops, self-hosted | Curva aprendizado | ✅ Excelente (SAST nativo, templates) |
| **Jenkins** | Flexível, plugins infinitos, self-hosted | Complexo, manutenção | ✅ Bom (plugins Semgrep, SonarQube) |
| **CircleCI** | Performance, orbs reusáveis | Custo (minutos) | ✅ Bom (orbs de security) |
| **Azure Pipelines** | Integração MS, Windows support | Complexo | ✅ Bom (extensions) |

**Recomendação:** GitHub Actions (maioria dos projetos) ou GitLab CI (self-hosted)

**Práticas avançadas:**

**1. Matrix Builds (testar múltiplas versões):**
```yaml
strategy:
  matrix:
    node: [16, 18, 20]
    os: [ubuntu-latest, windows-latest]
    
# Roda SAST em 6 combinações (3 nodes x 2 OS)
```

**2. Conditional Execution (otimizar custo):**
```yaml
# Executar SAST apenas se arquivos de código mudaram
- name: Check changed files
  id: changed
  run: |
    if git diff --name-only origin/main | grep -E '\.(js|ts|py|java)$'; then
      echo "code_changed=true" >> $GITHUB_OUTPUT
    fi

- name: Run SAST
  if: steps.changed.outputs.code_changed == 'true'
  run: semgrep scan ...
```

**3. Custom Rulesets (específico do projeto):**
```yaml
# .github/workflows/sast.yml
- name: Run Semgrep with custom rules
  run: |
    semgrep scan \
      --config=p/security-audit \
      --config=.semgrep/custom-rules/ \  # Regras específicas do projeto
      --json --output=semgrep.json
```

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
