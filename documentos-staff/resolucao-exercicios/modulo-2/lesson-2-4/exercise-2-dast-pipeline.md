---
exercise_id: lesson-2-4-exercise-2-dast-pipeline
title: "Exercício 2.4.2: DAST no Pipeline"
lesson_id: lesson-2-4
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.4.2: DAST no Pipeline CI/CD

## 📋 Enunciado
Integre OWASP ZAP ao pipeline para testar aplicação em staging após deploy.

### Requisitos
1. Deploy staging automatizado
2. ZAP Baseline Scan ou Full Scan
3. Falha se vulnerabilidades críticas
4. Relatório HTML armazenado como artefato

---

## ✅ Solução Completa

### GitHub Actions + OWASP ZAP

```yaml
# .github/workflows/deploy-and-test.yml
name: Deploy & DAST Scan

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Deploy to staging
        run: |
          # Exemplo: deploy para Vercel/Netlify/Heroku
          npm run deploy:staging
        env:
          DEPLOY_TOKEN: ${{ secrets.STAGING_DEPLOY_TOKEN }}
      
      - name: Wait for deployment (health check)
        run: |
          for i in {1..30}; do
            if curl -f https://staging.exemplo.com/health; then
              echo "✅ Staging online"
              exit 0
            fi
            echo "Aguardando staging... ($i/30)"
            sleep 10
          done
          echo "❌ Staging não respondeu"
          exit 1

  dast-scan:
    name: OWASP ZAP DAST Scan
    runs-on: ubuntu-latest
    needs: deploy-staging
    
    steps:
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: 'https://staging.exemplo.com'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a -j -l PASS'
      
      - name: Upload ZAP Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: |
            report_html.html
            report_json.json
      
      - name: Check for critical alerts
        run: |
          CRITICAL=$(jq '[.site[].alerts[] | select(.riskcode=="3")] | length' report_json.json)
          HIGH=$(jq '[.site[].alerts[] | select(.riskcode=="2")] | length' report_json.json)
          
          echo "🔴 Critical: $CRITICAL"
          echo "🟠 High: $HIGH"
          
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ FALHA: $CRITICAL vulnerabilidades críticas"
            exit 1
          fi
```

### Configuração ZAP Rules (opcional)

```tsv
# .zap/rules.tsv
# Ignora false positives conhecidos
10202	IGNORE	(X-Frame-Options - Header Not Set)	https://staging.exemplo.com/api/*
10038	IGNORE	(Content Security Policy - não aplicável a API)	https://staging.exemplo.com/api/*
```

### Alternativa: ZAP Full Scan (mais agressivo)

```yaml
- name: ZAP Full Scan
  uses: zaproxy/action-full-scan@v0.10.0
  with:
    target: 'https://staging.exemplo.com'
    allow_issue_writing: false
    fail_action: true
    cmd_options: >
      -T 60
      -z "-config spider.maxDepth=5"
      -z "-config spider.maxChildren=10"
```

### GitLab CI Equivalent

```yaml
# .gitlab-ci.yml
stages:
  - deploy
  - test

deploy_staging:
  stage: deploy
  script:
    - npm run deploy:staging
    - curl -f https://staging.exemplo.com/health
  only:
    - main

dast:
  stage: test
  image: owasp/zap2docker-stable
  script:
    - mkdir -p /zap/wrk
    - zap-baseline.py -t https://staging.exemplo.com -r report.html -J report.json -l PASS
    - |
      CRITICAL=$(jq '[.site[].alerts[] | select(.riskcode=="3")] | length' report.json)
      if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
  artifacts:
    paths:
      - report.html
      - report.json
    expire_in: 30 days
  only:
    - main
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **DAST Timing**: Executar APÓS deploy (app rodando)
2. **Staging Isolation**: Testar em staging (não produção)
3. **Health Check**: Validar app online antes de scan
4. **Threshold**: Definir critério de falha (critical > 0)

### Erros Comuns

**Erro 1: "ZAP executou antes do deploy (scan falhou)"**
- **Causa**: Jobs paralelos, ZAP não esperou deploy
- **Feedback**: "Use `needs: deploy-staging` no job DAST. Isso cria dependência: ZAP SÓ executa APÓS deploy completar. Também adicione health check para garantir que app está respondendo antes de scan."

**Erro 2: "Scan sempre falha (muitos false positives)"**
- **Causa**: ZAP baseline muito estrito para staging (CSP, HTTPS, etc)
- **Feedback**: "Configure `.zap/rules.tsv` para ignorar false positives conhecidos (ex: CSP em API, X-Frame-Options em localhost). Ou use `cmd_options: -l PASS` (menos rigoroso). Focus: vulnerabilidades reais (SQLi, XSS), não headers faltando."

**Erro 3: "Scan demora 2 horas (timeout CI)"**
- **Causa**: ZAP Full Scan em app grande com spider infinito
- **Feedback**: "Para CI/CD, use ZAP Baseline (não Full Scan). Baseline: passivo, 2-5min. Full Scan: ativo, 30min-2h. Se precisar Full, rode em job noturno/semanal (não em cada push). Ou limite spider: `-z '-config spider.maxDepth=3'`."

**Erro 4: "Não salvou relatório (perdeu evidências)"**
- **Causa**: Não configurou artifacts no CI
- **Feedback**: "Adicione `uses: actions/upload-artifact` (GitHub) ou `artifacts: paths:` (GitLab). Relatórios são críticos para: 1) Dev corrigir (ver payload exato), 2) Auditoria (compliance), 3) Comparar ao longo do tempo. Sem relatório = scan inútil."

**Erro 5: "Testou produção (não staging)"**
- **Causa**: URL hardcoded errada ou variável de ambiente incorreta
- **Feedback**: "⚠️ NUNCA rode DAST em produção! ZAP é agressivo (SQLi payloads, brute force). Use staging isolado. Valide URL antes: `echo $TARGET_URL` no CI. Se não tem staging, crie (Docker Compose local é suficiente)."

**Erro 6: "Pipeline sempre passa (mesmo com vulnerabilidades)"**
- **Causa**: Não verifica resultados ou não faz exit 1
- **Feedback**: "ZAP gera relatório mas não FALHA automaticamente. Adicione step que parse JSON: `jq '[.site[].alerts[] | select(.riskcode==\"3\")] | length'`. Se > 0: `exit 1`. Sem isso, seu pipeline é teatro de segurança."

### Feedback Construtivo

**Para implementação robusta:**
> "Excelente integração DAST! Deploy automático → health check → ZAP scan → validação de threshold → artifacts. Isso é pipeline de segurança maduro. Próximo nível: 1) ZAP autenticado (testa área logada), 2) Scan incremental (apenas páginas alteradas), 3) Baseline de vulnerabilidades aceitas (track remediation progress)."

**Para implementação funcional:**
> "Boa integração! ZAP rodando após deploy. Para profissionalizar: 1) Adicione health check (evita scan em app offline), 2) Configure rules.tsv (ignore false positives recorrentes), 3) Armazene relatórios como artifacts, 4) Defina threshold claro (critical > 0 = falha). Funciona, agora confiabilidade."

**Para dificuldades:**
> "DAST em CI é complexo (timing, false positives, performance). Comece incremental: 1) Rode ZAP Baseline localmente (entenda output), 2) Adicione ao CI (sem fail primeiro), 3) Identifique false positives (crie rules.tsv), 4) Ative bloqueio (exit 1). Processo iterativo, não overnight."

### Contexto Pedagógico

**Por que é fundamental:**
- **Complemento de SAST**: SAST = código estático, DAST = runtime (autenticação, configuração, integrações)
- **Staging Testing**: Único momento seguro para DAST agressivo
- **CI/CD Security**: Automatizar segurança em cada release
- **Compliance**: SOC2, PCI-DSS exigem testes DAST recorrentes

**Habilidades do mundo real:**
- DevSecOps configura DAST em pipelines
- SRE/QA Automation gerencia staging e testes automatizados
- Security Engineers interpretam resultados e refinam rules

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
