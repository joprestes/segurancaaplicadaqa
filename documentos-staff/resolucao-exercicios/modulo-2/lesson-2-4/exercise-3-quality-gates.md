---
exercise_id: lesson-2-4-exercise-3-quality-gates
title: "Exercício 2.4.3: Quality Gates de Segurança"
lesson_id: lesson-2-4
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.4.3: Quality Gates de Segurança

## 📋 Enunciado
Configure Quality Gates no SonarQube/Semgrep para bloquear PRs que não atendem critérios de segurança.

### Requisitos
1. Quality Gate com métricas de segurança
2. Threshold definido (ex: Security Rating ≥ A)
3. Bloqueio automático de PR
4. Aprovação manual para Medium (quando aplicável)
5. Notificações automáticas configuradas
6. Documentar critérios

---

## ✅ Solução Completa

### SonarQube Quality Gate

**1. Criar Quality Gate (Web UI)**

```
SonarQube > Quality Gates > Create

Nome: "Security Gate - Produção"
Descrição: "Quality Gate com foco em segurança para releases de produção"

Condições (Conditions):

┌─────────────────────────────────────┬──────────┬──────────┐
│ Métrica                             │ Operator │ Value    │
├─────────────────────────────────────┼──────────┼──────────┤
│ Security Rating                     │ is worse │ A        │
│ Security Hotspots Reviewed          │ is less  │ 100%     │
│ Vulnerabilities                     │ is greater│ 0       │
│ Coverage on New Code                │ is less  │ 80%      │
│ Duplicated Lines on New Code (%)    │ is greater│ 3%      │
└─────────────────────────────────────┴──────────┴──────────┘

Nota: "is worse than A" = bloqueia se B, C, D, E
```

**2. Associar ao Projeto**

```
SonarQube > Project > Project Settings > Quality Gate
Selecionar: "Security Gate - Produção"
```

**3. Configurar GitHub Integration**

```yaml
# sonar-project.properties (na raiz do repo)
sonar.projectKey=my-project
sonar.organization=my-org
sonar.qualitygate.wait=true  # ⬅️ CRÍTICO: Aguarda Quality Gate
sonar.sources=src
sonar.tests=tests
sonar.exclusions=**/node_modules/**,**/*.spec.js
```

**4. Workflow GitHub Actions**

```yaml
# .github/workflows/sonarqube.yml
name: SonarQube Quality Gate

on:
  pull_request:
    branches: [main]

jobs:
  sonarqube:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Histórico completo para análise
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: https://sonarcloud.io
      
      - name: SonarQube Quality Gate Check
        uses: sonarsource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        with:
          scanMetadataReportFile: .scannerwork/report-task.txt
      
      # Step adicional: Parse resultado
      - name: Comment Quality Gate Result
        if: always()
        run: |
          STATUS=$(cat .scannerwork/report-task.txt | grep ceTaskUrl | cut -d'=' -f2)
          echo "Quality Gate: $STATUS"
```

### Semgrep Quality Gate (Policy)

```yaml
# .semgrep/policy.yml
rules:
  - id: block-on-sql-injection
    pattern: |
      db.query($SQL)
    message: "SQL Injection detectado - PR BLOQUEADO"
    severity: ERROR
    languages: [javascript, python]
    metadata:
      cwe: "CWE-89"
      confidence: HIGH
      
  - id: block-on-hardcoded-secrets
    patterns:
      - pattern: password = "..."
      - pattern-not: password = ""
    message: "Senha hardcoded - PR BLOQUEADO"
    severity: ERROR
    
  - id: warn-on-eval
    pattern: eval(...)
    message: "eval() detectado - Revisar com cautela"
    severity: WARNING
    languages: [javascript]

# Semgrep Action com fail on error
- name: Run Semgrep
  run: |
    semgrep scan --config=.semgrep/policy.yml --error --json > semgrep.json
    # --error: exit code 1 se ERROR (não apenas warning)
```

### Documentação dos Critérios

```markdown
## 📊 Quality Gates - Critérios de Segurança

### Gate 1: Security Rating ≥ A
**O que mede**: Vulnerabilidades confirmadas no código  
**Threshold**: Nenhuma vulnerabilidade crítica/alta  
**Ação**: PR bloqueado se rating < A  
**Justificativa**: Zero vulnerabilidades conhecidas em produção

### Gate 2: Security Hotspots 100% Reviewed
**O que mede**: Código suspeito que requer revisão manual  
**Threshold**: Todos os hotspots revisados (marked safe/fixed)  
**Ação**: PR bloqueado se hotspots não revisados  
**Justificativa**: Garantir que código sensível foi auditado

### Gate 3: Vulnerabilities = 0
**O que mede**: Contagem de vulnerabilidades detectadas  
**Threshold**: Zero vulnerabilidades  
**Ação**: PR bloqueado se > 0  
**Justificativa**: Política de zero-vulnerability

### Gate 4: Coverage ≥ 80% (New Code)
**O que mede**: Cobertura de testes no código novo  
**Threshold**: 80% das linhas novas cobertas por testes  
**Ação**: PR bloqueado se < 80%  
**Justificativa**: Código testado = menos bugs/vulnerabilidades

### Exceções (Override Manual)
- Security Lead pode aprovar PR que falhou Quality Gate
- Justificativa obrigatória (ticket no Jira)
- Revisão retrospectiva em 30 dias
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **Quality Gate**: Critério objetivo para aprovar/rejeitar PR
2. **Shift-Left Enforcement**: Bloquear código inseguro ANTES de merge
3. **Security Rating**: Métrica agregada (A-E) de segurança
4. **Security Hotspots**: Código suspeito que requer revisão humana

### Erros Comuns

**Erro 1: "Quality Gate muito permissivo (sempre passa)"**
- **Causa**: Threshold como "Vulnerabilities > 10" (permite 9 vulnerabilidades)
- **Feedback**: "Gate permissivo = inútil. Para produção: 'Vulnerabilities > 0' (zero tolerance). Para staging: 'Security Rating worse than B' (permite A ou B). Defina baseado em criticidade do sistema. Sistema financeiro: mais rigoroso. PoC interno: pode ser mais flexível."

**Erro 2: "Quality Gate muito rigoroso (nenhum PR passa)"**
- **Causa**: "Coverage 100%" ou "Duplications 0%" (inalcançável)
- **Feedback**: "Gate impossível = devs desabilitam (pior cenário). Seja pragmático: Coverage 80% (não 100%), Duplications < 3% (não 0%), Security Rating A (não A+ imaginário). Gate deve ser desafiador mas atingível com esforço razoável."

**Erro 3: "Quality Gate configurado mas não integrado ao GitHub"**
- **Causa**: SonarQube configurado, mas GitHub Actions não verifica resultado
- **Feedback**: "Adicione `sonar.qualitygate.wait=true` no sonar-project.properties E use action `sonarqube-quality-gate-action` no workflow. Sem integração, SonarQube calcula gate mas GitHub não bloqueia PR. Valide: crie PR com vulnerabilidade e veja se falha."

**Erro 4: "Não documentou critérios (devs confusos)"**
- **Causa**: Gate configurado sem explicação
- **Feedback**: "Dev vê 'Quality Gate Failed' mas não entende por quê. Documente: 1) O que cada métrica significa, 2) Por que threshold escolhido, 3) Como corrigir (ações concretas), 4) Processo de exceção. Transparência gera adesão."

**Erro 5: "Bloqueou hotfix crítico de produção"**
- **Causa**: Quality Gate aplicado até em branches de emergência
- **Feedback**: "Gate é importante mas não pode bloquear hotfix de incidente P0. Crie branch rules: main/develop = Quality Gate obrigatório, hotfix/* = Quality Gate ignorado (mas notifica). Ou permita override manual por Security Lead com justificativa."

**Erro 6: "Security Hotspots não foram revisados (marcou tudo como safe)"**
- **Causa**: Dev marcou todos hotspots como safe sem análise para passar gate
- **Feedback**: "Hotspot Review não é checkbox. Cada hotspot precisa: 1) Análise técnica (é vulnerável?), 2) Justificativa (por que safe?), 3) Evidência (teste que prova). Revise manualmente 10% dos hotspots marcados safe (auditoria). Se má qualidade, reverta."

### Feedback Construtivo

**Para configuração profissional:**
> "Excelente Quality Gate! Critérios claros (Security Rating A, Hotspots 100% reviewed, Vulnerabilities 0), integrado ao GitHub, documentado para devs. Isso é controle de qualidade maduro. Próximo nível: 1) Métricas de tendência (track evolution), 2) Gates diferenciados por criticidade (produção vs feature branches), 3) Exceções rastreadas (override audit log)."

**Para configuração básica:**
> "Bom Gate! Configurado no SonarQube. Para melhorar: 1) Integre ao GitHub (sonarqube-quality-gate-action), 2) Documente critérios (README.md), 3) Ajuste thresholds (teste com PRs reais), 4) Configure branch rules (proteja main). Gate configurado mas não integrado = decorativo."

**Para dificuldades:**
> "Quality Gates têm curva de aprendizado. Comece: 1) Use template do SonarQube ('Sonar way'), 2) Aplique em 1 projeto piloto, 3) Ajuste baseado em feedback do time (muito rigoroso? muito permissivo?), 4) Expanda para outros projetos. É processo iterativo, não big bang."

### Contexto Pedagógico

**Por que é fundamental:**
- **Enforcement Automatizado**: Humanos esquecem, CI nunca esquece
- **Objetividade**: Critérios claros (não subjetivos)
- **Cultura de Qualidade**: Normaliza padrões altos
- **Compliance**: PCI-DSS, SOC2 exigem controles automatizados

**Conexão com carreira:**
- QA Automation configura e mantém gates
- Security Engineers definem critérios
- DevSecOps integra gates em múltiplos projetos

**Habilidades desenvolvidas:**
- Configuração de Quality Gates (SonarQube, Semgrep)
- Definição de thresholds e métricas de segurança
- Integração CI/CD com enforcement automatizado
- Documentação de critérios e processos
- Balanceamento entre rigor e pragmatismo

**Estatísticas da indústria:**
- 78% das empresas usam Quality Gates automatizados (DevOps Research, 2025)
- Gates reduzem vulnerabilidades em produção em 65% (Forrester, 2024)
- Times com gates bem configurados têm 50% menos débito técnico (DORA, 2025)

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
