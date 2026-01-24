---
exercise_id: lesson-2-2-exercise-3-dast-cicd
title: "Exercício 2.2.3: Integrar DAST no CI/CD"
lesson_id: lesson-2-2
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.2.3: Integrar DAST no Pipeline CI/CD

## 📋 Enunciado Completo

Configurar OWASP ZAP no pipeline CI/CD para executar scans automatizados em staging antes de produção.

### Tarefa

1. Configurar ZAP baseline scan no CI/CD
2. Executar scan em ambiente de staging
3. Gerar relatório automaticamente
4. Bloquear deploy se vulnerabilidades críticas encontradas
5. Documentar processo

---

## ✅ Soluções Detalhadas

### Solução Esperada

**GitHub Actions (exemplo):**

```yaml
# .github/workflows/dast.yml
name: DAST Security Scan

on:
  push:
    branches: [staging]

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'https://staging.exemplo.com'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
```

**Evidências:**
- Pipeline executa em staging
- Relatório HTML gerado
- PRs bloqueados se Critical vulnerabilities
- Documentação clara

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] DAST integrado no CI/CD
- [ ] Executa automaticamente em staging
- [ ] Bloqueia deploy se crítico

### ⭐ Importantes
- [ ] Configurou baseline (aceita vulnerabilidades existentes)
- [ ] Otimizou tempo de scan (< 10min)
- [ ] Notificações configuradas (Slack, email)

### 💡 Diferencial
- [ ] Scan diferencial (apenas mudanças)
- [ ] Authenticated scan configurado
- [ ] Dashboard de tendências

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Scan muito lento (> 20min)"**
**Orientação**: "Use ZAP Baseline (não Full Scan) para CI/CD. Configure `-j` (AJAX spider) apenas se necessário. Meta: < 10min."

**Erro 2: "Bloqueia todo deploy"**
**Orientação**: "Configure baseline tolerante inicialmente. Gradualmente aperte. Use rules.tsv para aceitar False Positives conhecidos."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
