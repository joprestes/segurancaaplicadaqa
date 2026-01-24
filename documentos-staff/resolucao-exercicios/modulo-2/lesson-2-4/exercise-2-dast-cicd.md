---
exercise_id: lesson-2-4-exercise-2-dast-cicd
title: "Exercício 2.4.2: Integrar DAST no Pipeline"
lesson_id: lesson-2-4
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.4.2: Integrar DAST no Pipeline CI/CD

## 📋 Enunciado Completo

Configurar OWASP ZAP baseline scan em staging antes de deploy em produção.

### Tarefa
1. Adicionar step de DAST no pipeline
2. Executar em ambiente staging
3. Bloquear deploy se Critical
4. Gerar relatório automaticamente

---

## ✅ Soluções Detalhadas

**GitHub Actions:**
```yaml
- name: ZAP Scan
  uses: zaproxy/action-baseline@v0.7.0
  with:
    target: https://staging.exemplo.com
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] DAST executa em staging
- [ ] Bloqueia deploy se Critical
- [ ] Relatório gerado

---

**Última atualização**: 2026-01-24
