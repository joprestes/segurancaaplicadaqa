---
exercise_id: lesson-2-4-exercise-1-github-actions-sast
title: "Exercício 2.4.1: Configurar SAST no GitHub Actions"
lesson_id: lesson-2-4
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.4.1: Configurar SAST no GitHub Actions

## 📋 Enunciado Completo

Configurar Semgrep ou CodeQL no GitHub Actions para executar em cada PR.

### Tarefa
1. Criar workflow `.github/workflows/sast.yml`
2. Configurar scan em PRs
3. Postar resultados como comentário
4. Bloquear PR se Critical encontrado

---

## ✅ Soluções Detalhadas

**Workflow funcional:**
```yaml
name: SAST
on: pull_request

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: returntocorp/semgrep-action@v1
        with:
          config: p/security-audit
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Workflow criado e funcional
- [ ] Executa em PRs
- [ ] Bloqueia Critical

### ⭐ Importantes
- [ ] Resultados postados no PR
- [ ] Otimizado (< 3min)
- [ ] Cache configurado

---

**Última atualização**: 2026-01-24
