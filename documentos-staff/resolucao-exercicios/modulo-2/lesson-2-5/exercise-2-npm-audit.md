---
exercise_id: lesson-2-5-exercise-2-npm-audit
title: "Exercício 2.5.2: npm audit e yarn audit"
lesson_id: lesson-2-5
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.5.2: npm audit e yarn audit

## 📋 Enunciado Completo

Usar ferramentas nativas (npm audit, yarn audit) para detectar vulnerabilidades.

### Tarefa
1. Executar `npm audit` ou `yarn audit`
2. Analisar relatório
3. Aplicar `npm audit fix` (correções automáticas)
4. Validar correções manuais para High/Critical

---

## ✅ Soluções Detalhadas

**Comando:**
```bash
npm audit
npm audit fix  # Correções automáticas
npm audit fix --force  # Inclui breaking changes (cuidado!)
```

**Análise esperada:**
- Vulnerabilidades automáticas corrigidas: X
- Vulnerabilidades manuais restantes: Y
- Plano de correção manual para High/Critical

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Executou npm audit
- [ ] Aplicou correções automáticas
- [ ] Documentou restantes

---

**Última atualização**: 2026-01-24
