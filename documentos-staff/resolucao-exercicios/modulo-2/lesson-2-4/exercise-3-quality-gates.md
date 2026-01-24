---
exercise_id: lesson-2-4-exercise-3-quality-gates
title: "Exercício 2.4.3: Implementar Quality Gates"
lesson_id: lesson-2-4
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.4.3: Implementar Quality Gates de Segurança

## 📋 Enunciado Completo

Configurar Quality Gates que bloqueiam deploy se:
- Vulnerabilidades Critical > 0
- Security Rating < B
- Cobertura de testes < 80%

### Tarefa
1. Configurar Quality Gate no SonarQube
2. Integrar no pipeline CI/CD
3. Testar com PR que falha no gate
4. Documentar critérios

---

## ✅ Soluções Detalhadas

**Quality Gate SonarQube:**
```yaml
Conditions:
  - New Critical Vulnerabilities: 0
  - New High Vulnerabilities: max 5
  - Security Rating: A ou B
  - Test Coverage: >= 80%
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Quality Gate configurado
- [ ] Integrado no CI/CD
- [ ] Testado com PR

---

**Última atualização**: 2026-01-24
