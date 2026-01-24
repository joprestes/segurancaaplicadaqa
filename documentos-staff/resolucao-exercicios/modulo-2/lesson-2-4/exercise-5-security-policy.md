---
exercise_id: lesson-2-4-exercise-5-security-policy
title: "Exercício 2.4.5: Criar Política de Segurança Executável"
lesson_id: lesson-2-4
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.4.5: Criar Política de Segurança Executável

## 📋 Enunciado Completo

Criar "Security Policy as Code" que define e força regras de segurança no CI/CD.

### Tarefa
1. Definir políticas (ex: 0 Critical, max 5 High)
2. Implementar em código (YAML, JSON)
3. Integrar no pipeline
4. Gerar relatório de compliance

---

## ✅ Soluções Detalhadas

**Policy as Code (exemplo):**
```yaml
# security-policy.yml
policy:
  vulnerabilities:
    critical: 0
    high: 5
    medium: 20
  
  sast:
    required: true
    tools: [semgrep, sonarqube]
  
  dast:
    required_for: [staging, prod]
    tools: [zap]
  
  sca:
    required: true
    sbom_required: true
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Política definida em código
- [ ] Integrada no CI/CD
- [ ] Enforce (bloqueia se violar)

### ⭐ Importantes
- [ ] Versionada no git
- [ ] Relatório de compliance gerado
- [ ] Documentação clara

---

**Última atualização**: 2026-01-24
