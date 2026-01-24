---
exercise_id: lesson-2-2-exercise-4-dast-report-analysis
title: "Exercício 2.2.4: Análise de Relatório DAST Completo"
lesson_id: lesson-2-2
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.2.4: Análise de Relatório DAST Complexo

## 📋 Enunciado Completo

Analisar relatório DAST com 45 findings (3 Critical, 12 High, 20 Medium, 10 Low). Criar plano de remediação priorizado.

### Tarefa

1. Ler relatório completo (HTML ou JSON)
2. Agrupar findings por tipo (SQLi, XSS, etc)
3. Priorizar top 10 por risco real
4. Criar tickets para desenvolvimento
5. Definir sprints de correção

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Análise estruturada:**

```markdown
## Análise de Relatório DAST

### Resumo Executivo
- **Total**: 45 findings
- **Critical**: 3 (SQLi, Auth Bypass, Path Traversal)
- **High**: 12 (XSS, CSRF, IDOR)

### Priorização (Top 10)

| # | Vulnerabilidade | CVSS | Prioridade | Justificativa |
|---|-----------------|------|------------|---------------|
| 1 | SQL Injection (/checkout) | 9.8 | P0 | Dados de cartão expostos |
| 2 | Auth Bypass (/admin) | 9.1 | P0 | Acesso total ao painel |
| 3 | XSS Stored (/comments) | 7.5 | P1 | Persistente, múltiplos users afetados |

### Plano de Remediação

**Sprint Atual (Blocker)**:
- P0: SQLi e Auth Bypass (prazo: 48h)

**Próxima Sprint**:
- P1: 5 High vulnerabilities (prazo: 2 semanas)

**Backlog**:
- P2/P3: Medium e Low (gradualmente)
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Analisou relatório completo
- [ ] Agrupou findings por tipo
- [ ] Priorizou por risco real

### ⭐ Importantes
- [ ] Criou plano de remediação com sprints
- [ ] Comunicação clara para stakeholders
- [ ] Tickets criados com POCs

### 💡 Diferencial
- [ ] Dashboard visual de priorização
- [ ] Estratégia de remediação gradual
- [ ] Métricas de progresso

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Não agrupou findings"**
**Orientação**: "Agrupe por tipo (8 SQLi, 5 XSS, etc). Facilita visualizar padrões e priorizar correções sistêmicas."

**Erro 2: "Priorizou tudo como P0"**
**Orientação**: "Use matriz de risco. P0 é APENAS para Critical em produção com dados sensíveis. Re-priorize contextualmente."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
