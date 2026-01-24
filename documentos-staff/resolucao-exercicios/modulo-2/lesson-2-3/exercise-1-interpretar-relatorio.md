---
exercise_id: lesson-2-3-exercise-1-interpretar-relatorio
title: "Exercício 2.3.1: Interpretar Relatório de Pentest"
lesson_id: lesson-2-3
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.3.1: Interpretar Relatório de Pentest

## 📋 Enunciado Completo

Ler relatório profissional de pentest com 23 findings e criar plano de ação prático para QA.

### Tarefa
1. Ler Executive Summary e Technical Details
2. Priorizar findings por contexto de negócio
3. Criar plano de remediação (quem, quando, como)
4. Comunicar para stakeholders (CEO vs Devs)

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Análise matura:**
- Leu relatório completo (não apenas summary)
- Re-priorizou por contexto (não apenas CVSS)
- Criou action items com responsáveis e prazos
- Comunicação adaptada para audiência (técnica vs negócio)

**Exemplo:**
```markdown
## Priorização por Contexto

| Finding | CVSS | Prioridade QA | Justificativa |
|---------|------|---------------|---------------|
| SQLi em /checkout | 9.8 | P0 | Exposição de 5M registros PII → LGPD |
| Auth Bypass /admin | 9.1 | P0 | Acesso total sistema |
| IDOR em /orders | 8.2 | P1 | Vazamento dados pedidos |
| XSS em /search | 6.1 | P2 | Requer engenharia social |

## Comunicação

**Para CEO:**
> "Pentest identificou 2 críticas que podem expor dados de clientes. Priorizando correção urgente (5 dias). Risco está sendo mitigado."

**Para Devs:**
> "Relatório anexado. Prioridade: SQLi no /checkout (usar prepared statements) e Auth Bypass no /admin (validar roles server-side). Tickets criados com POCs."
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Leu relatório completo
- [ ] Priorizou por contexto
- [ ] Criou plano de ação
- [ ] Comunicação clara

### ⭐ Importantes
- [ ] Re-priorizou diferente do CVSS (justificado)
- [ ] Definiu responsáveis e prazos
- [ ] Adaptou comunicação para audiências

### 💡 Diferencial
- [ ] Criou estratégia de validação pós-correção
- [ ] Propôs controles preventivos
- [ ] Documentou lições aprendidas

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Priorizou apenas por CVSS"**
**Orientação**: "CVSS 9.8 em endpoint de teste pode ser P3. CVSS 6.0 em checkout pode ser P1. Re-priorize considerando contexto."

**Erro 2: "Não criou action items"**
**Orientação**: "QA não apenas identifica, mas COORDENA correção. Adicione: quem, quando, como QA vai validar."

**Erro 3: "Comunicação muito técnica para CEO"**
**Orientação**: "CEO não precisa saber o que é SQLi. Precisa saber: RISCO (dados vazados), IMPACTO ($, LGPD), PRAZO. Reescreva em linguagem de negócio."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
