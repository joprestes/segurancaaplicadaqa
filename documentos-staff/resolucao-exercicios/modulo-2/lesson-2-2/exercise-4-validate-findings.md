---
exercise_id: lesson-2-2-exercise-4-validate-findings
title: "Exercício 2.2.4: Validar e Priorizar Findings DAST"
lesson_id: lesson-2-2
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-14
---

# Exercício 2.2.4: Validar e Priorizar Findings DAST

## 📋 Enunciado Completo

Este exercício tem como objetivo **criar processo de triagem e validação de findings DAST**, diferenciar false positives de true positives, e priorizar vulnerabilidades por risco real.

### Tarefa Principal

1. Executar DAST em aplicação real
2. Para cada finding Critical/High:
   - Validar se é True Positive ou False Positive
   - Analisar contexto e impacto
   - Priorizar por risco real
   - Documentar decisão
3. Criar dashboard de vulnerabilidades priorizadas
4. Criar processo de triagem documentado

---

## ✅ Soluções Detalhadas

### Passo 1: Executar DAST

**Solução Esperada:**
- DAST executado em aplicação real
- Resultados exportados (JSON e HTML)
- Findings consolidados

### Passo 2: Processo de Validação

**Solução Esperada - Template de Validação:**

```markdown
## Finding: SQL Injection em /api/users

### Metadados
- Severidade DAST: High
- URL: http://app.com/api/users?id=1
- Parâmetro: id

### Requisição/Resposta
[Requisição e resposta HTTP completas]

### Análise de Contexto
- [x] URL está em produção? Sim
- [x] Endpoint requer autenticação? Não
- [x] Dados sensíveis afetados? Sim
- [x] Vulnerabilidade é reproduzível? Sim

### Análise de Risco
- Exploitability: ALTA
- Impacto: CRÍTICO
- Contexto: Endpoint público, dados sensíveis

### Decisão
- [x] True Positive - P1 (Corrigir IMEDIATAMENTE)
```

**Validação:**
- ✅ Aluno valida cada finding Critical/High
- ✅ Aluno diferencia true/false positives
- ✅ Aluno documenta decisão claramente

### Passo 3: Priorização

**Solução Esperada - Matriz de Priorização:**

| Severidade DAST | Exploitability | Impacto | App em Prod | Prioridade |
|----------------|----------------|---------|-------------|------------|
| High | Alta | Dados sensíveis | Sim | P1 |
| High | Alta | Dados sensíveis | Não | P2 |
| Medium | Alta | Dados sensíveis | Sim | P2 |

**Validação:**
- ✅ Aluno prioriza por risco real (não apenas severidade)
- ✅ Aluno considera exploitability, impacto, contexto

### Passo 4: Dashboard

**Solução Esperada:**
- Dashboard criado com vulnerabilidades priorizadas
- Agrupamento por prioridade (P1, P2, P3, P4)
- Estatísticas (total, por severidade, por status)

### Passo 5: Processo de Triagem

**Solução Esperada:**
- Processo documentado claramente
- Passos definidos (execução, triagem, validação, priorização)
- Critérios de priorização documentados

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Validação:**
- [ ] DAST executado em aplicação real
- [ ] Findings Critical/High validados (True Positive vs False Positive)
- [ ] Template de validação preenchido para cada finding

**Priorização:**
- [ ] Priorização por risco real realizada (P1/P2/P3/P4)
- [ ] Dashboard de vulnerabilidades criado

### ⭐ Importantes (Recomendados para Resposta Completa)

**Processo:**
- [ ] Processo de triagem documentado
- [ ] Issues criadas para True Positives P1/P2/P3
- [ ] Estatísticas de validação (quantos TP vs FP)

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Análise Avançada:**
- [ ] Análise profunda de contexto e impacto
- [ ] Consideração de compliance (LGPD, PCI-DSS)
- [ ] Estratégia de correção com prazos

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Validação**: Aluno valida findings ou assume que tudo é real?
2. **Priorização**: Aluno prioriza por risco real ou apenas severidade?
3. **Processo**: Aluno documenta processo de triagem?

### Erros Comuns

1. **Erro: Não Validar Findings**
   - **Feedback**: "Boa análise! Sempre valide cada finding Critical/High manualmente. Nem tudo que DAST reporta é vulnerabilidade real. Reproduzir o ataque ajuda a confirmar se é true positive."

2. **Erro: Priorização Apenas por Severidade**
   - **Feedback**: "Excelente identificação! Lembre-se de priorizar por risco real, não apenas severidade DAST. Considere: está em produção? dados sensíveis? fácil explorar? Isso ajuda a focar esforço onde realmente importa."

---

---

## 📝 CRÉDITOS

═══════════════════════════════════════════════════════
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Baseado em**: Aula 2.2: DAST: Dynamic Application Security Testing  
**Referência**: Módulo 2 - Testes de Segurança na Prática  
**Data de revisão**: Janeiro/2026
═══════════════════════════════════════════════════════
