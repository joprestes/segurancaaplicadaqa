---
exercise_id: lesson-2-2-exercise-5-compare-dast-tools
title: "Exercício 2.2.5: Comparar Ferramentas DAST"
lesson_id: lesson-2-2
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-14
---

# Exercício 2.2.5: Comparar Ferramentas DAST

## 📋 Enunciado Completo

Este exercício tem como objetivo **comparar diferentes ferramentas DAST** na mesma aplicação, analisar resultados, e criar relatório comparativo com recomendação.

### Tarefa Principal

1. Escolher aplicação para análise
2. Executar 2-3 ferramentas DAST diferentes na mesma aplicação
3. Comparar resultados (número de findings, false positives, tempo)
4. Validar manualmente amostra de findings
5. Analisar custo, facilidade de uso, integração
6. Criar relatório comparativo com recomendação

---

## ✅ Soluções Detalhadas

### Passo 1: Preparar Ambiente

**Solução Esperada:**
- Aplicação escolhida para teste
- 2-3 ferramentas DAST instaladas (OWASP ZAP, Burp Suite, etc.)
- Ambiente preparado para comparação

### Passo 2: Executar Ferramentas

**Solução Esperada:**

**2.1. OWASP ZAP:**
```bash
docker exec zap zap-full-scan.py -t http://localhost:3000 -J zap-results.json
```

**2.2. Burp Suite:**
- Executar scan automatizado
- Exportar resultados

**2.3. Medir Tempo:**
- Anotar tempo de execução de cada ferramenta

### Passo 3: Consolidar Resultados

**Solução Esperada - Tabela Comparativa:**

| Ferramenta | Total | High | Medium | Low | Tempo | Precisão |
|------------|-------|------|--------|-----|-------|----------|
| OWASP ZAP | 28 | 2 | 8 | 18 | 15 min | Alta |
| Burp Suite | 22 | 1 | 7 | 14 | 20 min | Muito Alta |

### Passo 4: Validar Findings

**Solução Esperada:**
- Amostra de 10-15 findings validada manualmente
- Precisão calculada (TP / Total validados)
- False positives identificados

### Passo 5: Análise de Custo-Benefício

**Solução Esperada:**
- Custo calculado (licença, setup, tempo)
- Benefício calculado (vulnerabilidades encontradas)
- ROI calculado

### Passo 6: Relatório Comparativo

**Solução Esperada - Estrutura:**

```markdown
# Relatório Comparativo: Ferramentas DAST

## Resumo Executivo
- Ferramentas testadas: OWASP ZAP, Burp Suite
- Recomendação: [Ferramenta] para [contexto]

## Resultados
[Comparação de findings, tempo, precisão]

## Análise
[Pontos fortes e fracos de cada ferramenta]

## Recomendação
[Justificativa da recomendação]
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Execução:**
- [ ] 2-3 ferramentas DAST executadas na mesma aplicação
- [ ] Resultados consolidados e comparados
- [ ] Tabela comparativa criada

**Análise:**
- [ ] Amostra de findings validada manualmente
- [ ] Precisão calculada para cada ferramenta

### ⭐ Importantes (Recomendados para Resposta Completa)

**Relatório:**
- [ ] Análise de custo-benefício realizada
- [ ] Relatório comparativo criado com recomendação
- [ ] Justificativa da recomendação clara

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Análise Avançada:**
- [ ] Análise profunda de trade-offs
- [ ] Consideração de contexto específico (financeiro, educacional, etc.)
- [ ] Estratégia de uso combinado de ferramentas

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Comparação**: Aluno compara ferramentas de forma justa?
2. **Análise**: Aluno analisa trade-offs e custo-benefício?
3. **Recomendação**: Aluno justifica recomendação claramente?

### Erros Comuns

1. **Erro: Comparação Injusta**
   - **Feedback**: "Boa comparação! Certifique-se de que todas as ferramentas testam a mesma aplicação nas mesmas condições. Isso garante comparação justa."

2. **Erro: Não Validar Findings**
   - **Feedback**: "Excelente trabalho comparando ferramentas! Para calcular precisão, valide manualmente uma amostra de findings. Isso mostra qual ferramenta tem menos false positives."

---

---

## 📝 CRÉDITOS

═══════════════════════════════════════════════════════
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Baseado em**: Aula 2.2: DAST: Dynamic Application Security Testing  
**Referência**: Módulo 2 - Testes de Segurança na Prática  
**Data de revisão**: Janeiro/2026
═══════════════════════════════════════════════════════
