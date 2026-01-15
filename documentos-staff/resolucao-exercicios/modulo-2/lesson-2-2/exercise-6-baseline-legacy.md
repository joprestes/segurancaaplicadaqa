---
exercise_id: lesson-2-2-exercise-6-baseline-legacy
title: "Exercício 2.2.6: Gerenciar Baseline em Projeto Legado"
lesson_id: lesson-2-2
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-14
---

# Exercício 2.2.6: Gerenciar Baseline em Projeto Legado ⭐ **OPCIONAL**

> **Nota**: Este exercício é opcional e focado em cenários específicos de projetos legados. Se você não trabalha com projetos legados, pode pular este exercício.

## 📋 Enunciado Completo

Este exercício tem como objetivo **criar e gerenciar baseline de vulnerabilidades em projeto legado**, permitindo que o time continue desenvolvendo enquanto trabalha na redução gradual de vulnerabilidades existentes.

### Tarefa Principal

1. Executar DAST em aplicação legada (ou simular)
2. Criar baseline de vulnerabilidades aceitas
3. Configurar Quality Gate que permite baseline mas bloqueia novas
4. Criar estratégia de redução gradual
5. Documentar processo de triagem
6. Comunicar baseline para stakeholders

---

## ✅ Soluções Detalhadas

### Passo 1: Executar DAST Inicial

**Solução Esperada:**
- DAST executado em aplicação legada
- Estado inicial documentado (total de vulnerabilidades por severidade)
- Baseline criado com data específica

**Documentação Esperada:**
```markdown
# Estado Inicial - Baseline
- Data: 2026-01-14
- Total: 347 vulnerabilidades
- Critical: 28
- High: 89
- Medium: 156
- Low: 74
```

### Passo 2: Criar Baseline Aceito

**Solução Esperada:**

**2.1. Critérios de Baseline:**
- Todas as vulnerabilidades encontradas na data X são aceitas
- Novas vulnerabilidades (após data X) devem ser tratadas
- Critical novas: Bloquear deploy
- High novas: Corrigir neste sprint

**2.2. Documentação:**
```markdown
# Baseline de Vulnerabilidades Aceitas
- Data de Baseline: 2026-01-14
- Todas as 347 vulnerabilidades encontradas são aceitas
- Regras para novas: Critical bloqueia, High corrige neste sprint
```

### Passo 3: Configurar Quality Gate com Baseline

**Solução Esperada:**

**3.1. Script de Validação:**
```python
def check_baseline(zap_file='zap-full.json'):
    baseline_ids = load_baseline_ids()
    alerts = load_alerts(zap_file)
    
    new_critical = 0
    for alert in alerts:
        if alert_id not in baseline_ids and risk == 'HIGH':
            new_critical += 1
    
    if new_critical > 0:
        print(f"❌ Found {new_critical} NEW Critical vulnerabilities!")
        sys.exit(1)
```

**Validação:**
- ✅ Script diferencia baseline de novas vulnerabilidades
- ✅ Pipeline bloqueia apenas novas Critical
- ✅ Baseline é aceito

### Passo 4: Estratégia de Redução Gradual

**Solução Esperada:**

**4.1. Metas por Trimestre:**
```markdown
# Estratégia de Redução
- Q1: Baseline estabelecido
- Q2: Reduzir aproximadamente metade das Critical (28 → 15)
- Q3: Reduzir aproximadamente dois terços das Critical restantes (15 → 5)
- Q4: Eliminar todas Critical (5 → 0)
```

**4.2. Alocação de Recursos:**
- 1 desenvolvedor: parte do tempo (aproximadamente um quinto do tempo disponível)
- 1 sprint por trimestre: focado em segurança

### Passo 5: Processo de Triagem

**Solução Esperada:**
- Processo documentado claramente
- Passos definidos (verificar se é baseline, validar se nova, priorizar)
- Critérios de priorização para novas vulnerabilidades

### Passo 6: Comunicação para Stakeholders

**Solução Esperada:**
- Relatório executivo criado
- Justificativa do baseline clara
- Metas de redução definidas
- Investimento necessário quantificado

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Baseline:**
- [ ] Baseline de vulnerabilidades criado e documentado
- [ ] Quality Gate configurado (permite baseline, bloqueia novas)
- [ ] Script de validação com baseline funcionando

**Estratégia:**
- [ ] Estratégia de redução gradual criada
- [ ] Processo de triagem documentado

### ⭐ Importantes (Recomendados para Resposta Completa)

**Comunicação:**
- [ ] Relatório de comunicação para stakeholders criado
- [ ] Justificativa do baseline clara
- [ ] Metas de redução definidas

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Análise Avançada:**
- [ ] Dashboard de progresso criado
- [ ] Métricas de redução definidas
- [ ] Plano de comunicação para time

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Baseline**: Aluno entende conceito de baseline?
2. **Estratégia**: Aluno cria estratégia realista de redução?
3. **Comunicação**: Aluno comunica baseline claramente?

### Erros Comuns

1. **Erro: Baseline Muito Permissivo**
   - **Feedback**: "Boa criação do baseline! Lembre-se de que Critical relacionadas a dados sensíveis (pagamentos, cartões) devem ser corrigidas mesmo no baseline. Baseline não significa aceitar tudo."

2. **Erro: Metas Irrealistas**
   - **Feedback**: "Excelente estratégia! Certifique-se de que metas são realistas. Reduzir todas as Critical em 1 mês pode ser muito agressivo. Metas graduais (aproximadamente um quarto a um terço por trimestre) são mais sustentáveis."

---

---

## 📝 CRÉDITOS

═══════════════════════════════════════════════════════
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Baseado em**: Aula 2.2: DAST: Dynamic Application Security Testing  
**Referência**: Módulo 2 - Testes de Segurança na Prática  
**Data de revisão**: Janeiro/2026
═══════════════════════════════════════════════════════
