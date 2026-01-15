---
exercise_id: lesson-2-2-exercise-7-optimize-performance
title: "Exercício 2.2.7: Otimizar Performance de Scans DAST"
lesson_id: lesson-2-2
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-14
---

# Exercício 2.2.7: Otimizar Performance de Scans DAST ⭐ **OPCIONAL**

> **Nota**: Este exercício é opcional e focado em otimização de performance. Se seus scans já são rápidos (< 10 minutos), pode pular este exercício.

## 📋 Enunciado Completo

Este exercício tem como objetivo **otimizar performance de scans DAST**, reduzindo tempo de execução sem comprometer cobertura de segurança.

### Tarefa Principal

1. Identificar por que scan está lento
2. Aplicar otimizações (escopo, políticas, paralelização)
3. Medir impacto das otimizações
4. Validar que cobertura não foi comprometida
5. Documentar otimizações aplicadas

---

## ✅ Soluções Detalhadas

### Passo 1: Identificar Gargalos

**Solução Esperada:**

**1.1. Medir Tempo Inicial:**
```bash
time docker exec zap zap-full-scan.py -t http://localhost:3000
# Exemplo: 45 minutos
```

**1.2. Análise de Gargalos:**
- Crawling: 15 minutos (aproximadamente um terço do tempo) - muitas URLs
- Active scanning: 25 minutos (mais da metade do tempo) - muitos payloads
- Total: 45 minutos

**Documentação:**
```markdown
# Análise de Performance
- Tempo total: 45 minutos
- Crawling: 15 min (aproximadamente um terço do tempo)
- Active scanning: 25 min (mais da metade do tempo)
- Gargalo: Muitas URLs × Muitos payloads
```

### Passo 2: Aplicar Otimizações

**Solução Esperada:**

**2.1. Otimização 1: Limitar Escopo**
```bash
# Scan apenas em URLs críticas
docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -I ".*api.*|.*admin.*|.*checkout.*"
# Tempo: 12 minutos (redução significativa - menos de um terço do tempo original)
```

**2.2. Otimização 2: Reduzir Profundidade**
```bash
# Máximo 3 níveis
docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -I ".*api.*" \
  -m 3
# Tempo: 8 minutos (redução adicional - menos da metade do tempo anterior)
```

**2.3. Otimização 3: Passivo + Ativo Crítico**
```bash
# Passivo em todas URLs (rápido)
docker exec zap zap-baseline.py -t http://localhost:3000

# Ativo apenas em URLs críticas
docker exec zap zap-full-scan.py -t http://localhost:3000 -I ".*critical.*"
# Tempo total: 7 minutos (redução muito significativa - menos de um quinto do tempo original)
```

### Passo 3: Medir Impacto

**Solução Esperada - Tabela Comparativa:**

| Configuração | Tempo | Vulnerabilidades | Cobertura |
|--------------|-------|------------------|-----------|
| Original | 45 min | 28 | Completa |
| Escopo limitado | 12 min | 24 | Alta (maioria das vulnerabilidades críticas) |
| + Profundidade | 8 min | 22 | Alta (maioria das vulnerabilidades críticas) |
| Passivo + Ativo | 7 min | 20 | Boa (vulnerabilidades críticas mantidas) |

**Validação:**
- ✅ Tempo reduzido significativamente (mais da metade do tempo original)
- ✅ Cobertura de vulnerabilidades críticas mantida (maioria das vulnerabilidades críticas encontradas)

### Passo 4: Validar Cobertura

**Solução Esperada:**
- Vulnerabilidades críticas encontradas: 7 de 8 (maioria encontrada) ✅
- Vulnerabilidades High encontradas: 10 de 12 (maioria encontrada) ✅
- Cobertura crítica mantida (maioria das vulnerabilidades críticas encontradas)

**Decisão:**
- Cobertura crítica mantida → Otimização aceitável
- Scan completo semanalmente para cobertura total

### Passo 5: Documentar Otimizações

**Solução Esperada:**
- Otimizações aplicadas documentadas
- Impacto medido (tempo, cobertura)
- Estratégia de balance performance/cobertura definida

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Otimização:**
- [ ] Gargalos identificados e documentados
- [ ] Pelo menos 3 otimizações aplicadas
- [ ] Tempo de execução reduzido significativamente (pelo menos metade do tempo original)

**Validação:**
- [ ] Cobertura de vulnerabilidades críticas mantida (maioria das vulnerabilidades críticas encontradas)
- [ ] Melhorias medidas e documentadas

### ⭐ Importantes (Recomendados para Resposta Completa)

**Estratégia:**
- [ ] Estratégia de balance performance/cobertura definida
- [ ] Comparação de performance (antes/depois) documentada

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Otimização Avançada:**
- [ ] Paralelização implementada
- [ ] Múltiplas estratégias testadas e comparadas
- [ ] Análise de trade-offs detalhada

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Otimização**: Aluno identifica e aplica otimizações efetivas?
2. **Balance**: Aluno balance performance e cobertura?
3. **Medição**: Aluno mede impacto das otimizações?

### Erros Comuns

1. **Erro: Sacrificar Cobertura Demais**
   - **Feedback**: "Boa otimização! Certifique-se de que cobertura de vulnerabilidades críticas não foi comprometida. Se a maioria das vulnerabilidades críticas não está sendo encontrada, considere ajustar otimizações."

2. **Erro: Não Medir Impacto**
   - **Feedback**: "Excelente trabalho otimizando! Sempre meça impacto (tempo antes/depois, cobertura antes/depois). Isso valida que otimizações funcionam."

---

---

## 📝 CRÉDITOS

═══════════════════════════════════════════════════════
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Baseado em**: Aula 2.2: DAST: Dynamic Application Security Testing  
**Referência**: Módulo 2 - Testes de Segurança na Prática  
**Data de revisão**: Janeiro/2026
═══════════════════════════════════════════════════════
