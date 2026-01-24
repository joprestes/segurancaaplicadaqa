---
exercise_id: lesson-2-4-exercise-4-pipeline-optimization
title: "Exercício 2.4.4: Otimização de Pipeline de Segurança"
lesson_id: lesson-2-4
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.4.4: Otimizar Pipeline de Segurança

## 📋 Enunciado Completo

Pipeline de segurança demora 18 minutos. Otimizar para < 5 minutos sem perder eficácia.

### Tarefa
1. Analisar gargalos (SAST, DAST, SCA)
2. Implementar otimizações (cache, paralelização)
3. Medir tempo antes e depois
4. Validar que detecta as mesmas vulnerabilidades

---

## ✅ Soluções Detalhadas

**Otimizações comuns:**
- Cache de dependências (npm, pip)
- Executar SAST e SCA em paralelo
- Scan diferencial (apenas mudanças)
- DAST baseline (não full scan)

**Resultados esperados:**
- Antes: 18min → Depois: 4min 30s
- Eficácia mantida (mesmas vulnerabilidades detectadas)

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Otimizações implementadas
- [ ] Tempo reduzido (> 50%)
- [ ] Eficácia validada

---

**Última atualização**: 2026-01-24
