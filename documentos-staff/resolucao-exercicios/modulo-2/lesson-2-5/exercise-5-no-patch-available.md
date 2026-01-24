---
exercise_id: lesson-2-5-exercise-5-no-patch-available
title: "Exercício 2.5.5: Dependência Vulnerável Sem Patch Disponível"
lesson_id: lesson-2-5
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.5.5: Dependência Vulnerável Sem Patch Disponível

## 📋 Enunciado Completo

**Cenário**: Dependência crítica (`auth-lib@2.5.0`) tem vulnerabilidade High, mas não há patch disponível. Biblioteca abandonada pelo mantenedor.

### Tarefa
1. Avaliar risco real (exploitável?)
2. Buscar alternativas (fork, biblioteca alternativa)
3. Implementar workarounds
4. Criar plano de migração
5. Documentar risco residual

---

## ✅ Soluções Detalhadas

**Análise de opções:**

```markdown
## Análise: auth-lib@2.5.0 vulnerável (sem patch)

### Opção 1: Fork e Patch Customizado
**Prós**: Controle total, correção rápida
**Contras**: Manutenção nossa, risco de bugs
**Esforço**: 2-3 dias

### Opção 2: Migrar para Alternativa (passport.js)
**Prós**: Mantida ativamente, comunidade grande
**Contras**: Refatoração de código (1-2 sprints)
**Esforço**: 2 semanas

### Opção 3: Workaround (validação extra)
**Prós**: Rápido (< 1 dia)
**Contras**: Não resolve root cause
**Esforço**: 1 dia

### Decisão: Opção 3 (curto prazo) + Opção 2 (longo prazo)
- **Imediato**: Implementar validação extra (mitiga risco)
- **Próximos 2 meses**: Migrar para passport.js
- **Risco residual**: Baixo (mitigação valida inputs)
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Avaliou risco real
- [ ] Analisou múltiplas opções
- [ ] Tomou decisão fundamentada

### ⭐ Importantes
- [ ] Implementou workaround temporário
- [ ] Criou plano de migração
- [ ] Documentou risco residual

### 💡 Diferencial
- [ ] Contatou mantenedor original
- [ ] Propôs patch para comunidade
- [ ] Criou biblioteca alternativa open-source

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Decidiu apenas remover biblioteca"**
**Orientação**: "Biblioteca provê funcionalidade crítica (autenticação). Não pode apenas remover. Analise alternativas viáveis."

**Erro 2: "Implementou fork sem avaliar custo de manutenção"**
**Orientação**: "Fork = você vira mantenedor. Considere esforço contínuo de manutenção, bugs, segurança. Às vezes migração é melhor long-term."

---

**Última atualização**: 2026-01-24
