---
exercise_id: lesson-2-3-exercise-2-validar-correcoes
title: "Exercício 2.3.2: Validar Correções de Pentest"
lesson_id: lesson-2-3
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.3.2: Validar Correções de Pentest

## 📋 Enunciado Completo

Time de dev corrigiu 5 vulnerabilidades do pentest. Validar se correções são efetivas.

### Tarefa
1. Reproduzir exploits originais do pentest
2. Testar correções (exploit ainda funciona?)
3. Testar variações (bypass possível?)
4. Validar com pentester (se disponível)
5. Documentar validação

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Validação profissional:**
```markdown
## Validação de Correção: SQLi em /checkout

### Exploit Original (do relatório)
```bash
curl -X POST https://app.exemplo.com/checkout \
  -d "item_id=1' OR '1'='1' --"
# Resultado ANTES: Retornou todos os pedidos (VULNERÁVEL)
```

### Tentativa Após Correção
```bash
curl -X POST https://app.exemplo.com/checkout \
  -d "item_id=1' OR '1'='1' --"
# Resultado DEPOIS: 400 Bad Request (CORRIGIDO ✅)
```

### Tentativas de Bypass
1. `item_id=1" OR "1"="1" --` → Bloqueado ✅
2. `item_id=1 UNION SELECT * FROM users --` → Bloqueado ✅
3. `item_id=1; DROP TABLE orders; --` → Bloqueado ✅

### Código Corrigido Revisado
```python
# ANTES (vulnerável)
query = f"SELECT * FROM orders WHERE id={item_id}"

# DEPOIS (corrigido)
query = "SELECT * FROM orders WHERE id = ?"
cursor.execute(query, (item_id,))
```

### Conclusão
✅ **CORREÇÃO EFETIVA**
- Exploit original bloqueado
- 3 variações testadas, todas bloqueadas
- Código usa prepared statements corretamente
- Recomendação: APROVAR para produção
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Reproduziu exploit original
- [ ] Testou após correção
- [ ] Validou que correção funciona

### ⭐ Importantes
- [ ] Testou variações (tentativas de bypass)
- [ ] Revisou código corrigido
- [ ] Documentou processo de validação

### 💡 Diferencial
- [ ] Automatizou teste de regressão
- [ ] Validou com pentester externo
- [ ] Criou teste de integração permanente

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Testou apenas exploit original"**
**Orientação**: "Atacantes tentam bypasses. Teste ao menos 3 variações. Isso valida robustez da correção."

**Erro 2: "Não revisou código"**
**Orientação**: "Teste funcional valida comportamento, mas revisão de código valida COMO foi corrigido. Correção pode funcionar mas ser frágil."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
