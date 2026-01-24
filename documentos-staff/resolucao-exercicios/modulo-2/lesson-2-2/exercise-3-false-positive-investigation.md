---
exercise_id: lesson-2-2-exercise-3-false-positive-investigation
title: "Exercício 2.2.3: Investigação de False Positive em DAST"
lesson_id: lesson-2-2
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.2.3: Investigação de False Positive em DAST

## 📋 Enunciado Completo

DAST reportou XSS Reflected (High) em `/search?q=<script>alert(1)</script>`. Validar se é TRUE ou FALSE POSITIVE.

### Tarefa

1. Reproduzir payload manualmente (Burp Suite ou curl)
2. Testar variações do payload
3. Analisar resposta HTTP (payload foi sanitizado?)
4. Consultar código-fonte (se disponível)
5. Concluir: TRUE ou FALSE POSITIVE com evidências

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Investigação completa:**

```markdown
## Investigação de False Positive

### 1. Reprodução Manual

**Teste 1: Payload original**
```bash
curl "https://app.exemplo.com/search?q=<script>alert(1)</script>"
# Resposta: <div>Busca por: &lt;script&gt;alert(1)&lt;/script&gt;</div>
# ✅ HTML entities codificados → NÃO executou
```

**Teste 2: Variações**
- `<img src=x onerror=alert(1)>` → Codificado
- `javascript:alert(1)` → Codificado

### 2. Código-Fonte (React)
```javascript
<div>Busca por: {query}</div>  // React sanitiza automaticamente
```

### 3. Conclusão

**Veredito**: ❌ FALSE POSITIVE

**Justificativa**:
- HTML entities codificados (&lt; ao invés de <)
- Testado 3 payloads, nenhum executou
- React JSX sanitiza automaticamente
- Ação: Marcar como FP no ZAP, documentar
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Reproduziu payload manualmente
- [ ] Analisou resposta HTTP
- [ ] Concluiu com evidências

### ⭐ Importantes
- [ ] Testou múltiplas variações (3+)
- [ ] Consultou código-fonte
- [ ] Explicou tecnicamente POR QUÊ é FP

### 💡 Diferencial
- [ ] Criou teste automatizado que valida proteção
- [ ] Ajustou regra do ZAP para reduzir FPs
- [ ] Documentou no README

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Marcou como FP sem testar"**
**Orientação**: "PROVE que é FP. Mostre screenshots das tentativas falhadas. Sem evidência = não é confiável."

**Erro 2: "Testou apenas payload original"**
**Orientação**: "Atacantes tentam bypasses. Teste ao menos 3-5 variações (img tag, svg, event handlers)."

**Erro 3: "Não explicou POR QUÊ não é vulnerável"**
**Orientação**: "Explique tecnicamente: HTML encoding? Framework protege? CSP bloqueou? Dev precisa entender."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
