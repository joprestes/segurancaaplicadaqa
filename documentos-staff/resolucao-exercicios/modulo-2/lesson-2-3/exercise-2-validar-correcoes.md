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

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
