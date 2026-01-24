---
exercise_id: lesson-2-3-exercise-3-preparar-escopo
title: "Exercício 2.3.3: Preparar Escopo de Pentest"
lesson_id: lesson-2-3
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.3.3: Preparar Escopo de Pentest

## 📋 Enunciado Completo

Empresa contratou pentest externo. Como QA, você deve preparar escopo e ambiente de teste.

### Tarefa
1. Definir escopo (endpoints, funcionalidades, exclusões)
2. Preparar ambiente de teste (staging isolado)
3. Criar credenciais de teste (diferentes níveis de acesso)
4. Documentar regras de engajamento
5. Preparar time interno

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Documento de escopo completo:**
```markdown
## Escopo de Pentest - Q1 2026

### In-Scope
- **URLs**: app.exemplo.com, api.exemplo.com
- **Funcionalidades**: Login, Checkout, Admin Panel
- **Tipos de teste**: Web App, API, Mobile App

### Out-of-Scope
- ❌ Infraestrutura (AWS, servidores)
- ❌ DoS/DDoS attacks
- ❌ Social engineering (phishing, vishing)
- ❌ Ambiente de produção

### Credenciais de Teste
- **User normal**: test_user@exemplo.com / TestPass123!
- **User premium**: test_premium@exemplo.com / PremPass123!
- **Admin**: test_admin@exemplo.com / AdminPass123!

### Regras de Engajamento
- Testes APENAS em staging (staging.exemplo.com)
- Horário: 09:00-18:00 (seg-sex)
- Contato emergência: security@exemplo.com
- Comunicar ANTES de: Port scanning, exploits destrutivos
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Escopo claro (in-scope vs out-of-scope)
- [ ] Credenciais de teste criadas
- [ ] Regras de engajamento definidas

### ⭐ Importantes
- [ ] Ambiente isolado preparado
- [ ] Múltiplos níveis de acesso (user, admin)
- [ ] Contatos de emergência definidos

### 💡 Diferencial
- [ ] Baseline de segurança documentado
- [ ] Kickoff meeting planejado
- [ ] NDA e contratos revisados

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
