---
exercise_id: lesson-2-3-exercise-4-incident-postmortem
title: "Exercício 2.3.4: Post-Mortem de Incidente de Segurança"
lesson_id: lesson-2-3
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.3.4: Post-Mortem de Incidente de Segurança

## 📋 Enunciado Completo

**Cenário**: Hacker explorou SQL Injection em produção, acessou 50K registros de clientes. Criar post-mortem blameless.

### Tarefa
1. Timeline do incidente (descoberta, resposta, resolução)
2. Root cause analysis (como passou despercebido?)
3. Action items (preventivos e detectivos)
4. Lições aprendidas
5. Apresentação para liderança

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Post-mortem blameless:**
```markdown
## Post-Mortem: SQL Injection Incident - Janeiro 2026

### Timeline
- **14:23**: Alerta automático (Cloudflare detectou padrão suspeito)
- **14:35**: Security team confirmou exploit ativo
- **14:45**: Aplicação colocada em modo manutenção
- **15:20**: Patch deployado, aplicação restaurada
- **16:00**: Auditoria de logs (50K registros acessados)

### Root Cause
SQLi no endpoint `/api/search` (PR #1234, deployado 2 semanas atrás).

**Por que passou despercebido?**
1. SonarQube não detectou (regra desabilitada)
2. Code review não pegou (reviewer focou em funcionalidade)
3. Testes unitários não cobriam segurança

### Action Items

**Preventivo** (não deixar acontecer de novo):
- [ ] Re-ativar regras SQLi no SonarQube
- [ ] Security checklist obrigatório em code review
- [ ] Testes de segurança automatizados (Semgrep no CI/CD)

**Detectivo** (detectar mais rápido):
- [ ] WAF rules para SQL injection patterns
- [ ] Alertas em tempo real (Slack)
- [ ] Monitoramento de anomalias (DataDog)

### Lições Aprendidas
1. **Defesa em camadas funciona**: WAF detectou mesmo com código vulnerável
2. **Automação é essencial**: Humanos erram, ferramentas não dormem
3. **Velocidade importa**: 57 minutos do alerta ao patch (meta: < 2h)

### Comunicação
- **Clientes afetados**: Email enviado (transparência)
- **Regulador (LGPD)**: Notificação em 72h (conforme lei)
- **Board**: Apresentação executiva agendada
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Timeline preciso do incidente
- [ ] Root cause identificado
- [ ] Action items definidos

### ⭐ Importantes
- [ ] Análise profunda (não superficial)
- [ ] Blameless (foca em processo, não pessoas)
- [ ] Preventivo E detectivo

### 💡 Diferencial
- [ ] Apresentação executiva clara
- [ ] Comunicação com clientes/reguladores
- [ ] Métricas de melhoria

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Culpou desenvolvedor"**
**Orientação**: "Post-mortem é BLAMELESS. Foque em PROCESSO que falhou, não pessoa. Pergunta certa: 'Como nosso processo permitiu isso?' não 'Quem errou?'"

**Erro 2: "Action items vagos"**
**Orientação**: "Action item específico: 'Configurar Semgrep no CI/CD até 31/Jan' > 'Melhorar segurança'. Acionável, com responsável e prazo."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
