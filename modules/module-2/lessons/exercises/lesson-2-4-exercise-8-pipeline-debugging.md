---
layout: exercise
title: "Exercício 2.4.8: Debugging de Pipeline de Segurança"
slug: "pipeline-debugging"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-4-exercise-8-pipeline-debugging/
lesson_url: /modules/testes-seguranca-pratica/lessons/automacao-testes-seguranca/
---

## Objetivo

Pipeline quebrou após adicionar quality gate de segurança. Devs estão bloqueados há 3 horas. Sua missão: analisar logs, identificar causa raiz, corrigir rapidamente mantendo segurança.

Ao completar este exercício, você será capaz de:

- Debugar pipelines CI/CD quando quality gates falham
- Analisar logs de ferramentas SAST/DAST/SCA
- Identificar causa raiz de falhas (config vs vulnerabilidade real)
- Corrigir rapidamente sem comprometer segurança

---

## Descrição

**Cenário**: Pipeline GitHub Actions quebrou em todas as PRs. Quality gate de segurança está falhando. Devs não conseguem mergear nada. CTO está pressionando.

**Contexto**:
- Pipeline tem: SAST (SonarQube) + SCA (Snyk) + DAST (ZAP baseline)
- Quality Gate: Bloquear se Critical ou High
- Funcionava semana passada, quebrou hoje

### Tarefas

1. Analisar logs do pipeline
2. Identificar qual step está falhando
3. Determinar se é config ou vulnerabilidade real
4. Corrigir mantendo segurança
5. Validar que pipeline volta a funcionar

---

## Logs do Pipeline

```yaml
Step: SAST (SonarQube)
❌ FAILED
ERROR: Quality Gate failed: 1 Critical vulnerability found
- File: src/utils/crypto.js:23
- Rule: Weak Cryptography (MD5)
- CVSS: 9.1

Step: SCA (Snyk)
⏭️ SKIPPED (previous step failed)

Step: DAST (ZAP)
⏭️ SKIPPED (previous step failed)
```

### Investigação

**Tarefa 1**: Código flagado (crypto.js:23):
```javascript
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');
```

**Pergunta**: É vulnerabilidade real ou uso legítimo?

**Tarefa 2**: Decisões possíveis:
- Opção A: Corrigir agora (usar bcrypt)
- Opção B: Marcar como exceção documentada (se uso legítimo)
- Opção C: Baixar severidade no SonarQube
- Opção D: Desabilitar quality gate (NÃO RECOMENDADO)

**Tarefa 3**: Implemente correção escolhida e valide pipeline.

---

## 📤 Enviar Resposta

1. Análise de logs
2. Causa raiz identificada
3. Decisão tomada (com justificativa)
4. Correção implementada
5. Screenshot de pipeline verde ✅

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 30-45 minutos  
**Nível**: Intermediário
