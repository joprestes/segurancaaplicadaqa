---
layout: exercise
title: "Exercício 2.4.3: Implementar Quality Gates de Segurança"
slug: "quality-gates"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-4-exercise-3-quality-gates/
lesson_url: /modules/testes-seguranca-pratica/lessons/automacao-testes-seguranca/
---

## Objetivo

Criar Quality Gates que bloqueiam deploys quando vulnerabilidades críticas são detectadas, com exceções controladas.

---

## Contexto

O time quer balancear velocidade e risco. O objetivo é definir regras claras que automatizem bloqueios e permitam exceções documentadas.

## Pré-requisitos

- Pipeline CI/CD com pelo menos um scanner de segurança (SAST/DAST/SCA)
- Acesso para editar regras de branch e checks obrigatórios

## Passo a Passo

1. **Definir regras de Quality Gates**
   - Critical/High: bloqueiam automaticamente.
   - Medium: liberado com aprovação manual.

2. **Implementar no pipeline**
   - Configure o job para falhar quando o gate for violado.
   - Adicione output claro com severidade e contagem.

3. **Configurar notificações**
   - Envie alerta para o canal correto (email/Slack).

4. **Simular violação**
   - Rode o pipeline com findings críticos para validar o bloqueio.

## Validação

- Pipeline bloqueia com Critical/High > 0.
- Medium exige aprovação manual.
- Notificações são disparadas com contexto.

## Troubleshooting

- **Gate não bloqueia**: verifique condição de falha do job.
- **Notificação não chega**: revise webhook e permissões.
- **Dados inconsistentes**: normalize formato do relatório do scanner.

---

## 📤 Enviar Resposta

1. Configuração de Quality Gates
2. Evidência de build bloqueado
3. Documentação das regras

{% include exercise-submission-form.html %}

---

**Duração**: 60 minutos | **Nível**: Intermediário
