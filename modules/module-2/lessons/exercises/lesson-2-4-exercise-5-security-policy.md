---
layout: exercise
title: "Exercício 2.4.5: Criar Política de Segurança Executável"
slug: "security-policy"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Avançado ⭐⭐"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-4-exercise-5-security-policy/
lesson_url: /modules/testes-seguranca-pratica/lessons/automacao-testes-seguranca/
---

## Objetivo

Você é Security Champion. Criar política de segurança executável: quality gates, SLAs por severidade, processo de exceções.

---

## Contexto

O time precisa de uma política clara para decidir quando bloquear merge, quando abrir exceção e quais SLAs de correção aplicar. O objetivo é tornar regras executáveis e auditáveis.

## Pré-requisitos

- Conhecimento básico de severidades (Critical/High/Medium/Low)
- Familiaridade com pipeline CI/CD e regras de aprovação

## Passo a Passo

1. **Definir Quality Gates**
   - Estabeleça critérios objetivos por severidade.

2. **Definir processo de exceções**
   - Quem aprova, quais evidências são obrigatórias, e periodicidade de revisão.

3. **Definir SLAs**
   - Prazo de correção por severidade e por tipo de vulnerabilidade.

4. **Documentar e padronizar**
   - Crie templates para exceções e escalonamento.

## Tarefa

Documente:
```markdown
1. Quality Gates
   - Critical: Bloqueia merge (SLA: 4h correção)
   - High: Warning (SLA: 48h correção)
   - Medium: Informacional (SLA: 1 sprint)

2. Processo de Exceções
   - Quem pode aprovar
   - Documentação obrigatória
   - Re-análise periódica

3. SLAs de Correção
   - Por severidade
   - Por tipo de vulnerabilidade
   - Escalation path
```

---

## Validação

- A política é clara, objetiva e executável.
- Há critérios mensuráveis para bloquear/permitir merges.
- Existe fluxo de exceções com evidências obrigatórias.

## Troubleshooting

- **Regras subjetivas**: transforme em critérios numéricos (ex.: Critical > 0).
- **Exceções sem controle**: exija aprovação e revisão periódica.
- **SLAs inconsistentes**: alinhe com risco e exposição.

## 📤 Enviar Resposta

1. Política completa documentada
2. Workflow diagram
3. Templates de exceção

{% include exercise-submission-form.html %}

**Duração**: 90 minutos | **Nível**: Avançado ⭐⭐
