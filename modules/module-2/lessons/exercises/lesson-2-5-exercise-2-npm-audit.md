---
layout: exercise
title: "Exercício 2.5.2: npm audit e yarn audit"
slug: "npm-audit"
lesson_id: "lesson-2-5"
module: "module-2"
difficulty: "Básico"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-5-exercise-2-npm-audit/
lesson_url: /modules/testes-seguranca-pratica/lessons/dependency-scanning-sca/
---

## Objetivo

Usar ferramentas nativas (npm audit/yarn audit) para identificar e corrigir vulnerabilidades em dependências Node.js.

---

## Contexto

Você precisa validar rapidamente a segurança de um projeto Node.js antes de um release. O objetivo é usar ferramentas nativas para identificar e tratar riscos.

## Pré-requisitos

- Projeto Node.js com `package.json`
- npm ou yarn instalado localmente

## Passo a Passo

1. **Executar o audit**
   - Rode `npm audit` ou `yarn audit`.

2. **Interpretar o relatório**
   - Identifique severidade e pacotes afetados.

3. **Aplicar correções**
   - Use `npm audit fix` (ou `yarn audit --fix` se suportado).
   - Registre dependências que exigem atualização manual.

## Validação

- Relatório com severidades identificadas.
- Dependências corrigidas automaticamente quando possível.
- Plano para correções manuais pendentes.

## Troubleshooting

- **Audit sem resultados**: valide se o projeto tem dependências instaladas.
- **Fix quebra versão**: avalie o impacto semântico e use branch de teste.

---

## 📤 Enviar Resposta

1. Output completo do audit
2. Plano de correção de vulnerabilidades
3. Evidence de dependências corrigidas

{% include exercise-submission-form.html %}

---

**Duração**: 45 minutos | **Nível**: Básico
