---
layout: exercise
title: "Exercício 2.2.9: Análise de Relatório DAST Completo"
slug: "dast-report-analysis"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-9-dast-report-analysis/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

## Objetivo

Relatório DAST com 47 findings (3 Critical, 12 High, 32 Medium). Priorizar top 5, identificar 3 FPs, criar plano de remediação.

---

## Contexto

Você recebeu um relatório grande de DAST e precisa transformar dados brutos em decisões de correção com impacto real.

## Pré-requisitos

- Conhecimento básico de severidade e risco
- Familiaridade com DAST e validação manual

---

## Passo a Passo

**Findings Critical:**
1. SQL Injection em /api/users (CVSS 9.8)
2. RCE em /upload (CVSS 10.0)
3. Auth Bypass em /admin (CVSS 9.1)

**Pergunta**: São todos true positives? Como validar?

**Deliverables**:
1. Top 5 priorizados por risco REAL
2. 3 false positives identificados (com justificativa)
3. Plano de remediação (timeline + responsáveis)

---

## Validação

- Top 5 priorizados com justificativa clara
- 3 possíveis false positives analisados e documentados
- Plano de remediação com prazos e responsáveis

## Troubleshooting

- **Difícil validar**: reproduza manualmente com payloads alternativos
- **Sem contexto**: peça apoio do time para entender o fluxo do endpoint

---

## 📤 Enviar Resposta

1. Relatório de análise
2. Priorização justificada
3. Plano de remediação

{% include exercise-submission-form.html %}

**Duração**: 60 minutos | **Nível**: Intermediário
