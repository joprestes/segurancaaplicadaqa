---
layout: exercise
title: "Exercício 2.3.8: Post-Mortem de Incidente de Segurança"
slug: "incident-postmortem"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Avançado ⭐⭐"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-3-exercise-8-incident-postmortem/
lesson_url: /modules/testes-seguranca-pratica/lessons/pentest-basico/
---

## Objetivo

XSS descoberto em produção por cliente. Realizar RCA (Root Cause Analysis), identificar gaps de processo e propor melhorias.

---

## Cenário

Cliente reportou: "Consegui executar JavaScript na página de checkout e acessar cookies de outros usuários."

**Fatos**:
- SAST rodou: não detectou
- DAST rodou: não detectou  
- Pentest há 6 meses: não testou checkout (fora de escopo)
- Código passou code review

**Tarefa**: Conduza post-mortem sem blame:
1. Timeline do incidente
2. Root cause (não "dev errou", mas "processo falhou onde")
3. Gaps identificados
4. Action items (SMART goals)

---

## 📤 Enviar Resposta

1. Relatório post-mortem completo
2. RCA (5 Whys)
3. Action items priorizados

{% include exercise-submission-form.html %}

**Duração**: 90 minutos | **Nível**: Avançado ⭐⭐
