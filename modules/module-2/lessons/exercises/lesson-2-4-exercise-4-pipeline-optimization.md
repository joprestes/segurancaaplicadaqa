---
layout: exercise
title: "Exercício 2.4.9: Otimização de Pipeline Lento"
slug: "pipeline-optimization"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Avançado ⭐"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-4-exercise-9-pipeline-optimization/
lesson_url: /modules/testes-seguranca-pratica/lessons/automacao-testes-seguranca/
---

## Objetivo

Pipeline demora 45 minutos. Devs reclamando. Meta: reduzir para <10 min sem perder cobertura.

---

## Situação Atual

```yaml
Steps:
1. SAST (SonarQube): 15 min
2. SCA (Snyk): 5 min
3. DAST (ZAP full): 25 min
Total: 45 min
```

**Tarefa**: Otimize:
- SAST: cache, análise incremental
- SCA: cache de dependências
- DAST: baseline em PR, full scan noturno

Meta: <10 min no PR, cobertura mantida.

---

## 📤 Enviar Resposta

1. Análise de bottlenecks
2. Otimizações implementadas
3. Antes/depois (45min → Xmin)

{% include exercise-submission-form.html %}

**Duração**: 60 minutos | **Nível**: Avançado ⭐
