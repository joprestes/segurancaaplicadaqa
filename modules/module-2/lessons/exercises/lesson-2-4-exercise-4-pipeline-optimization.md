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

## Contexto

O time está sofrendo com PRs lentas porque o pipeline de segurança é pesado. Você precisa otimizar sem comprometer a cobertura e manter a qualidade dos gates.

## Pré-requisitos

- Acesso ao pipeline CI/CD
- Relatório ou métricas de duração por etapa

## Situação Atual

```yaml
Steps:
1. SAST (SonarQube): 15 min
2. SCA (Snyk): 5 min
3. DAST (ZAP full): 25 min
Total: 45 min
```

## Passo a Passo

1. **Mapear gargalos**
   - Identifique quais etapas são mais lentas e por quê.

2. **Aplicar otimizações**
   - SAST: cache e análise incremental
   - SCA: cache de dependências
   - DAST: baseline em PR, full scan noturno

3. **Validar impacto**
   - Compare tempos antes/depois e confirme cobertura mínima.

**Tarefa**: Otimize:
- SAST: cache, análise incremental
- SCA: cache de dependências
- DAST: baseline em PR, full scan noturno

Meta: <10 min no PR, cobertura mantida.

---

## Validação

- PRs executam em <10 minutos.
- Full scan continua rodando em janela noturna.
- Cobertura de segurança mantida.

## Troubleshooting

- **Cache não funciona**: verifique chave de cache e diretórios corretos.
- **Baseline DAST muito permissivo**: ajuste o threshold ou regras.
- **Aumento de falsos positivos**: revise o perfil do scanner.

## 📤 Enviar Resposta

1. Análise de bottlenecks
2. Otimizações implementadas
3. Antes/depois (45min → Xmin)

{% include exercise-submission-form.html %}

**Duração**: 60 minutos | **Nível**: Avançado ⭐
