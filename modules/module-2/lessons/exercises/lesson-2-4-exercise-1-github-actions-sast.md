---
layout: exercise
title: "Exercício 2.4.1: Configurar SAST no GitHub Actions"
slug: "github-actions-sast"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Básico"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-4-exercise-1-github-actions-sast/
lesson_url: /modules/testes-seguranca-pratica/lessons/automacao-testes-seguranca/
---

## Objetivo

Configurar análise SAST automatizada usando GitHub Actions com CodeQL para detectar vulnerabilidades em cada push/PR.

---

## Descrição

Crie workflow GitHub Actions que execute SAST automaticamente:
- Configure CodeQL para linguagem do projeto
- Execute análise em pushes na branch main
- Bloqueie PRs com vulnerabilidades Critical

---

## 📤 Enviar Resposta

1. Arquivo `.github/workflows/sast.yml`
2. Screenshot de análise executada
3. Print do Security tab com findings

{% include exercise-submission-form.html %}

---

**Duração**: 45 minutos | **Nível**: Básico
