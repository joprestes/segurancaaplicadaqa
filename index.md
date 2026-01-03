---
layout: default
title: Início
---

# Bem-vindo ao Angular Expert 5 Dias

Treinamento intensivo e prático de Angular projetado para levar desenvolvedores do nível básico ao expert em apenas 5 dias.

## Módulos do Curso

{% for module in site.data.modules %}
### {{ module.order }}. {{ module.title }}

**Duração**: {{ module.duration }}  
**Descrição**: {{ module.description }}

[Acessar módulo →]({{ '/modules/' | append: module.slug | relative_url }})

{% endfor %}

## Sobre o Curso

Este curso utiliza uma metodologia prática e orientada ao framework, onde você aprende Angular usando Angular. Cada conceito é aprendido através de implementação imediata, com projetos que crescem em complexidade ao longo do curso.

