---
layout: default
title: Início
---

# Segurança Aplicada à Qualidade de Software

![Infográfico: Visão Geral do Curso - Segurança Aplicada à Qualidade de Software]({{ '/assets/images/infografico-inicio.png' | relative_url }})

Treinamento prático e focado em segurança para profissionais de QA da CWI. Aprenda a integrar segurança no processo de qualidade, com exemplos reais de projetos em diferentes setores: financeiro, educacional, ecommerce e IA.

## 🎯 O que você vai aprender

- **Fundamentos de Segurança**: OWASP Top 10, threat modeling, compliance (LGPD, PCI-DSS)
- **Ferramentas e Técnicas**: SAST, DAST, dependency scanning, pentest básico
- **Segurança por Setor**: Requisitos específicos para financeiro, educacional, ecommerce e IA
- **DevSecOps**: Integração de segurança em pipelines CI/CD

## 📚 Módulos do Curso

{% for module in site.data.modules.modules %}
### {{ module.order }}. {{ module.title }}

**Duração**: {{ module.duration }}  
**Descrição**: {{ module.description }}

[Acessar módulo →]({{ '/modules/' | append: module.slug | relative_url }})

{% endfor %}

## 💼 Contexto CWI

Este curso foi desenvolvido especificamente para profissionais de QA alocados em clientes CWI de diversos segmentos. Você aprenderá não apenas teoria, mas como aplicar segurança no dia a dia dos projetos, com exemplos práticos e contextualizados.

### Setores Cobertos

- **🏦 Financeiro**: Open Banking, PCI-DSS, autenticação forte
- **📚 Educacional**: LGPD para menores, proteção de dados sensíveis
- **🛒 Ecommerce**: Prevenção de fraudes, segurança de pagamentos
- **🤖 IA**: Adversarial attacks, model poisoning, data leakage

## 🚀 Por que Segurança em QA?

Segurança não é responsabilidade exclusiva de DevOps ou times especializados. Como profissional de QA, você está em posição única para identificar vulnerabilidades cedo, prevenir problemas de segurança e garantir que os produtos entregues sejam não apenas funcionais, mas também seguros.

