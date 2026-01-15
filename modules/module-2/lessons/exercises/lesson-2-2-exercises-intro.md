---
layout: exercise
title: "📹 Vídeo: Introdução aos Exercícios - DAST: Testes Dinâmicos"
slug: "exercises-intro-dast"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Informativo"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercises-intro/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
video:
  file: "assets/module-2/videos/Exercicios_Seguranca-lesson-2-2-exercises-intro.mp4"
  title: "Introdução aos Exercícios - DAST: Testes Dinâmicos"
  description: "Vídeo explicativo sobre os exercícios práticos da aula DAST"
---

## 🎥 Vídeo Explicativo dos Exercícios

Antes de começar os exercícios desta aula, recomendamos assistir ao **vídeo explicativo** que apresenta uma visão geral dos exercícios e explica como aproveitá-los ao máximo.

### 📋 O que este vídeo explica:

- Como os exercícios estão organizados
- O que você vai praticar em cada exercício
- Dicas para aproveitar ao máximo cada exercício
- Como os exercícios se conectam com o conteúdo teórico da aula
- Ferramentas e ambientes necessários

---

## 📚 Exercícios desta Aula

Esta aula conta com **7 exercícios práticos** para consolidar seu aprendizado sobre DAST:

> **📝 Nota Importante**: Os exercícios 1-5 são **obrigatórios** e cobrem os conceitos fundamentais de DAST. Os exercícios 6 e 7 são **opcionais** e focam em cenários específicos (projetos legados e otimização de performance). Se você não trabalha com esses cenários específicos, pode pular os exercícios opcionais sem perder conteúdo essencial.

### 1. Exercício 2.2.1: Configurar OWASP ZAP em Projeto Próprio (Básico)
- **Prática**: Setup completo de OWASP ZAP do zero
- **Objetivo**: Configurar OWASP ZAP, executar primeiro scan dinâmico e analisar resultados
- **Duração estimada**: 45-60 minutos
- **Ferramentas**: Docker, OWASP ZAP, aplicação web para testar

### 2. Exercício 2.2.2: Testes Manuais com Burp Suite (Intermediário)
- **Prática**: Testes manuais de segurança usando Burp Suite
- **Objetivo**: Aprender a usar Burp Suite para interceptar e modificar requisições, executar scans manuais
- **Duração estimada**: 60-90 minutos
- **Ferramentas**: Burp Suite Community Edition

### 3. Exercício 2.2.3: Integrar DAST no CI/CD (Intermediário)
- **Prática**: Integração de ferramentas DAST em pipeline CI/CD
- **Objetivo**: Configurar DAST no GitHub Actions / GitLab CI / Jenkins com Quality Gates
- **Duração estimada**: 60-90 minutos
- **Ferramentas**: GitHub Actions / GitLab CI, OWASP ZAP

### 4. Exercício 2.2.4: Validar e Priorizar Findings DAST (Avançado)
- **Prática**: Processo de triagem e validação de findings DAST
- **Objetivo**: Criar processo de validação de findings, diferenciar false positives de true positives, e priorizar por risco real
- **Duração estimada**: 90-120 minutos
- **Ferramentas**: OWASP ZAP / Burp Suite, ferramentas de tracking (Jira/GitHub Issues)

### 5. Exercício 2.2.5: Comparar Ferramentas DAST (Avançado)
- **Prática**: Comparação de múltiplas ferramentas DAST
- **Objetivo**: Executar diferentes ferramentas DAST no mesmo projeto, comparar resultados e criar relatório comparativo
- **Duração estimada**: 90-120 minutos
- **Ferramentas**: OWASP ZAP, Burp Suite, Acunetix (ou alternativas)

### 6. Exercício 2.2.6: Gerenciar Baseline em Projeto Legado (Intermediário) ⭐ **OPCIONAL**
- **Prática**: Criar e gerenciar baseline de vulnerabilidades
- **Objetivo**: Criar baseline aceito, configurar Quality Gate que permite baseline mas bloqueia novas vulnerabilidades, criar estratégia de redução gradual
- **Duração estimada**: 90-120 minutos
- **Ferramentas**: OWASP ZAP, Python (scripts de validação)
- **Nota**: Este exercício é opcional e focado em cenários específicos (projetos legados). Se você não trabalha com projetos legados, pode pular este exercício.

### 7. Exercício 2.2.7: Otimizar Performance de Scans DAST (Intermediário) ⭐ **OPCIONAL**
- **Prática**: Otimização de performance de scans
- **Objetivo**: Identificar gargalos, aplicar otimizações, medir impacto, validar que cobertura não foi comprometida
- **Duração estimada**: 60-90 minutos
- **Ferramentas**: OWASP ZAP, ferramentas de medição de tempo
- **Nota**: Este exercício é opcional e focado em otimização. Se seus scans já são rápidos (< 10 minutos), pode pular este exercício.

---

## 💡 Dicas para Aproveitar os Exercícios

1. **Assista ao vídeo primeiro**: Entenda a estrutura e objetivos antes de começar
2. **Complete na ordem**: Os exercícios são progressivos e constroem conhecimento incrementalmente
3. **Use aplicação real**: Configure as ferramentas em uma aplicação que você já trabalha ou use aplicação vulnerável de exemplo
4. **Pratique hands-on**: Não apenas leia, mas execute os comandos e configure as ferramentas
5. **Documente seu aprendizado**: Mantenha notas sobre configurações, desafios e soluções encontradas
6. **Experimente diferentes contextos**: Aplique os conceitos em contextos de diferentes setores (financeiro, educacional, ecommerce)
7. **Compartilhe resultados**: Discuta findings com colegas de desenvolvimento

---

## 🛠️ Pré-requisitos e Preparação

Antes de começar os exercícios, certifique-se de ter:

### Ambiente
- [ ] Docker instalado (para OWASP ZAP)
- [ ] Aplicação web para testar (própria ou vulnerável de exemplo)
- [ ] Navegador web configurado
- [ ] Git configurado

### Contas e Tokens
- [ ] Conta no GitHub (para GitHub Actions)
- [ ] Projeto de aplicação web para análise (ou usar OWASP Juice Shop / WebGoat)

### Conhecimento
- [ ] Entendimento básico de Docker
- [ ] Familiaridade com pipelines CI/CD (GitHub Actions / GitLab CI)
- [ ] Conhecimento básico de HTTP/HTTPS
- [ ] Aula 2.2 completada

---

## 📖 Estrutura dos Exercícios

Cada exercício segue a estrutura:

1. **Objetivo**: O que você vai aprender
2. **Descrição**: Contexto e tarefa detalhada
3. **Requisitos**: Passo a passo detalhado
4. **Dicas**: Sugestões para facilitar o trabalho
5. **Validação**: Como verificar se completou corretamente
6. **Próximos Passos**: O que fazer após completar
7. **Formulário de Submissão**: Envie sua solução para feedback

---

## 🎯 Objetivo Geral dos Exercícios

Ao completar todos os exercícios desta aula, você terá:

✅ Configurado OWASP ZAP do zero em uma aplicação real  
✅ Realizado testes manuais com Burp Suite  
✅ Integrado DAST em pipeline CI/CD funcional  
✅ Validado e priorizado findings DAST em projeto real  
✅ Comparado diferentes ferramentas DAST e suas características  
✅ Gerenciado baseline de vulnerabilidades em projeto legado  
✅ Otimizado performance de scans DAST  
✅ Experiência prática com ferramentas DAST mais usadas no mercado  

---

**Duração Total dos Exercícios**: 
- **Exercícios Obrigatórios (1-5)**: ~6-8 horas
- **Exercícios Opcionais (6-7)**: ~2-3 horas adicionais
- **Total (todos)**: ~8-10 horas

**Nível**: Básico a Avançado  
**Pré-requisitos**: Aula 2.2 (DAST: Dynamic Application Security Testing)

---

## 📌 Sobre os Exercícios Opcionais

Os exercícios 6 e 7 são **opcionais** e focam em cenários específicos:

- **Exercício 6 (Baseline)**: Útil se você trabalha com projetos legados que têm muitas vulnerabilidades acumuladas
- **Exercício 7 (Otimização)**: Útil se seus scans DAST são lentos (> 10 minutos) e precisam ser otimizados

**Recomendação**: Complete os exercícios 1-5 primeiro. Se você se deparar com cenários de projeto legado ou necessidade de otimização, então faça os exercícios opcionais.
