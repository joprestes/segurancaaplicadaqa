---
layout: exercise
title: "📹 Vídeo: Introdução aos Exercícios - SAST: Testes Estáticos"
slug: "exercises-intro-sast"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Informativo"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-1-exercises-intro/
lesson_url: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
video:
  file: "assets/module-2/videos/Exercicios_Seguranca-lesson-2-1-exercises-intro.mp4"
  title: "Introdução aos Exercícios - SAST: Testes Estáticos"
  description: "Vídeo explicativo sobre os exercícios práticos da aula SAST"
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

Esta aula conta com **5 exercícios práticos** para consolidar seu aprendizado sobre SAST:

### 1. Exercício 2.1.1: Configurar SonarQube em Projeto Próprio (Básico)
- **Prática**: Setup completo de SonarQube do zero
- **Objetivo**: Configurar SonarQube em projeto existente, executar primeiro scan e analisar resultados
- **Duração estimada**: 45-60 minutos
- **Ferramentas**: Docker, SonarQube Community Edition, SonarScanner

### 2. Exercício 2.1.2: Criar Regras Customizadas Semgrep (Intermediário)
- **Prática**: Criação de regras Semgrep personalizadas
- **Objetivo**: Identificar padrões inseguros no seu código e criar regras Semgrep para detectá-los
- **Duração estimada**: 60-90 minutos
- **Ferramentas**: Semgrep CLI, YAML editor

### 3. Exercício 2.1.3: Integrar SAST no CI/CD (Intermediário)
- **Prática**: Integração de ferramentas SAST em pipeline CI/CD
- **Objetivo**: Configurar SAST no GitHub Actions / GitLab CI / Jenkins com Quality Gates
- **Duração estimada**: 60-90 minutos
- **Ferramentas**: GitHub Actions / GitLab CI, SonarQube, Semgrep

### 4. Exercício 2.1.4: Validar e Priorizar Findings SAST (Avançado)
- **Prática**: Processo de triagem e validação de findings
- **Objetivo**: Criar processo de validação de findings, diferenciar false positives de true positives, e priorizar por risco real
- **Duração estimada**: 90-120 minutos
- **Ferramentas**: SonarQube / Semgrep, ferramentas de tracking (Jira/GitHub Issues)

### 5. Exercício 2.1.5: Comparar Ferramentas SAST (Avançado)
- **Prática**: Comparação de múltiplas ferramentas SAST
- **Objetivo**: Executar diferentes ferramentas SAST no mesmo projeto, comparar resultados e criar relatório comparativo
- **Duração estimada**: 90-120 minutos
- **Ferramentas**: SonarQube, Semgrep, Checkmarx (ou alternativas), Bandit (se Python)

---

## 💡 Dicas para Aproveitar os Exercícios

1. **Assista ao vídeo primeiro**: Entenda a estrutura e objetivos antes de começar
2. **Complete na ordem**: Os exercícios são progressivos e constroem conhecimento incrementalmente
3. **Use projeto real**: Configure as ferramentas em um projeto que você já trabalha
4. **Pratique hands-on**: Não apenas leia, mas execute os comandos e configure as ferramentas
5. **Documente seu aprendizado**: Mantenha notas sobre configurações, desafios e soluções encontradas
6. **Experimente diferentes contextos**: Aplique os conceitos em contextos de diferentes setores (financeiro, educacional, ecommerce)
7. **Compartilhe resultados**: Discuta findings com colegas de desenvolvimento

---

## 🛠️ Pré-requisitos e Preparação

Antes de começar os exercícios, certifique-se de ter:

### Ambiente
- [ ] Docker instalado (para SonarQube)
- [ ] Python 3.8+ instalado (para Semgrep, Bandit)
- [ ] Node.js instalado (se projeto Node.js)
- [ ] Java JDK instalado (se projeto Java)
- [ ] Git configurado

### Contas e Tokens
- [ ] Conta no GitHub (para GitHub Actions)
- [ ] Token de acesso ao SonarQube (quando necessário)
- [ ] Projeto de código-fonte para análise

### Conhecimento
- [ ] Entendimento básico de Docker
- [ ] Conhecimento básico de YAML (para Semgrep rules)
- [ ] Familiaridade com pipelines CI/CD (GitHub Actions / GitLab CI)
- [ ] Aula 2.1 completada

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

✅ Configurado SonarQube do zero em um projeto real  
✅ Criado regras customizadas Semgrep para padrões específicos  
✅ Integrado SAST em pipeline CI/CD funcional  
✅ Validado e priorizado findings SAST em projeto real  
✅ Comparado diferentes ferramentas SAST e suas características  
✅ Experiência prática com ferramentas SAST mais usadas no mercado  

---

**Duração Total dos Exercícios**: ~6-8 horas  
**Nível**: Básico a Avançado  
**Pré-requisitos**: Aula 2.1 (SAST: Static Application Security Testing)
