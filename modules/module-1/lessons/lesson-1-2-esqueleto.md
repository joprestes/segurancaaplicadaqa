---
layout: lesson
title: "Aula 1.2: OWASP Top 10 e Principais Vulnerabilidades"
slug: owasp-top-10
module: module-1
lesson_id: lesson-1-2
duration: "90 minutos"
level: "Básico"
prerequisites: ["lesson-1-1"]
exercises: []
podcast:
  file: "assets/podcasts/1.2-OWASP_Top_10.m4a"
  image: "assets/images/podcasts/1.2-OWASP_Top_10.png"
  title: "OWASP Top 10 - Vulnerabilidades que Todo QA Deve Conhecer"
  description: "Análise detalhada das 10 principais vulnerabilidades de segurança web segundo OWASP"
  duration: "60-75 minutos"
permalink: /modules/fundamentos-seguranca-qa/lessons/owasp-top-10/
---

# Aula 1.2: OWASP Top 10 e Principais Vulnerabilidades

## 🎯 Objetivos

- Conhecer as 10 principais vulnerabilidades web (OWASP Top 10 2021)
- Entender como cada vulnerabilidade funciona
- Aprender a identificá-las em testes
- Saber como prevenir cada tipo

## 📚 OWASP Top 10 - 2021

### 1. Broken Access Control

Controle de acesso quebrado permite usuários acessarem recursos não autorizados.

**Exemplos**:
- Modificar URL para acessar dados de outro usuário
- Elevar privilégios sem autorização
- Forçar navegação para páginas protegidas

**Como testar**:
- Tentar acessar recursos de outros usuários
- Testar endpoints sem autenticação
- Validar controles de autorização

### 2. Cryptographic Failures

Falhas em proteger dados sensíveis com criptografia adequada.

**Exemplos**:
- Senhas armazenadas em texto plano
- Dados transmitidos sem HTTPS
- Algoritmos de criptografia fracos

### 3. Injection

Injeção de código malicioso em consultas ou comandos.

**Tipos principais**:
- SQL Injection
- NoSQL Injection
- LDAP Injection
- OS Command Injection

### 4. Insecure Design

Falhas de design de segurança desde a concepção.

### 5. Security Misconfiguration

Configurações de segurança inadequadas ou padrão.

### 6. Vulnerable and Outdated Components

Uso de bibliotecas com vulnerabilidades conhecidas.

### 7. Identification and Authentication Failures

Falhas em autenticação e gerenciamento de sessão.

### 8. Software and Data Integrity Failures

Falhas em validar integridade de código e dados.

### 9. Security Logging and Monitoring Failures

Falta de logs e monitoramento adequado.

### 10. Server-Side Request Forgery (SSRF)

Servidor faz requisições não autorizadas.

## 💼 Aplicação Prática

Cada vulnerabilidade deve ser testada em contexto CWI:
- Como identificar em projetos financeiros
- Como validar em plataformas educacionais
- Como prevenir em ecommerce

## 🎯 Exercícios

1. Identificar vulnerabilidades em código de exemplo
2. Criar casos de teste para cada tipo
3. Documentar como mitigar cada vulnerabilidade

## 📖 Referências

- [OWASP Top 10 - 2021](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
