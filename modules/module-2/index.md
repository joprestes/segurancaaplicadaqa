---
layout: module
title: "Módulo 2: Testes de Segurança na Prática"
slug: testes-seguranca-pratica
duration: "8 horas"
description: "Aprenda técnicas e ferramentas para testar segurança em aplicações"
lessons: 
  - "lesson-2-1"
  - "lesson-2-2"
  - "lesson-2-3"
  - "lesson-2-4"
  - "lesson-2-5"
module: module-2
permalink: /modules/testes-seguranca-pratica/
---

<!-- # Módulo 2: Testes de Segurança na Prática -->

![Infográfico: Introdução ao Módulo 2 - Testes de Segurança na Prática]({{ '/assets/module-2/images/infograficos/infografico-introducao-modulo-2.png' | relative_url }})

## 🎯 Objetivo do Módulo

Neste módulo, você sai da teoria e mergulha nas ferramentas e técnicas práticas de testes de segurança. Aprenda a usar SAST, DAST, SCA, e até pentest básico para identificar vulnerabilidades em aplicações reais.

## 🛠️ Ferramentas que você vai dominar

### SAST (Static Application Security Testing)
- **SonarQube**: Análise de código e security hotspots
- **Semgrep**: Rules as code para detecção de vulnerabilidades
- **Checkmarx**: Scanning completo de código fonte
- **Bandit** (Python), **Brakeman** (Ruby), **ESLint Security** (JavaScript)

### DAST (Dynamic Application Security Testing)
- **OWASP ZAP**: Scanner de vulnerabilidades web
- **Burp Suite**: Proxy e scanner profissional
- **Acunetix**: Scanner automatizado
- **Nikto**: Scanner de servidores web

### SCA (Software Composition Analysis)
- **Snyk**: Análise de dependências com fix automático
- **Dependabot**: Alertas de vulnerabilidades no GitHub
- **OWASP Dependency-Check**: Scanner open-source
- **npm audit** / **pip-audit**: Scanners nativos

### Pentest Tools
- **Metasploit**: Framework de exploração
- **Nmap**: Scanner de portas e serviços
- **SQLMap**: Exploração de SQL Injection
- **Hydra**: Brute force de autenticação

## 📚 O que você vai aprender

### 1. SAST - Análise Estática
- Como funciona análise estática de código
- Configuração de SonarQube para projetos
- Interpretação de resultados (True/False positives)
- Integração no workflow de desenvolvimento

### 2. DAST - Análise Dinâmica
- Diferença entre SAST e DAST
- Configuração e uso do OWASP ZAP
- Scanning de aplicações em execução
- Testes de API com ferramentas DAST

### 3. Pentest Básico
- Mindset de pentesting para QAs
- Reconhecimento e enumeração
- Exploração básica de vulnerabilidades
- Documentação de findings

### 4. Automação de Testes de Segurança
- Scripts para automação de scans
- Integração com CI/CD
- Agendamento de testes de segurança
- Dashboards de segurança

### 5. Análise de Dependências
- Por que dependências são críticas
- CVEs e vulnerabilidades conhecidas
- Atualização segura de dependências
- Policy enforcement

## 🎓 Competências que você vai desenvolver

Ao final deste módulo, você será capaz de:

✅ Configurar e usar ferramentas SAST em projetos  
✅ Executar scans DAST em aplicações web  
✅ Analisar dependências com ferramentas SCA  
✅ Realizar pentest básico com mindset de segurança  
✅ Automatizar testes de segurança em pipelines  
✅ Interpretar e priorizar vulnerabilidades encontradas  
✅ Colaborar com times de desenvolvimento na correção  

## 📖 Estrutura das Aulas

### Aula 2.1: SAST - Testes Estáticos (90 min)
Mergulhe nos testes estáticos de segurança. Aprenda a usar SonarQube, Semgrep e outras ferramentas.

### Aula 2.2: DAST - Testes Dinâmicos (90 min)
Aprenda testes dinâmicos com OWASP ZAP, Burp Suite. Configure, execute e interprete scans.

### Aula 2.3: Pentest Básico (120 min)
Introdução ao mindset de pentesting. Técnicas básicas de exploração e ferramentas essenciais.

### Aula 2.4: Automação de Testes de Segurança (120 min)
Como automatizar SAST, DAST e SCA em pipelines CI/CD com scripts e integrações.

### Aula 2.5: Dependency Scanning e SCA (90 min)
Aprenda a usar Snyk, Dependabot, OWASP Dependency-Check para análise de dependências.

## 🔬 Laboratórios Práticos

Cada aula inclui exercícios práticos com ambientes de teste:

- **OWASP WebGoat**: Aplicação vulnerável para prática
- **OWASP Juice Shop**: Ecommerce vulnerável moderno
- **DVWA**: Damn Vulnerable Web Application
- **Repositórios de exemplo**: Código com vulnerabilidades intencionais

## 🔗 Conexão com os Próximos Módulos

- **Módulo 3**: Aplicar essas ferramentas em contextos específicos de cada setor
- **Módulo 4**: Integrar essas ferramentas em pipelines DevSecOps

## 📚 Recursos Adicionais

- [OWASP ZAP - Getting Started](https://www.zaproxy.org/getting-started/)
- [SonarQube Security Rules](https://rules.sonarsource.com/)
- [Snyk Documentation](https://docs.snyk.io/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [Burp Suite Learning Path](https://portswigger.net/web-security)

## 💡 Dicas de Estudo

1. **Instale as ferramentas**: SonarQube local, OWASP ZAP, Snyk CLI
2. **Pratique em ambientes seguros**: Use DVWA, WebGoat, Juice Shop
3. **Documente findings**: Crie relatórios de vulnerabilidades encontradas
4. **Experimente integrações**: Conecte ferramentas com GitHub/GitLab

---

**Duração Total do Módulo**: 8 horas  
**Nível**: Intermediário a Avançado  
**Pré-requisitos**: Módulo 1 completo, conhecimento de Git e CI/CD básico
