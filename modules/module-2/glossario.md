---
layout: page
title: "Glossário - Módulo 2: Testes de Segurança na Prática"
permalink: /modules/testes-seguranca-pratica/glossario/
---

# 📖 Glossário - Módulo 2: Testes de Segurança na Prática

Este glossário contém definições de termos técnicos usados no Módulo 2. Organize por ordem alfabética para facilitar consultas.

---

## A

**API Security**  
Práticas e ferramentas para proteger APIs (Application Programming Interfaces) contra ataques como injection, broken authentication, e excessive data exposure. Inclui autenticação, autorização, rate limiting, e validação de inputs.

**APT (Advanced Persistent Threat)**  
Ataque cibernético sofisticado e prolongado onde atacante obtém acesso não autorizado a sistemas e permanece indetectado por longo período. Geralmente executado por grupos organizados ou nation-states.

**ASVS (Application Security Verification Standard)**  
Framework OWASP que define requisitos de segurança para aplicações web em três níveis de rigor (L1, L2, L3). Usado como checklist em pentests e auditorias.

---

## B

**Baseline Scan**  
Scan de segurança rápido e passivo (DAST) que detecta vulnerabilidades óbvias sem exploração ativa. Tipicamente executado em cada Pull Request (10-15 min). Exemplo: OWASP ZAP baseline.

**Black Box Testing**  
Metodologia de teste onde tester não tem acesso a código-fonte ou documentação interna. Simula ataque externo real. Oposto de White Box Testing.

**BOLA (Broken Object Level Authorization)**  
Vulnerabilidade onde atacante pode acessar objetos de outros usuários modificando IDs em requests. Também chamado de IDOR (Insecure Direct Object Reference). Exemplo: `/api/orders/123` acessível por qualquer usuário.

**Burp Suite**  
Ferramenta comercial de pentesting web (PortSwigger). Intercepta e modifica requests HTTP/HTTPS, fuzzing, scanning de vulnerabilidades. Tem versão Community (gratuita) e Professional (paga).

---

## C

**CI/CD (Continuous Integration / Continuous Deployment)**  
Prática de desenvolvimento onde código é integrado e deployado automaticamente via pipelines. Security testing (SAST, DAST, SCA) é integrado nessas pipelines para shift-left security.

**CodeQL**  
Engine de análise de código estático (SAST) desenvolvido por GitHub. Usa linguagem de query específica para encontrar vulnerabilidades. Gratuito para projetos open-source no GitHub.

**Container Security**  
Práticas de segurança para ambientes containerizados (Docker, Kubernetes). Inclui scanning de imagens (Trivy, Clair), runtime protection, e policies de segurança.

**CVE (Common Vulnerabilities and Exposures)**  
Identificador único para vulnerabilidades de segurança conhecidas publicamente. Formato: CVE-YYYY-NNNNN. Exemplo: CVE-2021-44228 (Log4Shell). Base de dados mantida por MITRE.

**CVSS (Common Vulnerability Scoring System)**  
Sistema padronizado para classificar severidade de vulnerabilidades (0.0 a 10.0). Considera exploitability, impact, e scope. CVSS 9.0-10.0 = Critical, 7.0-8.9 = High, 4.0-6.9 = Medium, 0.1-3.9 = Low.

**CWE (Common Weakness Enumeration)**  
Catálogo de tipos comuns de fraquezas de software. CWEs são categories, CVEs são instances. Exemplo: CWE-89 (SQL Injection), CWE-79 (XSS).

---

## D

**DAST (Dynamic Application Security Testing)**  
Teste de segurança que analisa aplicação em **runtime** (executando), simulando ataques reais sem acesso a código-fonte (black box). Ferramentas: OWASP ZAP, Burp Suite, Acunetix.

**Dependency Scanning**  
Processo automatizado de identificar dependências de terceiros (npm, pip, maven) e detectar CVEs conhecidas. Parte do SCA (Software Composition Analysis).

**DevSecOps**  
Filosofia de integrar segurança em todas as fases do ciclo DevOps. Automação de testes de segurança em CI/CD, shift-left security, security champions nos times.

---

## E

**Exploit**  
Código ou técnica que aproveita vulnerabilidade para comprometer sistema. Pode ser PoC (Proof of Concept) ou weaponized (malicioso). Exemplo: Exploit Log4Shell permite RCE.

**Exploitability**  
Facilidade de explorar uma vulnerabilidade. Classificação comum: Trivial (payloads públicos), Médio (requer conhecimento), Difícil (requer condições específicas). Fator importante para priorização.

---

## F

**False Positive**  
Finding de segurança reportado por ferramenta automatizada que **não é vulnerabilidade real** após validação manual. SAST/DAST tem 15-30% false positive rate típico.

**False Negative**  
Vulnerabilidade **real** que ferramenta automatizada **não detectou**. Mais perigoso que false positive. Pentest manual reduz false negatives.

**Full Scan**  
Scan de segurança completo e ativo (DAST) que testa todas as funcionalidades com exploração ativa. Mais lento (30-60 min) e abrangente que baseline scan. Geralmente executado noturno ou pré-produção.

**Fuzzing**  
Técnica de teste que envia inputs aleatórios ou malformados para encontrar crashes, memory leaks, ou comportamentos inesperados. Usado em SAST, DAST, e pentesting.

---

## G

**GitHub Actions**  
Plataforma de CI/CD nativa do GitHub. Permite automatizar builds, testes, e deploys via workflows YAML. Suporta integração com ferramentas de segurança (SAST, SCA, DAST).

**GitLab CI**  
Plataforma de CI/CD nativa do GitLab. Similar a GitHub Actions. Tem suporte built-in para security scanning (SAST, DAST, SCA, container scanning).

**Gray Box Testing**  
Metodologia de teste onde tester tem acesso **parcial** a código-fonte ou documentação. Combina black box e white box. Comum em pentests reais.

---

## I

**IAST (Interactive Application Security Testing)**  
Híbrido de SAST e DAST. Instrumenta aplicação em runtime para coletar dados de execução. Detecta vulnerabilidades com baixo false positive. Ferramentas: Contrast Security, Hdiv.

**IaC (Infrastructure as Code)**  
Gerenciamento de infraestrutura via código (Terraform, CloudFormation). IaC Security valida configs antes de deploy. Ferramentas: Checkov, Terrascan, tfsec.

**IDOR (Insecure Direct Object Reference)**  
Vulnerabilidade onde atacante acessa objetos de outros usuários modificando IDs. Exemplo: `/api/orders/123` → `/api/orders/124`. Também chamado BOLA. OWASP Top 10 A01:2021.

---

## L

**LGPD (Lei Geral de Proteção de Dados)**  
Lei brasileira (Lei 13.709/2018) que regula tratamento de dados pessoais. Equivalente brasileiro de GDPR. Violações podem gerar multas até R$ 50M ou 2% do faturamento.

**Log4Shell**  
CVE-2021-44228. Vulnerabilidade crítica (CVSS 10.0) em Apache Log4j 2.x que permite RCE (Remote Code Execution) via JNDI injection. Afetou milhares de organizações globalmente em dezembro 2021.

---

## M

**Metasploit**  
Framework open-source de pentesting que contém exploits, payloads, e ferramentas para pós-exploração. Versões: Community (gratuita) e Pro (paga). Usado em pentests para exploitation.

---

## N

**Nikto**  
Scanner de vulnerabilidades open-source para servidores web. Detecta misconfigurations, versões desatualizadas, e vulnerabilidades conhecidas. Rápido mas ruidoso (gera muitos requests).

**Nmap**  
Ferramenta open-source de network scanning. Detecta hosts ativos, portas abertas, serviços, e versões. Fase de Reconnaissance em pentests. Tem NSE scripts para detection de vulnerabilidades.

---

## O

**OWASP (Open Web Application Security Project)**  
Organização sem fins lucrativos focada em segurança de software. Mantém projetos como OWASP Top 10, ZAP, Dependency-Check, e ASVS.

**OWASP Top 10**  
Lista das 10 vulnerabilidades mais críticas em aplicações web, atualizada a cada 3-4 anos. Versão atual: 2021. Inclui: Broken Access Control, Cryptographic Failures, Injection, etc.

**OWASP ZAP (Zed Attack Proxy)**  
Ferramenta open-source de DAST. Intercepta e modifica requests HTTP/HTTPS, fuzzing, baseline/full scans. Alternative gratuito ao Burp Suite Pro.

---

## P

**PCI-DSS (Payment Card Industry Data Security Standard)**  
Padrão de segurança para organizações que processam pagamentos com cartão. Exige testes de segurança contínuos (SAST, DAST, pentest anual).

**Pentest (Penetration Testing)**  
Teste de segurança manual onde pentester simula ataque real para encontrar vulnerabilidades. Combina ferramentas automatizadas com expertise humano. Tipos: Black Box, Gray Box, White Box.

**PoC (Proof of Concept)**  
Demonstração que prova vulnerabilidade é explorável. Geralmente código ou steps to reproduce. Incluso em relatórios de pentest para validação.

**Post-Exploitation**  
Fase de pentest após exploração inicial bem-sucedida. Inclui: privilege escalation, lateral movement, persistence, data exfiltration.

**PTES (Penetration Testing Execution Standard)**  
Framework metodológico para pentests. Define fases: Pre-engagement, Intelligence Gathering, Threat Modeling, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting.

---

## Q

**Quality Gate**  
Critério automatizado em CI/CD que bloqueia merge/deploy se métricas de qualidade/segurança não são atingidas. Exemplo: "Bloquear se Critical ou High vulnerabilities".

---

## R

**RCE (Remote Code Execution)**  
Vulnerabilidade que permite atacante executar código arbitrário no servidor remotamente. Tipicamente CVSS 9.0-10.0. Exemplo: Log4Shell (CVE-2021-44228).

**Reconnaissance**  
Primeira fase de pentest. Coleta de informações sobre alvo: DNS, subdomains, IPs, tecnologias, funcionários. Tipos: Passive (OSINT) e Active (scanning).

**Red Team**  
Time ofensivo que simula ataques avançados (APTs) contra organização. Mais abrangente que pentest tradicional. Inclui social engineering, physical security, evasion.

---

## S

**SAST (Static Application Security Testing)**  
Teste de segurança que analisa **código-fonte** sem executar aplicação (white box). Detecta vulnerabilidades como SQLi, XSS, hardcoded secrets. Ferramentas: SonarQube, Semgrep, CodeQL.

**SBOM (Software Bill of Materials)**  
Inventário completo de dependências de software. Lista componentes, versões, licenças, e supplier. Crítico para resposta rápida a CVEs (ex: Log4Shell). Formatos: CycloneDX, SPDX.

**SCA (Software Composition Analysis)**  
Análise automatizada de dependências de terceiros para detectar CVEs, licenças incompatíveis, e supply chain risks. Ferramentas: Snyk, Dependabot, OWASP Dependency-Check.

**Semgrep**  
Engine open-source de SAST. Usa regras customizáveis (YAML) para detectar patterns de código vulnerável. Rápido, baixo false positive. Mantido por r2c (agora Semgrep Inc).

**Shift-Left Security**  
Filosofia de mover testes de segurança para **fases iniciais** do SDLC. SAST em commits, SCA em PRs, DAST em staging. Detectar vulnerabilidades early é 30x mais barato.

**SLSA (Supply-chain Levels for Software Artifacts)**  
Framework de segurança para supply chain de software. Define 4 níveis de maturidade. Foca em provenance, integrity, e auditability de build artifacts.

**Snyk**  
Plataforma comercial de segurança de desenvolvedores. Oferece SCA, SAST, container scanning, e IaC security. Tem tier gratuito para open-source. Auto-fix de dependências vulneráveis.

**SonarQube**  
Plataforma de análise de qualidade e segurança de código (SAST). Versões: Community (gratuita), Developer, Enterprise. Detecta bugs, code smells, e vulnerabilidades.

**SQLMap**  
Ferramenta open-source de exploitation de SQL Injection. Automatiza detecção e exploitation de SQLi. Dump databases, bypass de autenticação, RCE via SQLi.

**Supply Chain Attack**  
Ataque que compromete software via dependências de terceiros. Exemplos: Event-stream (npm), SolarWinds. Detectável via SCA e SBOM.

---

## T

**Threat Modeling**  
Processo de identificar ameaças potenciais em sistema. Frameworks: STRIDE, PASTA, OCTAVE. Output: lista de ameaças priorizadas e mitigações.

**True Positive**  
Finding de segurança reportado por ferramenta que **é vulnerabilidade real** após validação manual. Oposto de false positive.

**Triage**  
Processo de analisar findings de segurança para determinar: True/False Positive, Severidade Real, Prioridade de Correção. QA Security responsável por triage.

---

## V

**Vulnerability**  
Fraqueza em software que pode ser explorada por atacante para comprometer segurança. Identificada por CVE. Classificada por CVSS.

---

## W

**WAF (Web Application Firewall)**  
Firewall especializado que protege aplicações web filtrando requests HTTP/HTTPS maliciosos. Detecta SQLi, XSS, etc. Exemplos: Cloudflare, AWS WAF, ModSecurity.

**White Box Testing**  
Metodologia de teste onde tester tem **acesso completo** a código-fonte, documentação, e arquitetura. Mais abrangente que black box. Usado em SAST e pentests internos.

---

## X

**XSS (Cross-Site Scripting)**  
Vulnerabilidade que permite atacante injetar JavaScript malicioso em páginas web. Tipos: Reflected, Stored, DOM-based. OWASP Top 10 A03:2021 (Injection).

---

## Z

**Zero-Day (0-day)**  
Vulnerabilidade desconhecida publicamente e sem patch disponível. Exploited "no dia zero" após descoberta. Altamente valiosos para atacantes. Geralmente descobertos por pentest manual.

---

## Números

**0-day**  
Ver Zero-Day acima.

---

**Última atualização**: Janeiro 2026  
**Próxima revisão**: Junho 2026

---

## Como Usar Este Glossário

1. **Durante Aulas**: Use como referência rápida ao encontrar termo desconhecido
2. **Revisão**: Leia seção por seção para fixar conceitos
3. **Exercícios**: Consulte quando precisar relembrar definições
4. **Entrevistas**: Estude termos para preparação de entrevistas técnicas

## Sugestões de Termos

Falta algum termo importante? Contribua via:
- GitHub Issues do repositório
- Formulário de feedback do curso
- Comentários nas aulas

---

[← Voltar para Módulo 2](/modules/testes-seguranca-pratica/)
