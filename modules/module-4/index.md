---
layout: module
title: "Módulo 4: Segurança em CI/CD e DevSecOps"
slug: seguranca-cicd-devsecops
duration: "8 horas"
description: "Integre segurança no pipeline de desenvolvimento e deploy"
lessons: 
  - "lesson-4-1"
  - "lesson-4-2"
  - "lesson-4-3"
  - "lesson-4-4"
  - "lesson-4-5"
module: module-4
permalink: /modules/seguranca-cicd-devsecops/
---

# Módulo 4: Segurança em CI/CD e DevSecOps

## 🎯 Objetivo do Módulo

Segurança não pode ser um gargalo no processo de desenvolvimento. Neste módulo, você aprende a integrar segurança em pipelines CI/CD, automatizar testes de segurança, e implementar práticas DevSecOps que tornam segurança parte natural do workflow.

## 🔄 O que é DevSecOps?

```
┌─────────────────────────────────────────────────┐
│  DevOps (ANTES)                                 │
│  Dev → Build → Test → Deploy                    │
│                                                 │
│  DevSecOps (AGORA)                              │
│  Dev → Security → Build → Security → Test →    │
│       SAST           SCA          DAST          │
│  → Security → Deploy → Security                 │
│     IaC Scan         Runtime                    │
└─────────────────────────────────────────────────┘
```

**DevSecOps** = Desenvolvimento + Segurança + Operações

**Princípios**:
- Security as Code (política, configuração, testes)
- Shift Left (segurança desde o início)
- Automação total (scanning automático em cada commit)
- Cultura de responsabilidade compartilhada

## 🛠️ Ferramentas do Ecossistema DevSecOps

### Pipeline CI/CD
- **GitHub Actions**: Workflows com security checks
- **GitLab CI**: Pipeline nativo com SAST/DAST
- **Jenkins**: Plugins de segurança extensivos
- **Azure DevOps**: Security Center integrado

### SAST no Pipeline
- **SonarQube**: Quality gate + security hotspots
- **Semgrep**: Fast, customizable SAST
- **Checkmarx**: Enterprise SAST

### DAST no Pipeline
- **OWASP ZAP**: Scanner automatizado em CI
- **Burp Suite Enterprise**: Continuous scanning
- **StackHawk**: DAST moderno e rápido

### SCA (Dependency Scanning)
- **Snyk**: Integração nativa com Git
- **Dependabot**: Alertas automáticos GitHub
- **WhiteSource Bolt**: SCA grátis para open-source

### Container Security
- **Trivy**: Scanner de vulnerabilidades em containers
- **Clair**: Análise estática de containers
- **Aqua Security**: Plataforma completa

### Secrets Management
- **HashiCorp Vault**: Gerenciamento centralizado
- **AWS Secrets Manager**: Secrets na AWS
- **Azure Key Vault**: Secrets no Azure
- **GitGuardian**: Detecção de secrets em repos

### IaC Security
- **Checkov**: Scanner de Terraform/CloudFormation
- **TFSec**: Security scanner para Terraform
- **Terrascan**: Policy as code para IaC

## 📚 O que você vai aprender

### 1. DevSecOps: Cultura e Práticas
- Fundamentos de DevSecOps
- Como QA se insere no processo
- Métricas de segurança em pipelines
- Cultura de segurança no time

### 2. Pipeline de Segurança Completo
- Arquitetura de pipeline seguro
- Integração de ferramentas SAST/DAST/SCA
- Quality gates de segurança
- Dashboards de segurança

### 3. Container Security
- Docker security best practices
- Scanning de imagens
- Kubernetes security (RBAC, policies)
- Runtime security

### 4. Secrets Management
- Por que secrets em código são críticos
- Ferramentas de gerenciamento
- Rotação automática de secrets
- Detecção de secrets vazados

### 5. Monitoramento e Resposta
- SIEM e logs de segurança
- Alertas de segurança em produção
- Resposta a incidentes
- Post-mortem de segurança

## 🎓 Competências que você vai desenvolver

Ao final deste módulo, você será capaz de:

✅ Implementar pipeline CI/CD com segurança integrada  
✅ Configurar SAST, DAST e SCA em workflows  
✅ Escanear vulnerabilidades em containers  
✅ Gerenciar secrets de forma segura  
✅ Monitorar segurança em produção  
✅ Criar quality gates de segurança  
✅ Automatizar testes de segurança  

## 📖 Estrutura das Aulas

### Aula 4.1: DevSecOps - Cultura e Práticas (90 min)
Entenda a cultura DevSecOps, práticas de segurança como código, e como QA se insere nesse contexto.

### Aula 4.2: Pipeline de Segurança (120 min)
Como montar um pipeline CI/CD com segurança integrada: SAST, DAST, SCA, secret scanning, IaC scanning. Exemplos práticos.

### Aula 4.3: Container Security e Kubernetes (90 min)
Segurança de containers Docker, scanning de vulnerabilidades, segurança em Kubernetes (RBAC, network policies, pod security).

### Aula 4.4: Secrets Management (90 min)
Boas práticas com Vault, AWS/Azure Secrets, detecção de secrets em repositórios.

### Aula 4.5: Monitoramento e Resposta a Incidentes (90 min)
Como monitorar segurança em produção: SIEM, logs, alertas. Processo de resposta a incidentes.

## 🔬 Laboratórios Práticos

### Lab 1: Pipeline GitHub Actions com Segurança
```yaml
name: Security Pipeline
on: [push, pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
  
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Snyk
        uses: snyk/actions/node@master
  
  container-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Build Docker image
        run: docker build -t myapp .
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
```

### Lab 2: Scanning de Container com Trivy
```bash
# Scan de imagem Docker local
trivy image myapp:latest

# Scan com níveis de severidade
trivy image --severity HIGH,CRITICAL myapp:latest

# Scan e falha em vulnerabilidades críticas
trivy image --exit-code 1 --severity CRITICAL myapp:latest
```

### Lab 3: Detecção de Secrets com GitGuardian
```bash
# Scan de repositório Git
ggshield scan repo .

# Scan de commit específico
ggshield scan commit HEAD

# Scan pré-commit (hook)
ggshield scan pre-commit
```

## 💼 Exemplos CWI

### Caso 1: Pipeline Financeiro
```
┌────────────────────────────────────────┐
│ Commit → SAST → SCA → Build →          │
│ Container Scan → Deploy to Staging →   │
│ DAST → PCI-DSS Compliance Check →      │
│ Deploy to Production                   │
└────────────────────────────────────────┘
```

### Caso 2: Pipeline EdTech
```
┌────────────────────────────────────────┐
│ Commit → SAST → SCA → Build →          │
│ LGPD Compliance Check → Deploy Test →  │
│ DAST → Privacy Tests → Production      │
└────────────────────────────────────────┘
```

### Caso 3: Pipeline Ecommerce
```
┌────────────────────────────────────────┐
│ Commit → SAST → SCA → Build →          │
│ Container Scan → Load Test (Security) →│
│ DAST → PCI-DSS Check → Canary Deploy   │
└────────────────────────────────────────┘
```


## 📚 Recursos Adicionais

### DevSecOps
- [DevSecOps Manifesto](https://www.devsecops.org/)
- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)

### Container Security
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)

### Secrets Management
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)

### CI/CD Security
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [GitLab CI/CD Security](https://docs.gitlab.com/ee/user/application_security/)

## 💡 Dicas de Implementação

1. **Comece simples**: Adicione SAST primeiro, depois SCA, depois DAST
2. **Não bloqueie tudo**: Use quality gates progressivos (warn → fail)
3. **Meça tudo**: Tempo de scan, vulnerabilidades encontradas, tempo de correção
4. **Eduque o time**: Explique por que cada ferramenta está lá
5. **Automatize correções**: Use ferramentas que criam PRs automáticos

---

**Duração Total do Módulo**: 8 horas  
**Nível**: Avançado  
**Pré-requisitos**: Módulos 1, 2 e 3 completos, conhecimento de CI/CD
