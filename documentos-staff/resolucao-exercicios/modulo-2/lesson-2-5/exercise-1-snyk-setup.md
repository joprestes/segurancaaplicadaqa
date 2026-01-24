---
exercise_id: lesson-2-5-exercise-1-snyk-setup
title: "Exercício 2.5.1: Snyk Setup e Scan"
lesson_id: lesson-2-5
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.5.1: Configurar Snyk e Escanear Dependências

## 📋 Enunciado
Configure Snyk para monitorar vulnerabilidades em dependências do projeto.

### Requisitos
1. Conta Snyk criada e conectada ao Git
2. Scan de dependências executado
3. Relatório interpretado (vulnerabilidades encontradas)
4. Pelo menos 1 vulnerabilidade corrigida

---

## ✅ Solução Completa

### 1. Setup Snyk CLI

```bash
# Instalar Snyk CLI
npm install -g snyk

# Autenticar (abre browser)
snyk auth

# Testar autenticação
snyk test --help
```

### 2. Scan de Dependências

```bash
# Projeto Node.js
cd meu-projeto
npm install  # Garante package-lock.json atualizado

# Scan de vulnerabilidades
snyk test

# Output esperado:
Testing /Users/dev/meu-projeto...

✗ High severity vulnerability found in express
  Description: Open Redirect
  Info: https://snyk.io/vuln/SNYK-JS-EXPRESS-5842117
  Introduced through: express@4.17.1
  From: express@4.17.1
  Fixed in: express@4.17.3
  
✗ Medium severity vulnerability found in lodash
  Description: Prototype Pollution
  Info: https://snyk.io/vuln/SNYK-JS-LODASH-590103
  Introduced through: lodash@4.17.19
  From: lodash@4.17.19
  Fixed in: lodash@4.17.21

Organization: seu-nome
Tested 245 dependencies for known issues, found 2 issues, 2 vulnerable paths.
```

### 3. Analisar Relatório

**Interpretação:**

1. **Severidade**:
   - Critical (🔴): Exploração remota fácil
   - High (🟠): Impacto alto, exploração possível
   - Medium (🟡): Impacto moderado
   - Low (🟢): Baixo risco

2. **Informações-chave**:
   - **Description**: Tipo de vulnerabilidade
   - **Introduced through**: Dependência afetada
   - **Fixed in**: Versão que corrige
   - **CVE/CWE**: Identificação padrão

### 4. Corrigir Vulnerabilidades

```bash
# Opção 1: Atualizar automaticamente (se patch disponível)
snyk wizard

# Snyk guiará você:
? Update lodash to 4.17.21 (fixes 1 vuln)? Yes
? Ignore express@4.17.1 (until 2024-12-31)? No
? Update express to 4.17.3? Yes

# Opção 2: Manual
npm install express@4.17.3
npm install lodash@4.17.21

# Verificar se corrigiu
snyk test

# Output:
✓ Tested 245 dependencies for known issues, no vulnerable paths found.
```

### 5. Integrar ao GitHub (CI/CD)

```yaml
# .github/workflows/snyk.yml
name: Snyk Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      - name: Upload result to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: snyk.sarif
```

### 6. Monitoramento Contínuo

```bash
# Conectar projeto ao Snyk para monitoramento 24/7
snyk monitor

# Snyk agora:
# 1. Monitora vulnerabilidades novas (CVEs publicados)
# 2. Envia alertas por email/Slack
# 3. Dashboard: https://app.snyk.io/org/seu-org/projects
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **SCA (Software Composition Analysis)**: Análise de dependências de terceiros
2. **CVE**: Common Vulnerabilities and Exposures (identificador padrão)
3. **Transitive Dependencies**: Dependências das dependências
4. **Patch Management**: Processo de atualização de dependências

### Erros Comuns

**Erro 1: "Snyk encontrou 0 vulnerabilidades (mas sei que tem)"**
- **Causa**: Scan sem `package-lock.json` (versões não resolvidas)
- **Feedback**: "Snyk precisa de lockfile (package-lock.json, yarn.lock, pom.xml, etc) para análise precisa. Sem lockfile, Snyk assume versões mais recentes. Execute `npm install` para gerar lockfile e scaneie novamente."

**Erro 2: "Ignorou todas as vulnerabilidades (não corrigiu nenhuma)"**
- **Causa**: Usou `snyk ignore` em tudo
- **Feedback**: "Ignore é para false positives ou vulnerabilidades sem patch disponível (temporariamente). Ignorar tudo = não resolveu o problema. Para High/Critical: SEMPRE tente atualizar primeiro. Ignore apenas se: 1) Não afeta seu uso, 2) Sem patch disponível, 3) Documentou justificativa."

**Erro 3: "Atualizou dependência → app quebrou"**
- **Causa**: Breaking change em major version (ex: express 4 → 5)
- **Feedback**: "Antes de atualizar: 1) Leia CHANGELOG da lib (breaking changes?), 2) Teste localmente (npm test), 3) Se major version, considere alternativas (ex: trocar lib). Segurança importante, mas disponibilidade também. Sempre teste após update."

**Erro 4: "Vulnerabilidade em dependência de dev (devDependencies)"**
- **Causa**: Não distingue runtime vs dev dependencies
- **Feedback**: "Snyk mostra todas as deps. Priorize: runtime > dev. Vulnerabilidade em `webpack` (dev) tem risco menor que em `express` (runtime). Se for dev: pode ignorar ou atualizar com menos urgência. Focus: o que vai para produção."

**Erro 5: "Relatório mostra 200 vulnerabilidades (paralisou)"**
- **Causa**: Projeto antigo sem manutenção de dependências
- **Feedback**: "Priorize por severidade: 1) Critical/High primeiro, 2) Medium depois, 3) Low quando tiver tempo. Comece por 1 dependência de cada vez (não todas juntas). Use `--severity-threshold=high` no CI (bloqueia apenas críticas). Débito técnico se paga incrementalmente."

**Erro 6: "Não integrou ao CI (scan manual apenas)"**
- **Causa**: Usou Snyk CLI localmente mas não automatizou
- **Feedback**: "Scan manual = inconsistente (dev esquece). Integre ao CI: GitHub Actions, GitLab CI, etc. Snyk roda em cada PR → bloqueia se nova vulnerabilidade. Automação é essencial para escala."

### Feedback Construtivo

**Para configuração profissional:**
> "Excelente setup! Snyk integrado ao CI, monitoramento ativo, vulnerabilidades corrigidas. Próximo nível: 1) Snyk Container (imagens Docker), 2) Snyk IaC (Terraform/K8s), 3) Policy as Code (threshold customizado por projeto), 4) SLA de remediação (Critical em 7 dias, High em 30 dias)."

**Para configuração básica:**
> "Bom início! Snyk rodando e vulnerabilidades identificadas. Para melhorar: 1) Automatize no CI (não apenas local), 2) Configure monitoramento contínuo (`snyk monitor`), 3) Estabeleça processo de correção (quem, quando, como), 4) Documente justificativas de ignore. Ferramenta configurada, agora processo."

**Para dificuldades:**
> "SCA pode ser overwhelmed no início (muitas vulnerabilidades). Comece simples: 1) Snyk CLI local (entenda output), 2) Corrija 1-2 vulnerabilidades High (aprenda processo), 3) Adicione ao CI (automatize), 4) Expanda para outros projetos. Um passo de cada vez."

### Contexto Pedagógico Completo

**Por que é fundamental:**
- **83% das aplicações** têm vulnerabilidades em dependências (Veracode 2023)
- **Supply Chain Attacks**: Atacar lib popular afeta milhares de apps (ex: Log4Shell 2021)
- **Compliance**: SOC2, PCI-DSS exigem SCA
- **Manutenção Contínua**: Novas CVEs aparecem diariamente (média: 50 CVEs/dia)

**Conexão com o curso:**
- **Pré-requisito**: Conhecimento de package managers (npm, pip, maven), CVE/CWE
- **Aplica conceitos**: SCA (Software Composition Analysis), Supply Chain Security, Patch Management
- **Prepara para**: Exercício 2.5.2 (npm audit), 2.5.3 (SBOM), 2.5.4 (War Room CVE)
- **Integra com**: Aula 2.1 (SAST - código próprio), Aula 2.2 (DAST - runtime)

**Habilidades desenvolvidas:**
- Instalação e configuração de SCA tools (Snyk, npm audit, OWASP Dependency-Check)
- Análise de vulnerabilidades em dependências (diretas e transitivas)
- Priorização por severity e exploitability
- Patch management (quando atualizar vs aceitar risco)
- Automação de scans no CI/CD
- Gestão de False Positives e ignored vulnerabilities

**Habilidades do mundo real:**
- Security Engineers gerenciam SCA em portfólio de 20-100 aplicações
- DevOps automatiza scans e correções (Dependabot, Renovate)
- Developers corrigem vulnerabilidades em sprint (SLA: Critical 7 dias, High 30 dias)

**Estatísticas da indústria:**
- 92% dos ataques recentes envolveram supply chain (Sonatype, 2024)
- Média de 237 dependências transitivas por aplicação (NPM, 2025)
- 45% das vulnerabilidades estão em deps transitivas (não diretas)
- Snyk detecta 15% mais vulnerabilidades que npm audit alone (Database maior)

**Estratégias de gestão de dependências:**

**1. Automated Updates (Dependabot, Renovate):**
- PRs automáticos quando patch disponível
- Reduz MTTR (Mean Time To Remediation)
- Requer testes automatizados robustos

**2. Version Pinning vs Ranges:**
```json
// Pinning exato (máxima previsibilidade, mas desatualiza)
"dependencies": {
  "express": "4.17.1"
}

// Range (recebe patches automaticamente, mas pode quebrar)
"dependencies": {
  "express": "^4.17.1"  // Aceita 4.17.x, 4.18.x (não 5.x)
}
```

**3. Lock Files (package-lock.json):**
- Garante builds reproduzíveis
- Essencial para SCA preciso
- Sempre commitar no git

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
