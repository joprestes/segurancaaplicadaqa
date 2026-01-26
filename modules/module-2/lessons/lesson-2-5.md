---
layout: lesson
title: "Aula 2.5: Dependency Scanning e SCA"
slug: dependency-scanning-sca
module: module-2
lesson_id: lesson-2-5
duration: "90 minutos"
level: "Intermediário"
prerequisites: ["lesson-2-4"]
exercises:
  - lesson-2-5-exercise-1-snyk-setup
  - lesson-2-5-exercise-2-npm-audit
  - lesson-2-5-exercise-3-sbom-generation
  - lesson-2-5-exercise-4-cve-war-room
  - lesson-2-5-exercise-5-no-patch-available
video:
  file: "assets/module-2/videos/2.5-Dependency_Scanning_SCA.mp4"
  title: "Dependency Scanning e SCA"
  thumbnail: "assets/module-2/images/infograficos/infografico-lesson-2-5.png"
image: "assets/module-2/images/podcasts/2.5-Dependency_Scanning_SCA.png"
permalink: /modules/testes-seguranca-pratica/lessons/dependency-scanning-sca/
---

<!-- # Aula 2.5: Dependency Scanning e SCA -->

## ⚡ TL;DR (5 minutos)

**O que você vai aprender**: SCA analisa dependências de terceiros (npm, pip, maven) para detectar CVEs conhecidas, licenças incompatíveis e supply chain attacks.

**Por que importa**: 60-80% do código moderno são dependências externas. Equifax perdeu $1.4B por não atualizar Apache Struts. Log4Shell afetou milhares de empresas em 24h.

**Ferramentas principais**: Snyk (comercial com auto-fix), Dependabot (GitHub native), OWASP Dependency-Check (open-source), npm audit (nativo)

**Aplicação prática**: SCA a cada commit detecta dependências vulneráveis antes de merge. SBOM permite resposta rápida a CVEs críticas (identificar uso em minutos).

**Tempo de leitura completa**: 90 minutos  
**Exercícios**: 5 (2 básicos, 1 intermediário ⭐, 2 avançados ⭐⭐)

---

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- [ ] Compreender o que é SCA (Software Composition Analysis) e Dependency Scanning
- [ ] Entender a importância de analisar dependências de terceiros
- [ ] Identificar as principais ferramentas de SCA disponíveis
- [ ] Executar scans de dependências em projetos reais
- [ ] Interpretar resultados de SCA e priorizar vulnerabilidades
- [ ] Integrar SCA em pipelines CI/CD
- [ ] Gerenciar e atualizar dependências vulneráveis
- [ ] Entender diferentes tipos de vulnerabilidades em dependências

---

## 🧭 Como usar esta aula (Essencial vs Aprofundamento)

Se estiver com pouco tempo, foque nas seções essenciais abaixo e deixe o aprofundamento como leitura complementar.

**Essencial**:
- Introdução, Tipos de vulnerabilidades, Ferramentas, Processo de scanning
- Integração com CI/CD, Exemplos práticos, Gerenciamento, Boas práticas

**Aprofundamento opcional**:
- Analogias e dados históricos da indústria
- Cheat sheet para consulta rápida

---

## 📘 Glossário rápido

- **CVE**: identificador público de vulnerabilidades conhecidas
- **CVSS**: pontuação de severidade (0 a 10)
- **SBOM**: inventário de componentes e dependências da aplicação
- **Dependência transitiva**: dependência indireta das suas dependências
- **SCA**: análise de componentes e vulnerabilidades em software de terceiros
- **License compliance**: validação de licenças incompatíveis
- **Supply chain attack**: ataque via dependências comprometidas

---

## 📚 Introdução ao SCA e Dependency Scanning

### O que é SCA?

**SCA (Software Composition Analysis)** é o processo automatizado de **identificar, analisar e gerenciar componentes de código aberto e dependências de terceiros** em uma aplicação. O objetivo é detectar vulnerabilidades conhecidas (CVEs), licenças incompatíveis, dependências desatualizadas e riscos de supply chain antes que código vulnerável chegue à produção.

**Diferente de SAST** (que analisa código próprio) e **DAST** (que testa aplicação em runtime), SCA foca especificamente em **código que você NÃO escreveu**: bibliotecas npm, pacotes PyPI, gems Ruby, JARs Maven, NuGet packages, etc.

**Por que SCA é crítico:**
- 📊 **60-80% do código moderno é open-source** (dependências de terceiros)
- 🔓 **97% das aplicações** têm pelo menos uma vulnerabilidade em dependências (Synopsys 2023)
- ⚠️ **Novas CVEs** são publicadas diariamente (20.000+ CVEs em 2023)
- 🎯 **Ataques a supply chain** aumentaram 650% desde 2021 (Sonatype)

**O que SCA detecta:**
- ✅ **Vulnerabilidades conhecidas** (CVEs) em dependências diretas e transitivas
- ✅ **Licenças de software** (GPL, MIT, Apache, etc) e incompatibilidades
- ✅ **Dependências desatualizadas** que precisam ser atualizadas
- ✅ **Dependências abandonadas** (unmaintained packages)
- ✅ **Malware** em dependências (typosquatting, backdoors)
- ✅ **Dependências transitivas** (dependências das suas dependências)

**Leitura opcional (aprofundamento)**  
#### 🎭 Analogia: O Inspetor de Ingredientes

Imagine que você é um **chef de restaurante** preparando um prato sofisticado:

**👨‍🍳 Seu Código Próprio**: Você mesmo prepara **20%** do prato - o molho especial secreto, o tempero único da casa.

**🛒 Dependências (Código de Terceiros)**: Os outros **80%** do prato você **compra pronto**: massa italiana importada, queijo parmesão, tomates orgânicos, azeite premium, ervas desidratadas.

**Sem SCA (Inspeção de Ingredientes)**:
- Você **não verifica a validade** dos ingredientes comprados
- Não sabe se o **queijo está contaminado** com bactérias (CVE)
- Não percebe que a **massa venceu há 6 meses** (outdated dependency)
- Não lê que o **azeite tem licença restritiva** que proíbe uso comercial (license issue)
- Não descobre que o **fabricante de ervas faliu** e não faz mais updates (abandoned package)

**Resultado**: Clientes ficam doentes (aplicação hackeada), restaurante é processado (violação de licença), health inspector fecha o restaurante (compliance failure).

**Com SCA (Inspeção Automatizada)**:
- **Scanner automático** verifica validade de todos os ingredientes todo dia (daily CVE checks)
- **Alerta instantâneo** se algum ingrediente foi recall (vulnerability alert)
- **Sugestão de substituição** por versão mais nova e segura (auto-fix PR)
- **Validação de licenças** de cada ingrediente (license compliance)
- **Monitoramento de fornecedores** para saber se pararam de produzir (unmaintained packages)

**Resultado**: Restaurante seguro, clientes satisfeitos, sem processos ou fechamentos.

**Mapeamento para SCA:**

| Restaurante | Aplicação |
|-------------|-----------|
| Ingredientes comprados prontos | Dependências (npm, pip, maven) |
| Inspetor de qualidade de alimentos | Ferramenta de SCA (Snyk, Dependabot) |
| Data de validade vencida | CVE publicado em dependência |
| Recall de produto | Critical vulnerability encontrada |
| Fornecedor faliu | Dependência abandonada (unmaintained) |
| Licença de uso comercial | License incompatível (GPL em produto proprietário) |
| Verificação diária de ingredientes | Daily SCA scan no CI/CD |

### Por que SCA é Importante?

Aplicações modernas são construídas sobre **pilhas gigantes de dependências**. Um projeto simples Node.js pode ter **1.000+ dependências** quando você conta transitivas. Cada uma é um **potencial vetor de ataque** se vulnerável.

**📊 Dados alarmantes da indústria:**

- **Equifax Breach (2017)**: 147 milhões de pessoas expostas por **Apache Struts não patcheado** (CVE conhecida há 2 meses)
  - Custo: **$1.4 bilhões** em multas, acordos e perda de valor de mercado
  - Causa raiz: Falta de SCA automatizado para detectar dependência vulnerável

- **Log4Shell (2021)**: Vulnerabilidade crítica em **Log4j** afetou milhares de empresas globalmente
  - Severidade: CVSS **10.0** (máxima)
  - Impacto: Servidores Minecraft, AWS, Twitter, iCloud comprometidos
  - SCA detectaria: Em **minutos** após CVE ser publicada

- **SolarWinds (2020)**: Supply chain attack atingiu **18.000 organizações**
  - Atacantes injetaram malware em **atualização legítima** de software
  - SCA avançado + binary analysis poderia ter detectado anomalias

- **ua-parser-js (2021)**: Package npm com **9 milhões de downloads/semana** teve versões **comprometidas com malware**
  - Afetou: Create React App, Webpack, Gatsby
  - SCA com malware detection teria bloqueado

#### Benefícios do SCA

| Benefício | Descrição | Impacto |
|-----------|-----------|---------|
| **Prevenção de Breaches** | Detecta CVEs conhecidas antes que atacantes explorem. Equifax poderia ter evitado breach de $1.4B | 🎯 Crítico - Evita comprometimentos massivos e multas regulatórias |
| **Compliance e Auditoria** | Mapeia todas as dependências e suas licenças. Essencial para ISO 27001, SOC2, PCI-DSS | ✅ Alto - Evita violações de licença (GPL em software proprietário pode custar milhões) |
| **Redução de Supply Chain Risk** | Detecta typosquatting, malware em packages, dependências abandonadas | 🛡️ Alto - Supply chain attacks cresceram 650% (Sonatype 2023) |
| **Velocidade de Resposta** | Quando Log4Shell foi publicado, SCA automatizado detectou em minutos vs semanas manualmente | ⚡ Alto - Mean Time To Detect (MTTD) cai de semanas para minutos |
| **Developer Experience** | Desenvolvedores descobrem vulnerabilidades no PR, não em produção. Auto-fix PRs reduzem toil | 👨‍💻 Médio - Reduz context switching e burnout de equipes |
| **Custo de Correção** | Corrigir dependência vulnerável em dev custa 30x menos que em produção (NIST) | 💰 Alto - ROI comprovado de shift-left security |
| **Visibilidade de Inventário** | SBOM (Software Bill of Materials) completo - sabe exatamente o que está rodando | 📊 Médio - Essencial para resposta a incidentes e auditorias |

### Contexto Histórico

```
📅 Evolução do SCA e Dependency Scanning

2000-2005 - 🏗️ Nascimento do Open Source Mainstream
           └─ Explosão de libraries open-source (Apache, GNU)
           └─ Desenvolvimento web adota LAMP stack
           └─ Ainda sem preocupação sistemática com dependências
           └─ CVEs começam a ser catalogadas (MITRE CVE Database)

2005-2010 - 📦 Package Managers Emergem
           └─ RubyGems (2004), Maven Central (2002), PyPI (2003), npm (2010)
           └─ Desenvolvedores começam usar dependências massivamente
           └─ Primeiros casos de malware em packages
           └─ Black Duck Software lança primeiro SCA comercial (2002)

2010-2015 - 🔐 Conscientização de Security em Dependencies
           └─ Heartbleed (2014): OpenSSL bug afeta 17% da internet
           └─ OWASP Top 10 (2013) adiciona A9: Using Components with Known Vulnerabilities
           └─ GitHub Security Advisories lançado
           └─ OWASP Dependency-Check (2012) - primeiro SCA open-source popular
           └─ npm audit command adicionado (2018)

2015-2020 - 🚀 SCA Automatizado e Integrado
           └─ Snyk fundada (2015) - SCA com auto-fix PRs
           └─ GitHub adquire Dependabot (2019)
           └─ WhiteSource (agora Mend) se populariza
           └─ Equifax breach (2017) - Apache Struts CVE não patcheada → $1.4B perdidos
           └─ Evento dominó attack (2018): 1 package malicioso → 800+ packages infectados
           └─ SCA se torna padrão em CI/CD pipelines

2020-2024 - 🎯 Supply Chain Security e SBOM
           └─ SolarWinds attack (2020): supply chain comprometida
           └─ Log4Shell (2021): CVSS 10.0, milhares de empresas afetadas em 24h
           └─ Executive Order 14028 (2021): Governo dos EUA exige SBOM
           └─ npm, PyPI, RubyGems adicionam 2FA obrigatório para maintainers
           └─ SLSA Framework (Supply-chain Levels for Software Artifacts)
           └─ Sigstore (2021): assinaturas criptográficas de packages
           └─ Socket.dev (2022): AI para detectar malware em packages
           └─ SCA evoluiu de "nice-to-have" para "obrigatório"
```

**Marcos críticos que aceleraram adoção de SCA:**

- **2014: Heartbleed** - Vulnerabilidade em OpenSSL expôs 17% dos servidores web. Mostrou que **todos dependem de código open-source crítico**, mas poucos auditam.

- **2017: Equifax Breach** - **147 milhões** de pessoas tiveram dados pessoais roubados porque Equifax não atualizou Apache Struts (CVE-2017-5638 conhecida há **2 meses**). Multa: **$575 milhões**. Provou que **falta de SCA automatizado custa bilhões**.

- **2018: Event-stream attack** - Package npm popular (`event-stream`, 2M downloads/week) teve versão comprometida com malware que roubava Bitcoin wallets. Mostrou que **attackers targetam supply chain**.

- **2021: Log4Shell (CVE-2021-44228)** - Vulnerabilidade **CVSS 10.0** em Log4j afetou **AWS, iCloud, Minecraft, Twitter** e milhares de empresas. SCA permitiu que empresas identificassem uso de Log4j em **minutos** (vs semanas manualmente).

- **2022: npm color & faker sabotage** - Maintainer de packages ultra-populares (`colors.js`, `faker.js` com 20M+ downloads/semana) **intencionalmente adicionou malware** em protesto. Quebrou builds de milhares de projetos globalmente. Acelerou discussão sobre **governance de open-source**.

**Estado Atual (2024):**
- SCA é **obrigatório** em pipelines CI/CD modernos
- Governo dos EUA exige **SBOM** (Software Bill of Materials) de fornecedores
- GitHub, npm, PyPI têm SCA integrado nativamente
- **91% das empresas** usam SCA (Gartner 2023)
- Foco mudou de "detectar CVEs" para **"prevenir supply chain attacks"**

---

## 🔄 Tipos de Vulnerabilidades em Dependências

### 1. Vulnerabilidades Conhecidas (CVEs)

**Definição**: falhas públicas com identificador oficial (CVE) e severidade (CVSS).

**Exemplo**: Log4Shell (CVE-2021-44228), CVSS 10.0, RCE sem autenticação.

### 2. Licenças Incompatíveis

**Definição**: licenças que não podem ser usadas no contexto do produto (ex: GPL em software proprietário).

**Risco**: obrigação de abrir código ou processos legais.

### 3. Dependências Desatualizadas

**Definição**: versões antigas sem patches de segurança ou com bugs conhecidos.

**Risco**: exposição desnecessária a CVEs já corrigidas.

### 4. Dependências Abandonadas

**Definição**: bibliotecas sem manutenção ativa (sem releases ou suporte).

**Risco**: vulnerabilidades ficam sem correção e dependência vira “ponto fraco eterno”.

---

## 🔧 Ferramentas de SCA

### 1. Snyk

**Definição**: SCA comercial com auto-fix e monitoramento contínuo.

**Características principais**:
- Alertas em PR e dashboard
- Auto-fix com PRs sugeridos
- Cobertura de dependências transitivas

**Quando usar**: times com alta cadência de deploy e necessidade de rapidez.

**Exemplo prático**:
```bash
snyk test --severity-threshold=high
```

### 2. Dependabot (GitHub)

**Definição**: bot nativo que cria PRs de atualização de dependências.

**Características principais**:
- PRs automáticos com changelog
- Configuração por diretório/stack
- Integração direta com repositório

### 3. OWASP Dependency-Check

**Definição**: ferramenta open-source para detectar CVEs em bibliotecas.

**Características principais**:
- Funciona offline após atualizar base
- Gera relatório em HTML/JSON
- Suporta Maven, npm, NuGet e outros

---

## 📋 Processo de Dependency Scanning

### 1. Identificação de Dependências

**Definição**: leitura dos arquivos de manifesto e lockfiles do projeto.

**Formatos suportados**:
- `package.json` / `package-lock.json`
- `pom.xml` / `gradle.lockfile`
- `requirements.txt` / `poetry.lock`

### 2. Análise de Vulnerabilidades

- Cruzar versões com bases de CVE
- Identificar dependências diretas e transitivas
- Analisar severidade e exploitabilidade

### 3. Priorização e Remediation

- Priorizar Critical/High com patch disponível
- Atualizar dependências com testes em staging
- Definir plano de mitigação quando não há patch

---

## 🔄 Integração com CI/CD

### Configurando SCA no Pipeline

**Objetivo**: rodar SCA em PRs e manter monitoramento contínuo.

**Exemplo de configuração**:
```yaml
name: SCA
on: [pull_request]
jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Snyk
        run: snyk test --severity-threshold=high
```

### Quality Gates para Dependências

- **Bloquear**: Critical com patch disponível
- **Alertar**: High com patch disponível há >30 dias
- **Informar**: Medium/Low e dependências desatualizadas

---

## 🎯 Exemplos Práticos

### Exemplo 1: npm audit com bloqueio de Critical

**Cenário**: projeto Node com vulnerabilidade conhecida em dependência.

**Passos**:
1. Rodar `npm audit --audit-level=high`
2. Aplicar `npm audit fix` quando possível
3. Validar build e testes

**Resultado esperado**: dependência atualizada e CVE removida.

### Exemplo 2: Bloqueio de licença GPL

**Cenário**: produto proprietário não pode usar GPL.

**Passos**:
1. Configurar lista de licenças permitidas
2. Rodar scan de licenças no pipeline
3. Bloquear PR com GPL/AGPL

**Resultado esperado**: PR bloqueado e dependência substituída.

---

## 📊 Gerenciamento de Dependências

### Estratégias de Atualização

- Atualizações pequenas e frequentes (1-5 deps por PR)
- Janela fixa semanal para updates
- Separar updates de segurança de updates funcionais

### Dependency Pinning

**Definição**: travar versões para garantir builds reproduzíveis.

**Explicação**: usar lockfiles e ranges controlados evita “surpresas” em produção.

### Dependency Updates Automatizados

- Dependabot/Renovate para PRs automáticos
- Agrupar updates por criticidade
- Validar com testes automatizados

---

## ⚠️ Boas Práticas

### Checklist de SCA

- ✅ SCA em PRs e monitoramento contínuo
- ✅ Quality gate claro para Critical/High
- ✅ SBOM gerado automaticamente por build
- ✅ Processo definido para “sem patch disponível”

### Anti-padrões a Evitar

- ❌ Atualizar tudo em “big bang”
- ❌ Ignorar alertas por “alert fatigue”
- ❌ Não testar updates em staging

---

### Aplicação Prática no Contexto CWI

**Cenários reais de SCA e Dependency Scanning em projetos CWI:**

#### 1. Resposta Rápida ao Log4Shell (CVE-2021-44228)

**Contexto:**
- Data: 10 de dezembro de 2021, 01:00 AM
- Severidade: CVSS 10.0 (máxima) - RCE sem autenticação
- Biblioteca afetada: Apache Log4j 2.x (usada por milhares de aplicações Java)
- Janela de exploração: Bots automatizados começaram a explorar em 1 hora

**Timeline de Resposta CWI (24 horas):**

```
🚨 Hora 0 (01:00): CVE publicada

🔍 Hora 1 (02:00): Identificação via SBOM
   - SCA automatizado (Snyk + Dependabot) escaneou 200+ repositórios
   - SBOM permitiu identificar 15 aplicações afetadas em 30 minutos
   - Sem SBOM, levaria 2-3 semanas de busca manual

⚠️ Hora 2 (03:00): Triagem e Priorização
   - 15 apps afetadas → 5 críticas (internet-facing)
   - 10 médias (intranet ou staging)
   - War Room ativado com DevOps + Security + QA

🔧 Hora 4-12 (05:00-13:00): Remediação Emergencial
   - Apps críticas: upgrade imediato para log4j 2.17.0
   - Deploy emergency bypass (aprovação de CISO)
   - Testes de fumaça automatizados

✅ Hora 24 (01:00 +1 dia): Resolução Completa
   - 100% das aplicações patcheadas
   - Zero explorações bem-sucedidas detectadas
   - Post-mortem documentado
```

**Lições Aprendidas:**
- ✅ **SBOM salvou 2-3 semanas**: Identificação em 30 min vs semanas de busca manual
- ✅ **SCA automatizado é essencial**: Dependabot/Snyk alertaram em <1h após CVE
- ✅ **Quality Gates flexíveis**: Emergency bypass permitiu deploy rápido
- ✅ **Monitoramento contínuo**: SIEM detectou tentativas de exploração (todas falharam)

#### 2. Gestão de Dependências npm em Monorepo (E-commerce)

**Contexto:**
- Monorepo: 25 packages npm internos + 1.500+ dependências externas
- Stack: Next.js + TypeScript + Node.js microservices
- Problema: Dependências duplicadas e conflitantes

**Desafio Inicial:**
```bash
# Projeto tinha 47 versões diferentes de React!
$ npm list react
├─ app-checkout@1.0.0 → react@17.0.2
├─ app-cart@1.0.0 → react@18.0.0
├─ shared-ui@1.0.0 → react@17.0.1
└─ ... (44 mais versões)

# Resultados:
- Bundle size inflado: 2.5MB só de React duplicado
- Conflitos de tipos TypeScript
- CVEs difíceis de remediar (qual versão atualizar?)
```

**Solução Implementada:**
```json
// package.json - Workspace resolutions
{
  "workspaces": ["packages/*"],
  "resolutions": {
    "react": "18.2.0",
    "react-dom": "18.2.0"
  }
}

// Renovate config - Automated dependency updates
{
  "extends": ["config:base"],
  "groupName": "all",
  "schedule": ["before 9am on Monday"],
  "prConcurrentLimit": 5,
  "vulnerabilityAlerts": {
    "enabled": true,
    "minimumSeverity": "high"
  }
}
```

**Ferramentas Utilizadas:**
- **Renovate Bot**: PRs automatizados de atualização (Monday mornings)
- **npm-check-updates**: Detectar dependências desatualizadas
- **Snyk**: Monitoramento 24/7 de novas CVEs
- **Webpack Bundle Analyzer**: Validar redução de bundle após dedupe

**Resultados:**
- ✅ **Bundle size reduzido** em 1.8MB (72% redução em duplicações)
- ✅ **1 versão única** de cada dependência crítica
- ✅ **Atualiz ações semanais automáticas**: 5 PRs por Monday, revisão em 30min
- ✅ **Zero breaking changes** em produção (staging testa antes)
- ✅ **CVEs corrigidas em <24h** (vs 2 semanas antes)

#### 3. Compliance de Licenças em Projeto Enterprise (Telecom)

**Contexto:**
- Cliente: Operadora de telecom (sistema de billing crítico)
- Stack: Java (Spring Boot) + 300+ JARs Maven
- Regulação: Código não pode usar GPL (software proprietário)

**Desafio:**
Auditoria externa encontrou **12 dependências GPL** no código-fonte. Violação de licença poderia custar **$5-10 milhões** em processos + código-fonte exposto publicamente.

**Situação Crítica Descoberta:**
```xml
<!-- pom.xml tinha: -->
<dependency>
  <groupId>org.example</groupId>
  <artifactId>gpl-library</artifactId>
  <version>3.0.0</version>
  <!-- ⚠️ License: GPL v3 - INCOMPATÍVEL com software proprietário! -->
</dependency>
```

**Solução Implementada:**
```yaml
1. License Scanning Automatizado:
   - FOSSA (SCA focado em licenças)
   - License Finder (GitHub)
   - Quality Gate: bloqueia GPL, AGPL, SSPL
   
2. Whitelist de Licenças Aprovadas:
   approved_licenses:
     - MIT
     - Apache-2.0
     - BSD-3-Clause
     - ISC
   
   blocked_licenses:
     - GPL-2.0
     - GPL-3.0
     - AGPL-3.0
     - SSPL

3. Remediação das 12 Dependências GPL:
   - 8 substituídas por alternativas MIT/Apache
   - 3 re-implementadas internamente
   - 1 negociada licença comercial com vendor
```

**Ferramentas Utilizadas:**
- **FOSSA**: License compliance automation
- **License Finder**: Scan de licenses em build time
- **ClearlyDefined**: Database de metadados de licenses

**Resultados:**
- ✅ **100% compliance** com política de licenças
- ✅ **Auditoria bem-sucedida**: Zero non-compliance findings
- ✅ **Processo evitado**: Economizou $5-10M em potenciais processos
- ✅ **Pipeline automatizado**: Nenhuma GPL passa sem bloqueio
- ✅ **Documentação**: SBOM com licenses para auditorias futuras

---

## 📋 Cheat Sheet: SCA e Dependency Scanning

### Comandos Rápidos

**npm/yarn**:
```bash
# Audit de vulnerabilidades
npm audit
npm audit fix  # Auto-fix

# Verificar dependências desatualizadas
npm outdated

# Audit com severidade específica
npm audit --audit-level=high
```

**Snyk**:
```bash
# Test (CI/CD)
snyk test --severity-threshold=high

# Monitor (tracking contínuo)
snyk monitor

# Fix automático
snyk fix
```

**OWASP Dependency-Check**:
```bash
# Scan de dependências
dependency-check --project MyApp --scan ./

# Com SBOM output
dependency-check --project MyApp --scan ./ --format JSON
```

### Quando Usar SCA

✅ **Use SCA para**:
- Detectar CVEs em dependências de terceiros
- License compliance (GPL, Apache, MIT)
- Supply chain security
- Resposta rápida a CVEs críticas (via SBOM)
- Dependency updates automatizados

❌ **NÃO use SCA para**:
- Vulnerabilidades em código próprio (use SAST)
- Runtime vulnerabilities (use DAST)
- Lógica de negócio (use Pentest)

### Quality Gate Sugerido

```yaml
Bloquear merge se:
  - Critical com patch disponível
  - High com patch disponível há >30 dias
  - License GPL/AGPL em software proprietário
  
Avisar (não bloquear) se:
  - High sem patch disponível
  - Medium com patch disponível
  
Informar:
  - Low
  - Dependências desatualizadas (sem CVE)
```

### Resposta a CVE Crítica

```
1. SBOM identifica apps afetadas (30 min)
2. Triagem por risco (2h):
   - Internet-facing = P0
   - Autenticado = P1
   - Interno = P2
3. Remediação por prioridade (4-24h)
4. Validação pós-patch (2h)
5. Post-mortem (1 semana)
```

### Links Úteis

- [Snyk Advisor](https://snyk.io/advisor/)
- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)
- [SBOM Guide](https://www.cisa.gov/sbom)
- [CVE Database](https://cve.mitre.org/)

---

## ✅ Quick Reference (para o dia a dia)

- **Pipeline mínimo**: SCA em PR + alertas contínuos
- **Prioridade**: Critical/High com SLA curto
- **SBOM**: gerar automaticamente no CI/CD
- **Resposta a CVE**: identificar apps afetadas em minutos
- **Ruído baixo**: trate falsos positivos e normalização

---

## 📝 Resumo

### Principais Conceitos

- SCA identifica riscos em dependências de terceiros
- Quality gates evitam CVEs críticas em produção
- SBOM acelera resposta a incidentes

### Pontos-Chave para Lembrar

- ✅ 60-80% do código é dependência
- ✅ Atualizações pequenas reduzem risco
- ✅ Licença é risco legal real

### Próximos Passos

- Próximo módulo: [Módulo 3: Segurança por Setor](../../module-3/index.md)
- Execute os exercícios para praticar Snyk, npm audit e SBOM

---

**Aula Anterior**: [Aula 2.4: Automação de Testes de Segurança](./lesson-2-4.md)  
**Próximo Módulo**: [Módulo 3: Segurança por Setor](../../module-3/index.md)  
**Voltar ao Módulo**: [Módulo 2: Testes de Segurança na Prática](../index.md)

---

## ❌ Erros Comuns que QAs Cometem com SCA

### 1. **Atualizar dependência sem testar (YOLO update)**

**Por quê é erro**: Breaking change quebra produção.

**Solução**: SEMPRE teste em staging antes. Leia changelog da dependência.

### 2. **Ignorar vulnerabilidades "sem patch disponível"**

**Por quê é erro**: "Não tem fix" ≠ "não fazer nada".

**Solução**: Avalie: exploitability, alternativas, mitigações (WAF, disable feature). Documente decisão.

### 3. **Não manter SBOM atualizado**

**Por quê é erro**: Log4Shell acontece. SBOM desatualizado = demora semanas para identificar apps afetadas.

**Solução**: SBOM deve ser gerado automaticamente a cada build. CI/CD integration.

### 4. **Aceitar dependências GPL em software proprietário (license compliance fail)**

**Por quê é erro**: Violação de licença → Processo legal → $5-10M em perdas.

**Solução**: License scanning automatizado no CI/CD. Bloqueia GPL/AGPL em software proprietário.

### 5. **Renovar todas as dependências de uma vez (big bang update)**

**Por quê é erro**: 50 dependências atualizadas = impossible to debug se algo quebrar.

**Solução**: Atualize incrementalmente. 1-5 dependências por PR. Facilita rollback.

---

## 📖 Recursos Adicionais

**Dúvida sobre algum termo técnico?**  
Consulte o [📖 Glossário do Módulo 2](/modules/testes-seguranca-pratica/glossario/) com mais de 80 definições de termos de segurança (SCA, CVE, CVSS, SBOM, Snyk, Dependabot, Supply Chain Attack, Transitive Dependency, etc.).

---
