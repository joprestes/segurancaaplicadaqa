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
  - lesson-2-5-exercise-2-dependabot-config
  - lesson-2-5-exercise-3-npm-audit
  - lesson-2-5-exercise-4-license-compliance
  - lesson-2-5-exercise-5-dependency-update-strategy
  - lesson-2-5-exercise-6-sbom-generation
  - lesson-2-5-exercise-7-supply-chain-security
video:
  file: "assets/module-2/videos/2.5-Dependency_Scanning_SCA.mp4"
  title: "Dependency Scanning e SCA"
  thumbnail: "assets/module-2/images/infograficos/infografico-lesson-2-5.png"
image: "assets/module-2/images/podcasts/2.5-Dependency_Scanning_SCA.png"
permalink: /modules/testes-seguranca-pratica/lessons/dependency-scanning-sca/
---

<!-- # Aula 2.5: Dependency Scanning e SCA -->

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
- ✅ **Dependências transitivasm** (dependências das suas dependências)

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

**Definição**: [A ser preenchido]

[Explicação detalhada a ser desenvolvida]

### 2. Licenças Incompatíveis

[Conteúdo a ser desenvolvido]

### 3. Dependências Desatualizadas

[Conteúdo a ser desenvolvido]

### 4. Dependências Abandonadas

[Conteúdo a ser desenvolvido]

---

## 🔧 Ferramentas de SCA

### 1. [Ferramenta 1]

**Definição**: [Descrição da ferramenta]

**Características principais**:
- [Característica 1]
- [Característica 2]
- [Característica 3]

**Quando usar**: [Cenários de uso]

**Exemplo prático**:
```bash
# [Exemplo de uso da ferramenta]
```

### 2. [Ferramenta 2]

[Conteúdo a ser desenvolvido]

### 3. [Ferramenta 3]

[Conteúdo a ser desenvolvido]

---

## 📋 Processo de Dependency Scanning

### 1. Identificação de Dependências

**Definição**: [A ser preenchido]

[Explicação detalhada a ser desenvolvida]

**Formatos suportados**:
- [Formato 1]
- [Formato 2]
- [Formato 3]

### 2. Análise de Vulnerabilidades

[Conteúdo a ser desenvolvido]

### 3. Priorização e Remediation

[Conteúdo a ser desenvolvido]

---

## 🔄 Integração com CI/CD

### Configurando SCA no Pipeline

[Conteúdo sobre integração CI/CD a ser desenvolvido]

**Exemplo de configuração**:
```yaml
# [Exemplo de pipeline CI/CD com SCA]
```

### Quality Gates para Dependências

[Conteúdo a ser desenvolvido]

---

## 🎯 Exemplos Práticos

### Exemplo 1: [Título do Exemplo]

**Cenário**: [Descrição do cenário]

**Passos**:
1. [Passo 1]
2. [Passo 2]
3. [Passo 3]

**Resultado esperado**: [A ser preenchido]

### Exemplo 2: [Título do Exemplo]

[Conteúdo a ser desenvolvido]

---

## 📊 Gerenciamento de Dependências

### Estratégias de Atualização

[Conteúdo sobre estratégias a ser desenvolvido]

### Dependency Pinning

**Definição**: [A ser preenchido]

[Explicação detalhada]

### Dependency Updates Automatizados

[Conteúdo a ser desenvolvido]

---

## ⚠️ Boas Práticas

### Checklist de SCA

- ✅ [Prática 1]
- ✅ [Prática 2]
- ✅ [Prática 3]
- ✅ [Prática 4]

### Anti-padrões a Evitar

- ❌ [Anti-padrão 1]
- ❌ [Anti-padrão 2]
- ❌ [Anti-padrão 3]

---

## 📝 Resumo

### Principais Conceitos

- [Conceito 1 - a ser preenchido]
- [Conceito 2 - a ser preenchido]
- [Conceito 3 - a ser preenchido]

### Pontos-Chave para Lembrar

- ✅ [Ponto-chave 1]
- ✅ [Ponto-chave 2]
- ✅ [Ponto-chave 3]

### Próximos Passos

- Próximo módulo: [Módulo 3: Segurança por Setor](../../module-3/index.md)
- [Ação prática sugerida]

---

**Aula Anterior**: [Aula 2.4: Automação de Testes de Segurança](./lesson-2-4.md)  
**Próximo Módulo**: [Módulo 3: Segurança por Setor](../../module-3/index.md)  
**Voltar ao Módulo**: [Módulo 2: Testes de Segurança na Prática](../index.md)
