---
layout: lesson
title: "Aula 2.1: SAST: Static Application Security Testing"
slug: sast-testes-estaticos
module: module-2
lesson_id: lesson-2-1
duration: "90 minutos"
level: "Intermediário"
prerequisites: ["lesson-1-5"]
exercises:
  - lesson-2-1-exercise-1-sonarqube-setup
  - lesson-2-1-exercise-2-semgrep-custom-rules
  - lesson-2-1-exercise-3-sast-cicd
  - lesson-2-1-exercise-4-validate-findings
  - lesson-2-1-exercise-5-compare-sast-tools
video:
  file: "assets/videos/2.1-SAST_Testes_Estaticos.mp4"
  title: "SAST: Static Application Security Testing"
  thumbnail: "assets/images/infografico-lesson-2-1.png"
image: "assets/images/podcasts/2.1-SAST_Testes_Estaticos.png"
permalink: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
---

<!-- # Aula 2.1: SAST: Static Application Security Testing -->

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Compreender o que é SAST e sua importância no processo de testes de segurança
- Diferenciar SAST de outras metodologias de teste (DAST, IAST, SCA)
- Identificar as principais ferramentas SAST disponíveis no mercado
- Executar análise estática de código em projetos reais
- Interpretar resultados de SAST e priorizar vulnerabilidades
- Integrar SAST em pipelines CI/CD
- Configurar regras customizadas em ferramentas SAST

---

## 📚 Introdução ao SAST

### O que é SAST?

**SAST (Static Application Security Testing)** é uma metodologia de teste de segurança que analisa o código-fonte, bytecode ou binários de uma aplicação **sem executá-la**. SAST identifica vulnerabilidades através da análise estática do código, procurando por padrões inseguros, más práticas e vulnerabilidades conhecidas.

#### 🎭 Analogia: Inspetor de Código vs Teste de Estrada

Imagine comprar um carro:

**SAST = Inspetor que examina o carro parado**:
- O inspetor abre o capô e examina o motor, sem ligar o carro
- Verifica se há peças soltas, vazamentos, fios expostos
- Identifica problemas potenciais antes de sair na estrada
- **Vantagem**: Encontra problemas antes de usar
- **Limitação**: Não testa como o carro funciona em movimento

**DAST = Teste de Estrada**:
- Testa o carro em movimento, em condições reais
- Verifica como o carro se comporta na prática
- **Vantagem**: Encontra problemas que só aparecem em uso real
- **Limitação**: Precisa que o carro esteja funcionando

Na segurança de software:
- **SAST** analisa código estático, sem executar
- **DAST** testa aplicação em execução (será abordado na próxima aula)

### Contexto Histórico do SAST

A análise estática de código existe desde os primórdios da programação, mas SAST como disciplina específica de segurança evoluiu significativamente:

```
Anos 1970-1980 ──────────────────────────────────────────── 2026+
 │                                                             │
 ├─ 1970s    📦 Lint (Original)                              │
 │          ┌─────────────────────────────────────┐          │
 │          │ • Análise de estilo de código      │          │
 │          │ • Detecção de bugs básicos         │          │
 │          │ • Foco em qualidade, não segurança │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 ├─ 1990s    🔍 Code Review Manual                            │
 │          ┌─────────────────────────────────────┐          │
 │          │ • Revisão humana de código         │          │
 │          │ • Encontra problemas de segurança   │          │
 │          │ • Lento e caro                     │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 ├─ 2000s    🔥 SAST Comercial Inicial                        │
 │          ┌─────────────────────────────────────┐          │
 │          │ • Ferramentas comerciais (Checkmarx)│          │
 │          │ • Foco em vulnerabilidades OWASP    │          │
 │          │ • Integração com IDEs              │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 ├─ 2010s    📈 SAST Open Source                             │
 │          ┌─────────────────────────────────────┐          │
 │          │ • SonarQube com security rules      │          │
 │          │ • Bandit (Python), Brakeman (Ruby) │          │
 │          │ • ESLint Security Plugin            │          │
 │          │ • Acessibilidade aumentada          │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 ├─ 2020    ⚡ Rules as Code (Semgrep)                       │
 │          ┌─────────────────────────────────────┐          │
 │          │ • Regras customizadas fáceis        │          │
 │          │ • Fast scanning                     │          │
 │          │ • Developer-friendly                │          │
 │          └─────────────────────────────────────┘          │
 │                                                             │
 └─ 2026+    🚀 SAST Moderno                                  │
            ┌─────────────────────────────────────┐          │
            │ • AI/ML para reduzir false positives│          │
            │ • Integração nativa com CI/CD       │          │
            │ • Real-time scanning em IDEs        │          │
            │ • Análise de IaC (Infrastructure)   │          │
            │ • Integração com SCA e DAST         │          │
            └─────────────────────────────────────┘          │
```

**Por que SAST se tornou fundamental?**

- **Shift-Left**: Encontra vulnerabilidades cedo (durante desenvolvimento)
- **Custo-Benefício**: Corrigir durante dev é 10-100x mais barato que em produção
- **Escalabilidade**: Automatiza o que antes era revisão manual
- **Padronização**: Regras consistentes aplicadas a todo o código
- **Compliance**: Muitos padrões (PCI-DSS, SOC2) exigem análise estática

### Por que SAST é Importante?

#### O Custo de Vulnerabilidades Encontradas por SAST vs Produção

```
┌─────────────────────────────────────────────────────────┐
│  CUSTO DE CORRIGIR VULNERABILIDADE POR MÉTODO          │
│                                                         │
│  SAST (Dev)    Code Review    Testes    DAST    Prod   │
│     │              │            │         │       │     │
│     $50          $200        $500    $2,000  $50,000│
│                                                         │
│  SAST encontra problemas quando são mais baratos!      │
└─────────────────────────────────────────────────────────┘
```

**Dados Reais (2025)**:
- Vulnerabilidade encontrada por **SAST durante desenvolvimento**: $50-200 para corrigir
- Vulnerabilidade encontrada em **code review manual**: $200-500
- Vulnerabilidade encontrada em **testes de segurança**: $500-2,000
- Vulnerabilidade encontrada por **DAST em staging**: $2,000-10,000
- Vulnerabilidade encontrada em **produção (breach)**: $50,000-500,000+

**Fonte**: OWASP, SANS Institute, IBM Security

#### Benefícios do SAST

| Benefício | Descrição | Impacto |
|-----------|-----------|---------|
| **Detecção Precoce** | Encontra vulnerabilidades durante desenvolvimento | Redução de 80-90% de bugs em produção |
| **Custo-Benefício** | Correção durante dev é muito mais barata | Economia de 10-100x vs produção |
| **Cobertura Completa** | Analisa todo o código, não apenas o que é executado | Encontra código morto, branches não testados |
| **Automação** | Integra no workflow de desenvolvimento | Não depende de revisão manual |
| **Educação** | Ensina desenvolvedores padrões seguros | Melhora cultura de segurança |
| **Compliance** | Atende requisitos de padrões de segurança | PCI-DSS, SOC2, ISO 27001 |

### O que você vai aprender

- **Fundamentos de SAST**: Como funciona análise estática
- **Ferramentas SAST**: SonarQube, Semgrep, Checkmarx, ferramentas específicas por linguagem
- **Configuração Prática**: Setup de ferramentas SAST em projetos
- **Interpretação de Resultados**: Como priorizar e validar findings
- **False Positives vs True Positives**: Como diferenciar e tratar
- **Integração CI/CD**: Automatizar scans em pipelines
- **Regras Customizadas**: Criar regras específicas para seu projeto

---

## 💼 SAST no Workflow Real de QA

> **📝 Nota para QAs Plenos**: Esta seção é essencial para entender como SAST se encaixa no seu dia a dia de trabalho. Se você já tem experiência básica com SAST, pode pular para a seção seguinte, mas recomendamos revisar os cenários práticos.

### Quando Usar SAST vs Testes Manuais?

Como QA de segurança, você precisa decidir **quando usar SAST** e **quando fazer testes manuais**. Ambas abordagens são complementares:

| Cenário | Usar SAST | Usar Testes Manuais | Combinar |
|---------|-----------|---------------------|----------|
| **Código novo sendo desenvolvido** | ✅ Sim - Integrar no CI/CD | ⚠️ Seletivamente | ✅ Ideal |
| **Código legado (herdado)** | ✅ Sim - Baseline e melhorar gradualmente | ✅ Sim - Explorar manualmente áreas críticas | ✅ Recomendado |
| **Release crítico (prazos apertados)** | ✅ Sim - Scan rápido | ✅ Sim - Foco em áreas críticas | ✅ Combinar |
| **Análise profunda de vulnerabilidade** | ⚠️ Pode gerar muitos false positives | ✅ Sim - Análise manual detalhada | ⚠️ SAST para triagem inicial |
| **Validação de correção** | ✅ Sim - Confirmar que vulnerabilidade foi corrigida | ⚠️ Se necessário | ✅ SAST primeiro |

**Regra de Ouro**: SAST é excelente para **encontrar problemas** e **validar correções**, mas **não substitui** análise manual e exploração real de vulnerabilidades.

### Integrando SAST em Processo QA Existente

Se você **já tem um processo de QA estabelecido**, aqui está como integrar SAST sem quebrar o fluxo:

#### Cenário 1: Você Herdou Projeto com SAST Configurado

**Situação Real**: Você entrou em um projeto que já tem SonarQube configurado, mas não sabe como está configurado.

**Ações Práticas**:

1. **Entender Configuração Existente**
   ```bash
   # Verificar arquivo de configuração
   cat sonar-project.properties
   
   # Ver configurações no SonarQube
   # Acessar: http://sonarqube:9000 → Projeto → Configuration
   ```

2. **Revisar Quality Gates Atuais**
   - Quais critérios estão configurados?
   - O pipeline está bloqueando merges?
   - Há exceções ou supressões?

3. **Analisar Baseline de Vulnerabilidades**
   - Quantas vulnerabilities existem atualmente?
   - Há um baseline aceito?
   - Qual a estratégia de redução (se houver)?

4. **Documentar Processo Atual**
   - Como findings são validados?
   - Quem é responsável por corrigir?
   - Como são comunicados para o time?

#### Cenário 2: SAST Está Gerando Muito Ruído (Muitos False Positives)

**Situação Real**: SonarQube encontra 500+ vulnerabilities, mas a maioria são false positives ou não críticas.

**Ações Práticas**:

1. **Criar Baseline e Priorizar**
   - Estabelecer baseline: "Acceptar tudo que está hoje, focar em novas"
   - Criar lista de exceções documentadas
   - Priorizar apenas Critical/High novos

2. **Ajustar Quality Gates Gradualmente**
   ```yaml
   # Início (Permissivo)
   - Qualidade Gate 1: 0 Critical novas (após baseline)
   - Qualidade Gate 2: Máximo 10 High novas
   
   # Após 1 mês (Médio)
   - Qualidade Gate 1: 0 Critical novas
   - Qualidade Gate 2: Máximo 5 High novas
   
   # Objetivo (Rigoroso)
   - Qualidade Gate 1: 0 Critical (total)
   - Qualidade Gate 2: 0 High novas
   ```

3. **Configurar Exceções Documentadas**
   ```java
   // Exemplo: Supressão documentada
   @SuppressWarnings("java:S2068") // Hardcoded credential - false positive
   // Razão: Password é para teste unitário apenas, não é usado em produção
   // Revisado por: QA Team em 2026-01-14
   // Issue: SEC-123 (documentado)
   String testPassword = "changeme123";
   ```

4. **Criar Processo de Triagem Rápida**
   - Checklist rápido: "É Critical? Está em produção? Dados sensíveis?"
   - Se sim → Validar manualmente
   - Se não → Marcar para review posterior

#### Cenário 3: Como Comunicar Findings para Dev Team

**Situação Real**: Você encontrou vulnerabilities, mas precisa comunicar efetivamente para desenvolvedores que podem não entender SAST.

**Melhores Práticas**:

1. **Criar Relatório Clara e Ação-Oriented**
   ```markdown
   ## Finding: SQL Injection em UserService.getUser()
   
   ### O Problema
   O código concatena input do usuário diretamente em query SQL, permitindo SQL Injection.
   
   ### Localização
   - Arquivo: `src/services/UserService.java`
   - Linha: 45
   - Função: `getUser(String id)`
   
   ### Código Problemático
   ```java
   String query = "SELECT * FROM users WHERE id = " + id;  // ❌ Inseguro
   ```
   
   ### Como Corrigir
   ```java
   String query = "SELECT * FROM users WHERE id = ?";  // ✅ Seguro
   PreparedStatement stmt = conn.prepareStatement(query);
   stmt.setString(1, id);
   ```
   
   ### Por Que Isso Importa?
   - Risco: Ataque pode acessar dados de outros usuários
   - Compliance: Viola PCI-DSS se dados de cartão envolvidos
   - Prioridade: P1 - Corrigir antes do próximo release
   
   ### Referência
   - OWASP: https://owasp.org/www-community/attacks/SQL_Injection
   - CWE: CWE-89
   ```

2. **Integrar em Code Review**
   - Criar comentário no PR com link para finding
   - Sugerir correção específica
   - Oferecer ajuda para implementar correção

3. **Sessões de Treinamento Curto**
   - 15 min: "Como interpretar SAST findings"
   - Mostrar exemplos de true vs false positives
   - Compartilhar cheat sheet de correções comuns

#### Cenário 4: Convencendo Management a Investir em SAST

**Situação Real**: Você acredita que SAST seria valioso, mas precisa justificar investimento para gestão.

**Argumentos Eficazes**:

1. **ROI (Return on Investment)**
   - Vulnerabilidade encontrada em dev: $50-200 para corrigir
   - Vulnerabilidade em produção: $50,000-500,000+ (breach)
   - **ROI**: 250-10,000x mais barato encontrar cedo

2. **Compliance e Auditoria**
   - Muitos padrões (PCI-DSS, SOC2, ISO 27001) exigem análise estática
   - SAST fornece evidência auditável de testes de segurança

3. **Caso Real de Negócio**
   - "Projeto X teve breach que custou $200k. SAST teria detectado vulnerabilidade em dev por $100"

4. **Métricas de Sucesso**
   - Definir KPIs: "Reduzir vulnerabilidades críticas em 50% em 6 meses"
   - Medir antes/depois

### Métricas e KPIs de SAST

Para demonstrar valor de SAST, meça:

**Métricas Principais**:

1. **Cobertura de Código**
   - % do código analisado por SAST
   - Meta: 100% de código novo

2. **Tempo de Detecção**
   - Tempo médio entre código escrito e vulnerabilidade detectada
   - Meta: < 1 dia (com CI/CD)

3. **Taxa de Correção**
   - % de vulnerabilities corrigidas vs encontradas
   - Meta: 80%+ de Critical/High corrigidas

4. **False Positive Rate**
   - % de findings que são false positives
   - Meta: < 30% (tune regras para reduzir)

5. **Redução de Vulnerabilidades**
   - Número total de vulnerabilities ao longo do tempo
   - Meta: Redução de 20-30% por trimestre

**Exemplo de Dashboard Executivo**:

```
┌─────────────────────────────────────────────────────┐
│  SAST METRICS - ÚLTIMOS 6 MESES                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Vulnerabilidades Críticas: 45 → 12 (-73%) ✅      │
│  Tempo Médio de Detecção: 7 dias → 4 horas ✅      │
│  Taxa de Correção: 62% → 85% ✅                    │
│  False Positive Rate: 35% → 22% ✅                 │
│                                                     │
│  ROI Estimado: $180,000 economizados               │
│  (Baseado em 6 vulnerabilidades críticas            │
│   encontradas antes de produção)                    │
└─────────────────────────────────────────────────────┘
```

### Troubleshooting Comum: Problemas Reais que QAs Enfrentam

#### Problema 1: "SonarQube Está Lento (>10 minutos por scan)"

**Causas Comuns**:
- Projeto muito grande
- Muitas linguagens sendo analisadas
- Qualidade Gate muito complexo

**Soluções**:
```properties
# sonar-project.properties
# Analisar apenas código fonte, não testes
sonar.tests=test  # Separar código de testes
sonar.test.inclusions=**/*Test.java

# Excluir arquivos grandes/não relevantes
sonar.exclusions=**/*.min.js,**/vendor/**,**/node_modules/**

# Otimizar análise
sonar.analysis.mode=preview  # Para análise rápida (sem salvar histórico)
```

#### Problema 2: "Quality Gate Está Bloqueando Todo o Time"

**Solução Gradual**:
1. **Fase 1 (Permissivo)**: Bloquear apenas Critical novas
2. **Fase 2 (Médio)**: Bloquear Critical + High novas
3. **Fase 3 (Rigoroso)**: Bloquear Critical + High totais

```yaml
# Quality Gate Gradual (exemplo)
Sonar way (Ajustado):
  - Security Rating: A (qualquer que seja)
  - New Vulnerabilities: 0 Critical  # Fase 1
  - New Vulnerabilities: Máx 10 High  # Fase 1
  - Security Hotspots: 0 Critical/High novas  # Fase 2
```

#### Problema 3: "SAST Encontra Vulnerabilidade, mas Código Não É Executado"

**Validação Rápida**:
- Código está em produção? ✅ → Corrigir | ❌ → Avaliar
- Código é chamado por algum endpoint? ✅ → Corrigir | ❌ → Prioridade baixa
- Código está morto (deprecated)? ✅ → Remover código | ❌ → Avaliar

**Ação**: Marcar como "Aceitar Risco" com justificativa documentada.

---

## 🔄 SAST vs Outras Metodologias de Teste

### Comparação: SAST, DAST, IAST, SCA

SAST não é a única forma de testar segurança. É importante entender diferenças:

#### Tabela Comparativa Completa

| Aspecto | SAST | DAST | IAST | SCA |
|---------|------|------|------|-----|
| **Quando Executa** | Antes de executar (código estático) | Aplicação em execução | Aplicação em execução (instrumentado) | Análise de dependências |
| **O que Analisa** | Código-fonte, bytecode | Aplicação rodando (black-box) | Código em execução (instrumentado) | Bibliotecas e dependências |
| **Quando Usar** | Durante desenvolvimento | Testes de integração/staging | Testes de integração/staging | Durante desenvolvimento |
| **Vantagens** | Precoce, barato, cobre todo código | Testa comportamento real, encontra runtime issues | Combina SAST e DAST | Encontra vulnerabilidades em libs |
| **Limitações** | False positives, não testa runtime | Só testa o que executa, precisa de app rodando | Overhead de performance, complexidade | Não encontra bugs no código próprio |
| **Exemplos de Ferramentas** | SonarQube, Semgrep, Checkmarx | OWASP ZAP, Burp Suite | Contrast Security, Veracode | Snyk, Dependabot, npm audit |
| **Tempo de Execução** | Minutos a horas | Minutos a horas | Contínuo durante execução | Minutos |
| **Custo** | Baixo-Médio (open source disponível) | Baixo-Médio | Alto | Baixo (muitas gratuitas) |
| **False Positives** | Muitos (20-40%) | Poucos (5-10%) | Médios (10-15%) | Muito poucos (<5%) |
| **Precisão** | Média-Alta (depende de ferramenta) | Alta | Muito Alta | Muito Alta |

### Diagrama: Posicionamento no SDLC

```
┌─────────────────────────────────────────────────────────┐
│  METODOLOGIAS DE TESTE NO SDLC                         │
│                                                         │
│  Requisitos → Design → Desenvolvimento → Testes → Prod │
│                                                         │
│     │          │            │            │       │     │
│     │          │            ▼            │       │     │
│     │          │        ┌───────┐       │       │     │
│     │          │        │ SAST  │       │       │     │
│     │          │        │(Código│       │       │     │
│     │          │        │Estático)      │       │     │
│     │          │        └───────┘       │       │     │
│     │          │            │            │       │     │
│     │          │            ▼            ▼       │     │
│     │          │        ┌───────┐   ┌───────┐  │     │
│     │          │        │  SCA  │   │ IAST  │  │     │
│     │          │        │(Deps) │   │(App   │  │     │
│     │          │        │       │   │Instrumentada)│ │
│     │          │        └───────┘   └───────┘  │     │
│     │          │            │            │       │     │
│     │          │            ▼            ▼       ▼     │
│     │          │                    ┌───────┐ ┌─────┐ │
│     │          │                    │ DAST  │ │Prod │ │
│     │          │                    │(App   │ │(Breach│
│     │          │                    │Rodando)│ │Response)│
│     │          │                    └───────┘ └─────┘ │
│                                                         │
│  SAST: Mais cedo = Mais barato                         │
└─────────────────────────────────────────────────────────┘
```

### Quando Usar Cada Abordagem

**SAST é ideal quando**:
- ✅ Você quer encontrar vulnerabilidades durante desenvolvimento
- ✅ Precisa analisar todo o código, incluindo branches não testados
- ✅ Quer educar desenvolvedores sobre padrões inseguros
- ✅ Precisa atender compliance que exige análise estática
- ✅ Tem orçamento limitado (muitas ferramentas open source)

**SAST não é suficiente quando**:
- ❌ Você precisa testar comportamento em runtime
- ❌ Precisa validar configuração de servidor
- ❌ Quer testar autenticação/autorização complexa
- ❌ Precisa encontrar problemas de infraestrutura

**Conclusão**: SAST deve ser combinado com DAST, IAST e SCA para cobertura completa!

---

## 🔍 Conceitos Teóricos

### Como Funciona SAST?

> **📚 Aprofundamento Opcional**: As seções abaixo explicam detalhes técnicos internos de como SAST funciona. Se você está focado em **usar SAST na prática**, pode pular para a seção ["Tipos de Análise SAST"](#tipos-de-análise-sast) sem perder conteúdo essencial. No entanto, entender como funciona internamente ajuda a interpretar resultados e ajustar configurações.

#### 🔬 Processo de Análise Estática (Aprofundamento Técnico)

SAST funciona em múltiplas camadas de análise, transformando código-fonte em representações abstratas que são então analisadas por diferentes algoritmos:

```
┌─────────────────────────────────────────────────────────┐
│         ARQUITETURA DE PROCESSAMENTO SAST               │
└─────────────────────────────────────────────────────────┘

FASE 1: Parse e Análise Léxica/Sintática
┌─────────────────────────────────────────────┐
│ Código-Fonte Original                       │
│ ┌──────────────────────────────────────┐   │
│ │ userInput = request.getParameter();  │   │
│ │ query = "SELECT * WHERE id=" +       │   │
│ │         userInput;                   │   │
│ │ db.execute(query);                   │   │
│ └──────────────────────────────────────┘   │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ Lexical Analysis (Tokenização)              │
│ ┌──────────────────────────────────────┐   │
│ │ [IDENTIFIER: userInput]              │   │
│ │ [OPERATOR: =]                        │   │
│ │ [IDENTIFIER: request]                │   │
│ │ [OPERATOR: .]                        │   │
│ │ [METHOD: getParameter]               │   │
│ │ [OPERATOR: (] ...                    │   │
│ └──────────────────────────────────────┘   │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ Syntax Analysis (AST - Abstract Syntax Tree)│
│ ┌──────────────────────────────────────┐   │
│ │ AssignmentExpression                 │   │
│ │   ├─ left: Identifier (userInput)   │   │
│ │   └─ right: CallExpression          │   │
│ │       ├─ object: request            │   │
│ │       └─ method: getParameter       │   │
│ └──────────────────────────────────────┘   │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ Semantic Analysis (Símbolos e Tipos)        │
│ ┌──────────────────────────────────────┐   │
│ │ userInput: String                    │   │
│ │   - Source: request.getParameter     │   │
│ │   - Tainted: true                    │   │
│ │   - Trust: low                       │   │
│ │                                       │   │
│ │ query: String                        │   │
│ │   - Contains: userInput (tainted)    │   │
│ │   - Tainted: true                    │   │
│ └──────────────────────────────────────┘   │
└────────────────┬────────────────────────────┘
                 │
                 ▼
FASE 2: Análise de Segurança
┌─────────────────────────────────────────────┐
│ Pattern Matching Engine                     │
│ ┌──────────────────────────────────────┐   │
│ │ Regra: SQL Injection Pattern         │   │
│ │ Pattern: "...$VAR..."                │   │
│ │ Match: "SELECT * WHERE id=" + user   │   │
│ │ Status: ⚠️ POTENTIAL VULNERABILITY   │   │
│ └──────────────────────────────────────┘   │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ Data Flow Analysis Engine                   │
│ ┌──────────────────────────────────────┐   │
│ │ Source: request.getParameter()       │   │
│ │   → userInput (tainted)              │   │
│ │   → query (tainted)                  │   │
│ │   → db.execute() (sink)              │   │
│ │                                       │   │
│ │ Path: Source → ... → Sink            │   │
│ │ Sanitization: NONE                   │   │
│ │ Status: ⚠️ CONFIRMED VULNERABILITY   │   │
│ └──────────────────────────────────────┘   │
└────────────────┬────────────────────────────┘
                 │
                 ▼
FASE 3: Detecção e Classificação
┌─────────────────────────────────────────────┐
│ Vulnerability Detection Engine               │
│ ┌──────────────────────────────────────┐   │
│ │ Type: SQL Injection                  │   │
│ │ CWE: CWE-89                          │   │
│ │ OWASP: A03:2021 – Injection          │   │
│ │ Severity: Critical 🔴                │   │
│ │ Confidence: High (95%)               │   │
│ │                                       │   │
│ │ Location:                            │   │
│ │   File: src/UserService.java         │   │
│ │   Line: 45                           │   │
│ │   Column: 12-50                      │   │
│ │                                       │   │
│ │ Taint Path:                          │   │
│ │   Line 15: request.getParameter()    │   │
│ │   Line 20: query = "..." + userInput │   │
│ │   Line 45: db.execute(query)         │   │
│ └──────────────────────────────────────┘   │
└────────────────┬────────────────────────────┘
                 │
                 ▼
FASE 4: Geração de Relatório
┌─────────────────────────────────────────────┐
│ Report Generation Engine                     │
│ ┌──────────────────────────────────────┐   │
│ │ Finding #1: SQL Injection            │   │
│ │ ───────────────────────────────────  │   │
│ │ Severity: Critical 🔴                │   │
│ │ CWE: CWE-89                          │   │
│ │ OWASP: A03:2021 – Injection          │   │
│ │                                       │   │
│ │ Description:                         │   │
│ │ User input is directly concatenated  │   │
│ │ into SQL query without sanitization. │   │
│ │ This allows SQL Injection attacks.   │   │
│ │                                       │   │
│ │ Recommendation:                      │   │
│ │ Use parameterized queries (prepared  │   │
│ │ statements) instead of string        │   │
│ │ concatenation.                       │   │
│ │                                       │   │
│ │ Fix Example:                         │   │
│ │ PreparedStatement stmt =             │   │
│ │   conn.prepareStatement(             │   │
│ │     "SELECT * WHERE id = ?");        │   │
│ │ stmt.setString(1, userInput);        │   │
│ └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

> **💡 Por Que Isso Importa?**: Entender como SAST processa código ajuda você a:
> - Interpretar resultados com mais precisão
> - Ajustar configurações para reduzir false positives
> - Escolher ferramentas apropriadas para seu contexto
> - Explicar para desenvolvedores por que SAST encontrou uma vulnerabilidade

#### Componentes Técnicos Internos de SAST (Aprofundamento)

**1. Parser (Analisador Sintático)**
- **Função**: Converte código-fonte em AST (Abstract Syntax Tree)
- **Entrada**: Código-fonte em linguagem específica
- **Saída**: Árvore sintática abstrata
- **Complexidade**: Varia por linguagem (Python é mais simples que Java)
- **Exemplo**: `userInput = request.getParameter()` → AST com nós Assignment, Identifier, CallExpression

**2. Semantic Analyzer (Analisador Semântico)**
- **Função**: Adiciona informações de tipos, escopo e símbolos
- **Entrada**: AST do Parser
- **Saída**: AST enriquecido com informações semânticas
- **Adiciona**: Tipos de variáveis, escopo, símbolos, referências

**3. Control Flow Graph Builder (Construtor de CFG)**
- **Função**: Constrói grafo de fluxo de controle do código
- **Entrada**: AST semântico
- **Saída**: CFG (Control Flow Graph)
- **Usado para**: Análise de fluxo de controle, verificar caminhos de execução

**4. Data Flow Analyzer (Analisador de Fluxo de Dados)**
- **Função**: Rastreia como dados fluem pelo código
- **Entrada**: CFG + AST
- **Saída**: Def-Use chains, taint propagation paths
- **Usado para**: Detectar se dados não confiáveis chegam a pontos perigosos

**5. Rule Engine (Motor de Regras)**
- **Função**: Aplica regras de detecção de vulnerabilidades
- **Entrada**: AST, CFG, Data Flow information
- **Saída**: Findings potenciais
- **Tipos de Regras**: Pattern matching, taint analysis rules, control flow rules

**6. False Positive Filter (Filtro de False Positives)**
- **Função**: Tenta reduzir false positives usando heurísticas e ML
- **Entrada**: Findings brutos
- **Saída**: Findings filtrados com confidence score
- **Métodos**: Machine Learning, heurísticas, análise de contexto

**7. Report Generator (Gerador de Relatórios)**
- **Função**: Gera relatórios formatados com findings
- **Entrada**: Findings filtrados
- **Saída**: Relatórios (JSON, HTML, SARIF, etc.)
- **Inclui**: Severidade, localização, recomendações, exemplos de correção

#### Tipos de Análise SAST

**1. Pattern Matching (Matching de Padrões)**

**Definição Técnica**: Procura por padrões conhecidos de código inseguro usando expressões regulares ou árvores sintáticas (AST patterns).

**Como Funciona**:
```
1. Parse do código em AST (Abstract Syntax Tree)
2. Aplica regras que procuram padrões específicos
3. Exemplo de regra: "procura por 'eval(' seguido de variável"
4. Reporta quando padrão é encontrado
```

**Exemplos de Padrões Procurados**:
- `eval()`, `exec()`, `Function()` - Code Injection
- Concatenação de string em SQL - SQL Injection
- `innerHTML = userInput` - XSS
- `fs.readFile(userPath)` - Path Traversal
- Hardcoded secrets (regex: `password.*=.*"..."`)

**Vantagens**:
- ✅ Rápido (segundos para projetos grandes)
- ✅ Fácil de implementar (regras simples)
- ✅ Boa cobertura de padrões conhecidos
- ✅ Funciona bem em múltiplas linguagens

**Desvantagens**:
- ❌ Muitos false positives (20-40%)
- ❌ Não entende contexto (pode flagar código seguro)
- ❌ Não rastreia fluxo de dados
- ❌ Pode não encontrar padrões complexos

**Uso Ideal**: Scan rápido inicial, regras simples de compliance

---

**2. Data Flow Analysis (Análise de Fluxo de Dados)**

**Definição Técnica**: Rastreia dados desde sua entrada (source) até uso (sink) através do código, analisando como dados fluem entre variáveis e funções.

**Como Funciona**:
```
1. Identifica Sources (entrada de dados não confiáveis)
   - request.getParameter()
   - request.body
   - environment variables
   - database queries

2. Identifica Sinks (uso perigoso de dados)
   - executeQuery() - SQL Injection
   - innerHTML = - XSS
   - eval() - Code Injection
   - fs.readFile() - Path Traversal

3. Rastreia fluxo de dados
   - source → variável → função → variável → sink

4. Detecta se dados não sanitizados chegam ao sink
```

**Diagrama de Data Flow**:

```
┌─────────────────────────────────────────────────────────┐
│              DATA FLOW ANALYSIS - SQL INJECTION         │
└─────────────────────────────────────────────────────────┘

Source (Fonte de Dados Não Confiáveis)
┌─────────────────────┐
│ userInput =         │  ← SOURCE identificado
│ request.get         │     (dados não confiáveis)
│ Parameter("id")     │
└──────────┬──────────┘
           │
           │ Data flows through:
           ▼
┌─────────────────────┐
│ userId = userInput  │  ← Passagem por variável
└──────────┬──────────┘
           │
           │ Data flows to:
           ▼
┌─────────────────────┐
│ query = "SELECT *   │  ← Concatenação com query
│ FROM users          │
│ WHERE id = " +      │
│ userId              │
└──────────┬──────────┘
           │
           │ Data flows to:
           ▼
┌─────────────────────┐
│ result = db.execute │  ← SINK identificado
│ (query)             │     (uso perigoso)
└─────────────────────┘

SAST detecta: "Unsanitized data from Source reaches 
Sink → SQL Injection vulnerability" ⚠️

SOLUÇÃO: Sanitizer entre Source e Sink
┌─────────────────────┐
│ sanitized =         │  ← SANITIZER adicionado
│ escapeSQL(userId)   │     (prepara dados)
└─────────────────────┘
```

**Vantagens**:
- ✅ Encontra vulnerabilidades reais (menos false positives)
- ✅ Entende contexto (rastreia fluxo completo)
- ✅ Detecta padrões complexos
- ✅ Menos false positives (10-20%)

**Desvantagens**:
- ❌ Mais lento (minutos para projetos grandes)
- ❌ Complexo de implementar
- ❌ Pode não rastrear todos os caminhos
- ❌ Requer configuração de sources/sinks

**Uso Ideal**: Análise profunda, validação de findings

---

**3. Control Flow Analysis (Análise de Fluxo de Controle)**

**Definição Técnica**: Analisa caminhos de execução do código para verificar se controles de segurança (autenticação, autorização, validação) são aplicados antes de operações sensíveis.

**Como Funciona**:
```
1. Constrói Control Flow Graph (CFG)
   - Nós: blocos de código (funções, loops, conditions)
   - Arestas: caminhos de execução (se, então, senão, loops)

2. Identifica operações sensíveis
   - Acesso a dados sensíveis
   - Operações administrativas
   - Operações financeiras
   - Modificação de dados

3. Verifica se controles de segurança existem
   - Autenticação antes de acesso?
   - Autorização antes de operação?
   - Validação antes de processamento?

4. Reporta se caminho sem controle existe
```

**Diagrama de Control Flow**:

```
┌─────────────────────────────────────────────────────────┐
│         CONTROL FLOW ANALYSIS - BROKEN ACCESS CONTROL  │
└─────────────────────────────────────────────────────────┘

Caminho 1: ✅ SEGURO
┌─────────────────┐
│ authenticate()  │  ← Autenticação
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ checkRole()     │  ← Autorização
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ getAdminData()  │  ← Operação sensível
└─────────────────┘
✅ SAST: OK - Caminho seguro

Caminho 2: ❌ VULNERÁVEL
┌─────────────────┐
│ getAdminData()  │  ← Operação sensível
└─────────────────┘    SEM autenticação/autorização
⚠️ SAST detecta: "Sensitive operation without 
authentication/authorization → Broken Access Control"
```

**Exemplo Prático**:

```java
// ❌ VULNERÁVEL - Control Flow Analysis detecta:
@GetMapping("/admin/users")
public List<User> getAdminUsers() {
    // Não verifica autenticação/autorização
    return userService.getAllUsers();  // ← Operação sensível sem controle
}

// ✅ SEGURO - Control Flow Analysis confirma:
@GetMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")  // ← Controle de segurança
public List<User> getAdminUsers() {
    return userService.getAllUsers();  // ✅ Operação protegida
}
```

**Vantagens**:
- ✅ Encontra problemas de lógica de segurança
- ✅ Detecta Broken Access Control
- ✅ Identifica caminhos de execução não protegidos
- ✅ Útil para verificar arquitetura de segurança

**Desvantagens**:
- ❌ Muito complexo (exponencial em caminhos)
- ❌ Pode não encontrar todos os caminhos (undecidability)
- ❌ Lento (horas para projetos grandes)
- ❌ Requer configuração de controles de segurança

**Uso Ideal**: Análise de arquitetura, validação de controles de acesso

---

**4. Taint Analysis (Análise de Contaminação)**

**Definição Técnica**: Tipo especializado de Data Flow Analysis que rastreia especificamente dados "tainted" (contaminados/não confiáveis) desde sua origem até uso perigoso, verificando se foram sanitizados no caminho.

**Conceitos Fundamentais**:

- **Source (Fonte)**: Ponto onde dados não confiáveis entram no sistema
  - Input do usuário: `request.getParameter()`, `request.body`
  - Arquivos: `file.read()`, `fs.readFile()`
  - Rede: `socket.receive()`, API calls
  - Ambiente: `process.env`, `config files`

- **Sink (Ralo)**: Ponto onde dados são usados de forma perigosa
  - SQL: `executeQuery()`, `query()`
  - Execução: `eval()`, `exec()`, `system()`
  - HTML: `innerHTML =`, `document.write()`
  - Sistema de arquivos: `fs.readFile()`, `open()`
  - Paths: `os.path.join()`, `path.resolve()`

- **Sanitizer (Sanitizador)**: Função que "limpa" dados contaminados
  - SQL: `escapeSQL()`, `prepareStatement()`, parameterized queries
  - XSS: `escapeHtml()`, `DOMPurify.sanitize()`
  - Path: `os.path.basename()`, `path.normalize()`
  - Command: `subprocess.run()` com lista de argumentos

**Fluxo de Taint Analysis**:

```
┌─────────────────────────────────────────────────────────┐
│        TAINT ANALYSIS - DETECÇÃO DE SQL INJECTION       │
└─────────────────────────────────────────────────────────┘

1. Source Identification (Identificação da Fonte)
┌─────────────────────┐
│ userInput =         │  ← SOURCE: request.getParameter()
│ request.get         │     Taint: TRUE
│ Parameter("id")     │     Type: String
└──────────┬──────────┘     Trust: LOW
           │
           │ [Taint propagates]
           ▼

2. Taint Propagation (Propagação de Contaminação)
┌─────────────────────┐
│ userId = userInput  │  ← Taint: TRUE (herda de userInput)
└──────────┬──────────┘     Type: String
           │                Trust: LOW
           │
           │ [Taint propagates]
           ▼

┌─────────────────────┐
│ query = "SELECT *   │  ← Taint: TRUE (userId está tainted)
│ FROM users          │     Type: String
│ WHERE id = " +      │     Trust: LOW
│ userId              │
└──────────┬──────────┘
           │
           │ [Taint propagates]
           ▼

3. Sanitizer Check (Verificação de Sanitização)
┌─────────────────────┐
│ sanitized =         │  ← SANITIZER aplicado?
│ escapeSQL(userId)   │     Não encontrado ❌
└──────────┬──────────┘
           │
           │ [Taint continues - NO sanitization]
           ▼

4. Sink Detection (Detecção de Sink)
┌─────────────────────┐
│ result = db.execute │  ← SINK: executeQuery()
│ (query)             │     Taint: TRUE
└─────────────────────┘     Sanitized: FALSE
                            ⚠️ VULNERABILIDADE DETECTADA!

SAST Report:
- Vulnerability: SQL Injection
- Severity: Critical
- Source: request.getParameter("id") [line 15]
- Sink: db.execute(query) [line 45]
- Taint Path: userInput → userId → query → db.execute
- Sanitization: NONE
- Recommendation: Use parameterized queries (prepared statements)
```

**Vantagens**:
- ✅ Detecção precisa de vulnerabilidades reais
- ✅ Rastreia fluxo completo de dados
- ✅ Identifica quando sanitização está faltando
- ✅ Menos false positives (5-15%)
- ✅ Entende contexto de dados

**Desvantagens**:
- ❌ Muito lento (horas para projetos grandes)
- ❌ Complexo de implementar e configurar
- ❌ Requer configuração de sources/sinks/sanitizers
- ❌ Pode não rastrear todos os caminhos
- ❌ Pode gerar false negatives (caminhos não rastreados)

**Uso Ideal**: Análise profunda de segurança, validação de correções

---

### Comparação dos Tipos de Análise SAST

| Tipo de Análise | Velocidade | Precisão | False Positives | Complexidade | Melhor Para |
|----------------|------------|----------|-----------------|--------------|-------------|
| **Pattern Matching** | ⚡⚡⚡ Muito Rápido | 🎯🎯 Média | 🔴 Muitos (20-40%) | ⭐ Simples | Scan rápido, compliance |
| **Data Flow** | ⚡⚡ Médio | 🎯🎯🎯 Alta | 🟡 Médios (10-20%) | ⭐⭐ Média | Análise profunda |
| **Control Flow** | ⚡ Lento | 🎯🎯🎯 Alta | 🟡 Médios (10-15%) | ⭐⭐⭐ Complexa | Arquitetura, acesso |
| **Taint Analysis** | ⚡ Muito Lento | 🎯🎯🎯🎯 Muito Alta | 🟢 Poucos (5-15%) | ⭐⭐⭐⭐ Muito Complexa | Análise crítica |

**Recomendação**: Use combinação de múltiplos tipos:
- **Pattern Matching** para scan rápido (Semgrep)
- **Taint Analysis** para validação profunda (Checkmarx, SonarQube)

**Diagrama de Taint Analysis**:

```
┌─────────────────────────────────────────────────────────┐
│           EXEMPLO: TAINT ANALYSIS - SQL INJECTION      │
└─────────────────────────────────────────────────────────┘

Source (Fonte)
┌──────────────┐
│ userInput =  │  ← Dados não confiáveis entram
│ request.get  │
│ Parameter()  │
└──────┬───────┘
       │
       │ Taint propagates
       ▼
┌──────────────────────┐
│ query = "SELECT *    │
│ FROM users WHERE id="│
│ + userInput          │  ← Dados contaminados usados
└──────┬───────────────┘     sem sanitização
       │
       │ Tainted data reaches sink
       ▼
┌──────────────┐
│ db.execute   │  ← SINK: Execução perigosa
│ (query)      │     ⚠️ VULNERABILIDADE DETECTADA!
└──────────────┘

SAST detecta: "Tainted data from Source reaches Sink 
without sanitization → SQL Injection vulnerability"
```

### Principais Ferramentas SAST

#### 1. SonarQube

**Definição**: Plataforma open-source que combina análise de qualidade de código com segurança. Analisa código em mais de 25 linguagens e fornece métricas de qualidade, bugs, code smells e vulnerabilidades de segurança.

**Características Principais**:
- ✅ Open-source (Community Edition) + versões comerciais
- ✅ Suporta 25+ linguagens (Java, JavaScript, Python, C#, PHP, etc.)
- ✅ Integração com IDEs (IntelliJ, VS Code, Eclipse)
- ✅ Integração CI/CD (Jenkins, GitLab CI, GitHub Actions)
- ✅ Dashboards e relatórios visuais
- ✅ Regras de segurança baseadas em OWASP, CWE, SANS Top 25
- ✅ Quality Gates (bloqueia merge se não passar critérios)

**Analogia**:
SonarQube é como um "checkup completo" de código. Assim como um médico faz exames diversos (sangue, pressão, raio-X) para ter visão completa da saúde, SonarQube faz múltiplas análises (bugs, segurança, qualidade, duplicação) para ter visão completa da saúde do código.

**Exemplo de Configuração Básica**:

```yaml
# sonar-project.properties
sonar.projectKey=meu-projeto
sonar.projectName=Meu Projeto
sonar.projectVersion=1.0
sonar.sources=src
sonar.language=java
sonar.sourceEncoding=UTF-8

# Regras de segurança
sonar.security.hotspots=high,medium
```

**Dashboard SonarQube**:
```
┌─────────────────────────────────────────────────────────┐
│  SONARQUBE DASHBOARD                                   │
│                                                         │
│  Vulnerabilidades de Segurança: 23                     │
│  ├─ Critical: 2                                        │
│  ├─ High: 8                                            │
│  ├─ Medium: 10                                         │
│  └─ Low: 3                                             │
│                                                         │
│  Security Hotspots: 45                                 │
│  Bugs: 127                                             │
│  Code Smells: 342                                      │
│                                                         │
│  Cobertura de Testes: 78%                              │
│  Duplicação: 3.2%                                      │
│                                                         │
│  Quality Gate: ✅ PASSED                               │
└─────────────────────────────────────────────────────────┘
```

#### 2. Semgrep

**Definição**: Ferramenta open-source de análise estática que usa "rules as code" - regras escritas em YAML que são fáceis de criar e customizar. Foca em velocidade e simplicidade.

**Características Principais**:
- ✅ Open-source e gratuito
- ✅ Muito rápido (segundos para projetos grandes)
- ✅ Rules as code (regras em YAML, fáceis de criar)
- ✅ Suporta 20+ linguagens
- ✅ Regras pré-construídas (OWASP, PCI-DSS, SOC2)
- ✅ Integração CI/CD nativa
- ✅ Sem necessidade de servidor (CLI tool)

**Analogia**:
Semgrep é como um "detector de metais" rápido e portátil. Você pode usá-lo rapidamente em qualquer lugar, configurar facilmente o que procurar (regras), e ele encontra problemas rapidamente. Não é tão completo quanto um "raio-X" (SonarQube), mas é muito mais rápido e prático.

**Exemplo de Regra Semgrep**:

```yaml
# regras/sql-injection.yaml
rules:
  - id: sql-injection
    patterns:
      - pattern-either:
          - pattern: $X.executeQuery("...$Y...")
          - pattern: $X.execute("...$Y...")
    message: "Potential SQL Injection. User input '$Y' is directly concatenated into SQL query."
    languages: [java, python, javascript]
    severity: ERROR
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 – Injection"
```

**Uso Prático**:

```bash
# Scan básico
semgrep --config=auto .

# Scan com regras customizadas
semgrep --config=regras/ .

# Scan com saída JSON
semgrep --config=auto --json --output=results.json .
```

#### 3. Checkmarx

**Definição**: Ferramenta comercial enterprise-grade de SAST que oferece análise profunda de código-fonte com suporte a mais de 35 linguagens e 80 frameworks.

**Características Principais**:
- ✅ Comercial (enterprise, mais caro)
- ✅ Suporte extensivo (35+ linguagens, 80+ frameworks)
- ✅ Análise muito profunda (data flow, control flow)
- ✅ Menos false positives (usando AI/ML)
- ✅ Integração IDE em tempo real
- ✅ "Best Fix Location" (sugere melhor lugar para corrigir)
- ✅ Compliance mapping (PCI-DSS, OWASP, etc.)

**Analogia**:
Checkmarx é como um "laboratório médico completo" com todos os exames possíveis. É caro, mas oferece análise muito profunda e precisa. Ideal para empresas grandes que precisam de cobertura completa e precisão máxima.

**Comparação Rápida das 3 Ferramentas**:

| Aspecto | SonarQube | Semgrep | Checkmarx |
|---------|-----------|---------|-----------|
| **Custo** | Grátis (Community) ou Pago | Grátis | Pago (caro) |
| **Velocidade** | Médio (minutos) | Muito Rápido (segundos) | Lento (horas) |
| **Precisão** | Média-Alta | Média | Muito Alta |
| **False Positives** | Médios (20-30%) | Médios (15-25%) | Baixos (5-10%) |
| **Facilidade de Uso** | Média | Alta | Média |
| **Customização** | Média | Muito Alta (YAML) | Média |
| **Suporte de Linguagens** | 25+ | 20+ | 35+ |
| **Melhor Para** | Equipes médias/grandes | Desenvolvedores individuais/startups | Empresas grandes |

### Ferramentas SAST Específicas por Linguagem

Além das ferramentas universais, existem ferramentas específicas otimizadas para cada linguagem:

#### Python: Bandit

**Definição**: Ferramenta SAST específica para Python que procura por problemas de segurança comuns.

**Uso Prático**:

```bash
# Instalação
pip install bandit

# Scan básico
bandit -r src/

# Scan com saída HTML
bandit -r src/ -f html -o report.html

# Scan com configuração customizada
bandit -r src/ -c bandit.yaml
```

**Exemplo de Saída**:

```
Issue: [B506:yaml_load] Use of unsafe yaml load. Allows arbitrary code execution.
Severity: High   Confidence: High
Location: src/config.py:15
  14  import yaml
  15  config = yaml.load(open('config.yaml'))  # ← VULNERABILIDADE
```

#### Ruby: Brakeman

**Definição**: Analisador estático de segurança para aplicações Ruby on Rails.

**Uso Prático**:

```bash
# Instalação (Gemfile)
gem 'brakeman'

# Scan
brakeman

# Scan com JSON
brakeman -f json -o report.json
```

#### JavaScript/TypeScript: ESLint Security Plugin

**Definição**: Plugin do ESLint que adiciona regras de segurança para JavaScript/TypeScript.

**Configuração**:

```javascript
// .eslintrc.js
module.exports = {
  plugins: ['security'],
  extends: ['plugin:security/recommended'],
  rules: {
    'security/detect-object-injection': 'error',
    'security/detect-non-literal-fs-filename': 'warn'
  }
};
```

#### Java: SpotBugs + FindSecBugs

**Definição**: SpotBugs encontra bugs, FindSecBugs adiciona regras de segurança.

**Integração Maven**:

```xml
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <configuration>
    <plugins>
      <plugin>
        <groupId>com.h3xstream.findsecbugs</groupId>
        <artifactId>findsecbugs-plugin</artifactId>
      </plugin>
    </plugins>
  </configuration>
</plugin>
```

### Interpretação de Resultados SAST

#### Severidade de Vulnerabilidades

SAST classifica vulnerabilidades por severidade:

```
┌─────────────────────────────────────────────────────────┐
│         CLASSIFICAÇÃO DE SEVERIDADE                    │
└─────────────────────────────────────────────────────────┘

CRITICAL (Crítico) 🔴
├─ Vulnerabilidade que permite:
│  • Remote Code Execution (RCE)
│  • SQL Injection com acesso a dados sensíveis
│  • Autenticação bypass completo
│  • Exposição de secrets/chaves
└─ Ação: Corrigir IMEDIATAMENTE, bloquear deploy

HIGH (Alto) 🟠
├─ Vulnerabilidade que permite:
│  • Privilege Escalation
│  • Cross-Site Scripting (XSS) em área autenticada
│  • Path Traversal que expõe arquivos
│  • Insecure Deserialization
└─ Ação: Corrigir em 1-2 sprints

MEDIUM (Médio) 🟡
├─ Vulnerabilidade que permite:
│  • Information Disclosure (sem dados sensíveis)
│  • XSS em área pública
│  • Weak Cryptography
│  • Missing Security Headers
└─ Ação: Corrigir quando possível

LOW (Baixo) 🟢
├─ Vulnerabilidades menores:
│  • Code Quality issues
│  • Best Practices não seguidas
│  • Security Hotspots (potenciais problemas)
└─ Ação: Endereçar gradualmente
```

#### False Positives vs True Positives

**False Positive**: SAST reporta vulnerabilidade que não existe na prática.

**Exemplo de False Positive**:

```python
# SAST detecta: "Hardcoded password"
password = "default_password_123"  # ← Flagged

# Mas na prática:
if password == "default_password_123":
    raise Exception("Must change default password")  # ← Não é vulnerabilidade!
```

**True Positive**: SAST reporta vulnerabilidade real.

**Exemplo de True Positive**:

```python
# SAST detecta: "SQL Injection"
user_id = request.get('id')  # ← User input
query = f"SELECT * FROM users WHERE id = {user_id}"  # ← VULNERÁVEL
db.execute(query)  # ← SQL Injection confirmado
```

#### Como Validar Findings

**Processo de Validação Detalhado**:

```
┌─────────────────────────────────────────────────────────┐
│        PROCESSO DE VALIDAÇÃO DE FINDINGS SAST           │
└─────────────────────────────────────────────────────────┘

1. SAST Reporta Finding
   │
   ├─ Recebe: Severidade, Localização, Descrição, CWE
   │
   ▼
2. Análise Inicial do Contexto
   │
   ├─ Ler código ao redor (mínimo 10 linhas antes/depois)
   ├─ Verificar se dados são sanitizados (escaping, validation)
   ├─ Verificar se há controles de acesso (autenticação/autorização)
   ├─ Verificar se código está ativo (não é código morto)
   └─ Verificar se está em produção (risco imediato)
   │
   ├─ É False Positive?
   │  │
   │  ▼
   │  Marcar como "Won't Fix" / "False Positive"
   │  ├─ Documentar razão
   │  ├─ Adicionar comentário no código (se aplicável)
   │  └─ Configurar exceção na ferramenta SAST
   │
   └─ É True Positive?
      │
      ▼
3. Análise Detalhada de Risco
   │
   ├─ Severidade SAST vs Risco Real
   │  ├─ SAST Critical → Risco Real Critical? (confirmar)
   │  ├─ SAST High → Risco Real pode ser Critical? (investigar)
   │  └─ SAST Medium → Risco Real pode ser High? (avaliar contexto)
   │
   ├─ Exploitability (fácil explorar?)
   │  ├─ Requer autenticação? (reduz risco)
   │  ├─ Requer conhecimento interno? (reduz risco)
   │  ├─ Pode ser explorado via internet? (aumenta risco)
   │  └─ Já existe exploit público? (risco crítico)
   │
   ├─ Impacto (dados sensíveis afetados?)
   │  ├─ Dados de cartão (PCI-DSS) → Impacto Crítico
   │  ├─ Dados pessoais (LGPD) → Impacto Alto
   │  ├─ Dados financeiros → Impacto Crítico
   │  └─ Dados públicos → Impacto Baixo
   │
   └─ Contexto do Negócio
      ├─ Código em produção? (risco imediato)
      ├─ Código em desenvolvimento? (corrigir antes de deploy)
      ├─ Área crítica do sistema? (payment, auth, etc.)
      └─ Volume de usuários afetados? (muitos = maior impacto)
   │
   ▼
4. Priorização Final
   │
   ├─ Prioridade 1 (P1 - Corrigir IMEDIATAMENTE):
   │  ├─ Critical + Em produção + Dados sensíveis
   │  └─ Bloquear deploy, hotfix necessário
   │
   ├─ Prioridade 2 (P2 - Corrigir neste Sprint):
   │  ├─ Critical em desenvolvimento
   │  ├─ High + Em produção + Dados sensíveis
   │  └─ Corrigir antes do próximo release
   │
   ├─ Prioridade 3 (P3 - Corrigir no próximo Sprint):
   │  ├─ High em desenvolvimento
   │  ├─ Medium + Em produção
   │  └─ Planejar correção
   │
   └─ Prioridade 4 (P4 - Backlog):
      ├─ Medium em desenvolvimento
      ├─ Low + Em produção
      └─ Endereçar gradualmente
   │
   ▼
5. Ação Corretiva
   │
   ├─ Corrigir vulnerabilidade
   │  ├─ Implementar correção segura
   │  ├─ Adicionar testes de segurança
   │  └─ Validar com SAST novamente
   │
   ├─ Documentar risco aceito (se não corrigir)
   │  ├─ Justificativa técnica
   │  ├─ Análise de risco
   │  ├─ Mitigações implementadas
   │  └─ Aprovação de stakeholders
   │
   └─ Tracking e Follow-up
      ├─ Criar issue de tracking
      ├─ Atribuir responsável
      ├─ Definir prazo
      └─ Agendar revalidação
```

**Exemplo de Matriz de Priorização**:

| Severidade SAST | Exploitability | Impacto | Código em Prod | Prioridade Final |
|----------------|----------------|---------|----------------|------------------|
| Critical | Alta | Dados sensíveis | Sim | P1 - IMEDIATO |
| Critical | Alta | Dados sensíveis | Não | P2 - Este Sprint |
| Critical | Baixa | Dados não sensíveis | Sim | P2 - Este Sprint |
| High | Alta | Dados sensíveis | Sim | P2 - Este Sprint |
| High | Média | Dados sensíveis | Não | P3 - Próximo Sprint |
| Medium | Alta | Dados sensíveis | Sim | P3 - Próximo Sprint |
| Medium | Baixa | Dados não sensíveis | Não | P4 - Backlog |
| Low | Qualquer | Qualquer | Qualquer | P4 - Backlog |

**Template de Validação Completo**:

```markdown
## Finding: SQL Injection em UserService.getUser()

### Metadados do Finding
- **Severidade SAST**: Critical 🔴
- **CWE**: CWE-89 (SQL Injection)
- **OWASP Top 10**: A03:2021 – Injection
- **Localização**: `src/services/UserService.java:45`
- **Ferramenta**: SonarQube
- **Data do Finding**: 2026-01-14

### Código Flagado
```java
@GetMapping("/users/{id}")
public User getUser(@PathVariable String id) {
    // ❌ SAST detecta SQL Injection
    String query = "SELECT * FROM users WHERE id = " + id;
    return db.executeQuery(query);
}
```

### Análise de Contexto
- [ ] **Dados são validados antes de usar?**
  - ❌ Não há validação do parâmetro `id`
  - ❌ Permite qualquer string (pode conter SQL malicioso)
  
- [ ] **Há sanitização (prepared statements)?**
  - ❌ Usa concatenação de string em vez de prepared statement
  - ❌ Permite SQL Injection
  
- [ ] **Código está em produção?**
  - ✅ Sim, código está em produção (risco imediato)
  
- [ ] **Acesso requer autenticação?**
  - ✅ Sim, endpoint requer autenticação (reduz risco um pouco)
  
- [ ] **Dados sensíveis afetados?**
  - ✅ Sim, retorna dados de usuários completos (nomes, emails, etc.)

### Análise de Risco
**Exploitability**: ALTA ⚠️
- Pode ser explorado facilmente via API
- Exemplo de exploit: `GET /users/1 OR 1=1--`

**Impacto**: ALTO ⚠️
- Pode expor dados de todos os usuários
- Violação de LGPD/privacidade
- Potencial para escalação de privilégios

**Contexto**: CRÍTICO ⚠️
- Código em produção
- Endpoint público (requer apenas autenticação básica)
- Acesso a dados sensíveis

### Decisão
- [x] **True Positive - Corrigir imediatamente (P1)**
- [ ] False Positive - Marcar como resolvido (razão: ...)
- [ ] Aceitar Risco - Documentar (razão: ...)

### Correção Implementada
```java
@GetMapping("/users/{id}")
public User getUser(@PathVariable String id) {
    // ✅ Validação de entrada
    if (!isValidUserId(id)) {
        throw new IllegalArgumentException("Invalid user ID");
    }
    
    // ✅ Prepared Statement
    String query = "SELECT * FROM users WHERE id = ?";
    return db.executeQuery(query, id);  // Parâmetroizado
}
```

### Validação Pós-Correção
- [x] SAST re-executado - Finding removido ✅
- [x] Testes de segurança adicionados ✅
- [x] Code review aprovado ✅
- [x] Deploy em produção ✅

### Tracking
- **Issue**: SEC-1234
- **Responsável**: João Silva (Dev)
- **Prazo**: Corrigido em 2026-01-14 (mesmo dia)
- **Status**: ✅ RESOLVIDO

### Lições Aprendidas
- Implementar validação de entrada em todos os endpoints
- Sempre usar prepared statements para queries SQL
- Adicionar testes de segurança específicos para SQL Injection
- Considerar usar ORM (ex: Hibernate) que previne SQL Injection automaticamente
```

### Exemplo de False Positive (Marcar como Resolvido)

```markdown
## Finding: Hardcoded Password em SecurityTest.testDefaultPassword()

### Metadados do Finding
- **Severidade SAST**: High 🟠
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **Localização**: `src/test/SecurityTest.java:23`

### Código Flagado
```java
@Test
void testDefaultPassword() {
    // SAST detecta: "Hardcoded password"
    String defaultPassword = "changeme123";  // ← Flagged
    
    // Mas na prática:
    assertThrows(Exception.class, () -> {
        authService.login("admin", defaultPassword);
    }, "Must change default password");  // ✅ Não é vulnerabilidade!
}
```

### Análise
- [ ] **É código de teste?** ✅ Sim - arquivo em `src/test/`
- [ ] **Password é usado para autenticação real?** ❌ Não - é apenas teste
- [ ] **Há validação que rejeita este password?** ✅ Sim - teste valida rejeição

### Decisão
- [ ] True Positive - Corrigir imediatamente
- [x] **False Positive - Marcar como resolvido**
  - Razão: Password hardcoded é esperado em teste que valida rejeição de senha padrão
  - Contexto: Código em `src/test/`, não é executado em produção

### Ação
- Marcar como "False Positive" no SonarQube
- Adicionar comentário no código explicando contexto
- Configurar exceção na regra SAST para arquivos de teste

### Template de Exceção SAST
```java
@SuppressWarnings("java:S2068") // Hardcoded credential - false positive (test only)
@Test
void testDefaultPassword() {
    String defaultPassword = "changeme123";  // OK em teste
    // ...
}
```
```

---

## 🛠️ Exemplos Práticos Completos

### Exemplo 1: Configurar SonarQube em Projeto Node.js

**Contexto**: Configurar SonarQube para analisar projeto Node.js/TypeScript.

**Passo 1: Instalar SonarQube (Docker)**

```bash
# Baixar e executar SonarQube
docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community

# Acessar: http://localhost:9000
# Login padrão: admin/admin (solicita troca na primeira vez)
```

**Passo 2: Instalar SonarScanner**

```bash
# macOS
brew install sonar-scanner

# Ou usar Docker
docker pull sonarsource/sonar-scanner-cli
```

**Passo 3: Configurar Projeto**

```properties
# sonar-project.properties
sonar.projectKey=meu-projeto-nodejs
sonar.projectName=Meu Projeto Node.js
sonar.projectVersion=1.0

# Código fonte
sonar.sources=src
sonar.tests=test
sonar.sourceEncoding=UTF-8

# Linguagem
sonar.language=js
sonar.javascript.lcov.reportPaths=coverage/lcov.info

# Exclusões
sonar.exclusions=**/node_modules/**,**/dist/**,**/*.spec.ts

# Regras de segurança
sonar.security.hotspots=high,medium
```

**Passo 4: Configurar Quality Gate**

No SonarQube Dashboard:
- Vá em Quality Gates
- Configure:
  - Security Rating: A ou B
  - Security Hotspots: 0 Critical/High
  - Vulnerabilities: 0 Critical, máximo 5 High

**Passo 5: Executar Scan**

```bash
# Gerar token no SonarQube (My Account > Security)
export SONAR_TOKEN=seu_token_aqui

# Executar scan
sonar-scanner \
  -Dsonar.projectKey=meu-projeto-nodejs \
  -Dsonar.sources=src \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=$SONAR_TOKEN
```

**Passo 6: Integrar no CI/CD (GitHub Actions)**

```yaml
# .github/workflows/sonar.yml
name: SonarQube Analysis

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    # Scan diário às 2h da manhã
    - cron: '0 2 * * *'

jobs:
  sonar:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Shallow clones should be disabled
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests with coverage
        run: npm test -- --coverage --watchAll=false
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          # Falha o pipeline se Quality Gate não passar
          args: >
            -Dsonar.qualitygate.wait=true
      
      - name: Check Quality Gate
        if: failure()
        run: |
          echo "⚠️ Quality Gate falhou! Verifique os findings no SonarQube."
          echo "Critical/High vulnerabilities devem ser corrigidas antes do merge."
          exit 1
  
  # Job adicional: Semgrep para scan rápido
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/ci
          generateSarif: "1"
          outputFormat: "json"
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: semgrep.sarif
  
  # Job adicional: ESLint Security Plugin (JavaScript específico)
  eslint-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run ESLint Security
        run: npm run lint:security || true
      
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: eslint-security-results
          path: eslint-report.json
```

### Exemplo 2: Configurar Semgrep em Projeto Python

**Contexto**: Configurar Semgrep para projeto Python com regras customizadas.

**Passo 1: Instalar Semgrep**

```bash
# Instalação
pip install semgrep

# Ou via Homebrew (macOS)
brew install semgrep
```

**Passo 2: Criar Configuração**

```yaml
# .semgrep.yml
rules:
  # Regras OWASP
  - id: owasp-python
    config: p/owasp-top-ten
  
  # Regras customizadas
  - id: hardcoded-secrets
    languages: [python]
    severity: ERROR
    patterns:
      - pattern: |
          $X = "...$SECRET..."
        where:
          - pattern-inside: |
              $SECRET = $PATTERN
          - metavariable-regex:
              metavariable: $SECRET
              regex: (password|secret|api_key|token|credential)
    message: "Hardcoded secret detected: $SECRET"
    metadata:
      cwe: "CWE-798: Use of Hard-coded Credentials"
  
  - id: sql-injection-django
    languages: [python]
    severity: ERROR
    patterns:
      - pattern: |
          $MODEL.objects.raw("...$USER_INPUT...")
      - pattern: |
          $MODEL.objects.extra(where=["...$USER_INPUT..."])
    message: "Potential SQL Injection. Use parameterized queries instead."
    metadata:
      cwe: "CWE-89: SQL Injection"
```

**Passo 3: Executar Scan**

```bash
# Scan básico (usa regras padrão)
semgrep --config=auto src/

# Scan com configuração customizada
semgrep --config=.semgrep.yml src/

# Scan com saída JSON para integração
semgrep --config=auto --json --output=results.json src/

# Scan apenas regras de segurança
semgrep --config=p/security-audit src/
```

**Passo 4: Integrar em Pre-commit Hook**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config=auto', '--error']
```

**Passo 5: Exemplo de Finding**

```python
# src/auth.py (código vulnerável)
import os

# SAST detecta: Hardcoded secret
API_KEY = "sk_live_1234567890abcdef"  # ← Flagged por Semgrep

def authenticate(user_id, password):
    user_input = request.get('user_id')  # ← User input
    
    # SAST detecta: SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_input}"  # ← Flagged
    return db.execute(query)
```

**Saída Semgrep**:

```
src/auth.py
  hardcoded-secrets
    Line 4: API_KEY = "sk_live_1234567890abcdef"
    Message: Hardcoded secret detected: API_KEY
    Severity: ERROR
    CWE: CWE-798

  sql-injection-django
    Line 10: query = f"SELECT * FROM users WHERE id = {user_input}"
    Message: Potential SQL Injection. Use parameterized queries instead.
    Severity: ERROR
    CWE: CWE-89
```

### Exemplo 3: Integração SAST no CI/CD (GitLab CI)

**Contexto**: Configurar pipeline GitLab CI que executa múltiplas ferramentas SAST com Quality Gates e validação automática.

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - security
  - deploy

# Variáveis globais para SAST
variables:
  SEMGREP_CONFIG: "p/security-audit p/owasp-top-ten"

# Job de SAST com múltiplas ferramentas
sast:
  stage: security
  image: node:18
  before_script:
    - apt-get update -qq && apt-get install -y -qq python3-pip
    - pip3 install semgrep bandit
  
  script:
    # 1. ESLint Security Plugin (JavaScript)
    - echo "🔍 Running ESLint Security Plugin..."
    - npm install
    - npm run lint:security || true
    - npm run lint:security > eslint-security-report.json 2>&1 || true
    
    # 2. Semgrep (universal - scan rápido)
    - echo "🔍 Running Semgrep..."
    - semgrep --config=$SEMGREP_CONFIG --json --output=semgrep.json . || true
    - semgrep --config=$SEMGREP_CONFIG --text --output=semgrep.txt . || true
    
    # 3. Bandit (se projeto Python)
    - echo "🔍 Running Bandit (Python security scanner)..."
    - bandit -r . -f json -o bandit.json || true
    - bandit -r . -f txt -o bandit.txt || true
    
    # 4. SonarQube (se configurado)
    - |
      if [ -n "$SONAR_TOKEN" ]; then
        echo "🔍 Running SonarQube..."
        sonar-scanner \
          -Dsonar.projectKey=$CI_PROJECT_NAME \
          -Dsonar.sources=. \
          -Dsonar.host.url=$SONAR_HOST_URL \
          -Dsonar.login=$SONAR_TOKEN \
          -Dsonar.qualitygate.wait=true || true
      fi
    
    # 5. Agregar resultados
    - echo "📊 Aggregating SAST results..."
    - python3 scripts/aggregate_sast_results.py
    
    # 6. Validar Critical findings (falha pipeline se encontrar)
    - python3 scripts/check_critical_findings.py
    
  artifacts:
    reports:
      sast: sast-report.json
    paths:
      - semgrep.json
      - semgrep.txt
      - bandit.json
      - bandit.txt
      - eslint-security-report.json
      - sast-report.html
      - sast-report.json
    expire_in: 1 week
    when: always  # Sempre salvar, mesmo se falhar
  
  allow_failure: false  # Falha pipeline se encontrar Critical não tratado
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_COMMIT_TAG

# Job para validar findings e criar issues
sast-validation:
  stage: security
  image: python:3.9
  dependencies:
    - sast
  script:
    - echo "✅ Validating SAST findings..."
    - python3 scripts/validate_sast_findings.py
    
    - echo "📝 Creating GitHub issues for Critical findings..."
    - python3 scripts/create_issues_for_critical.py
    
  needs:
    - sast
  allow_failure: true  # Não bloqueia pipeline, mas cria issues
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Job para gerar dashboard de segurança
sast-dashboard:
  stage: security
  image: python:3.9
  dependencies:
    - sast
  script:
    - echo "📊 Generating security dashboard..."
    - python3 scripts/generate_security_dashboard.py
    
  artifacts:
    paths:
      - security-dashboard.html
    expire_in: 30 days
  
  only:
    - main
    - schedules
```

### Exemplo 4: Criar Regra Customizada Semgrep

**Contexto**: Criar regra para detectar uso inseguro de `eval()` em JavaScript.

**Regra Customizada**:

```yaml
# regras/eval-injection.yaml
rules:
  - id: eval-injection
    languages: [javascript, typescript]
    severity: ERROR
    message: "Use of eval() is dangerous and can lead to code injection. Use JSON.parse() or alternative safe methods."
    patterns:
      - pattern-either:
          - pattern: eval($EXPR)
          - pattern: Function($EXPR)
          - pattern: setTimeout($EXPR, ...)
          - pattern: setInterval($EXPR, ...)
    exceptions:
      - pattern: eval("true")  # Permite casos específicos
    metadata:
      cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
      owasp: "A03:2021 – Injection"
      category: security
      technology:
        - javascript
        - typescript
```

**Uso da Regra**:

```bash
# Executar apenas regra customizada
semgrep --config=regras/eval-injection.yaml src/

# Executar todas as regras (incluindo custom)
semgrep --config=auto --config=regras/ src/
```

**Exemplo de Código que Seria Flagado**:

```javascript
// ❌ VULNERÁVEL - Será flagado
const userInput = request.body.code;
eval(userInput);  // ← Flagged: eval-injection

// ✅ SEGURO - Não será flagado
const data = request.body.data;
const parsed = JSON.parse(data);  // OK
```

---

## ✅ Padrões e Boas Práticas

### Boas Práticas de SAST

1. **Execute SAST cedo e frequentemente**
   - **Por quê**: Encontrar problemas cedo reduz custo de correção drasticamente
   - **Como**: Integrar em pre-commit hooks e CI/CD
   - **Exemplo**: `pre-commit run semgrep` antes de cada commit
   - **Benefício**: Problemas são corrigidos antes de chegar ao repositório

2. **Configure Quality Gates apropriados**
   - **Por quê**: Previne merge de código com vulnerabilidades críticas
   - **Como**: Bloquear merge se encontrar Critical/High não corrigidos
   - **Exemplo**: SonarQube Quality Gate com "0 Critical vulnerabilities"
   - **Benefício**: Vulnerabilidades críticas nunca chegam à produção

3. **Tune regras para seu contexto**
   - **Por quê**: Reduz false positives e foca em problemas reais
   - **Como**: Desabilitar regras não aplicáveis, criar regras customizadas
   - **Exemplo**: Desabilitar regras de Python em projeto Java
   - **Benefício**: Menos ruído, mais sinal útil

4. **Valide findings antes de corrigir**
   - **Por quê**: Nem tudo que SAST reporta é vulnerabilidade real
   - **Como**: Processo de triagem que valida cada finding
   - **Exemplo**: Checklist de validação para cada Critical/High
   - **Benefício**: Evita trabalho desnecessário corrigindo false positives

5. **Priorize por risco real**
   - **Por quê**: Nem todas as vulnerabilidades têm mesmo impacto
   - **Como**: Considerar exploitability, impacto, contexto
   - **Exemplo**: SQL Injection em área pública > XSS em área admin
   - **Benefício**: Foca esforço onde realmente importa

6. **Combine múltiplas ferramentas**
   - **Por quê**: Cada ferramenta tem pontos fortes diferentes
   - **Como**: Usar SonarQube + Semgrep + ferramentas específicas de linguagem
   - **Exemplo**: SonarQube para cobertura completa + Semgrep para velocidade
   - **Benefício**: Cobertura máxima de vulnerabilidades

7. **Documente decisões de risco aceito**
   - **Por quê**: Transparência e rastreabilidade são importantes
   - **Como**: Documentar por que vulnerabilidade não será corrigida
   - **Exemplo**: "XSS Low em área interna: risco aceito, requer autenticação"
   - **Benefício**: Compliance e auditoria facilitadas

8. **Use SAST para educar desenvolvedores**
   - **Por quê**: SAST é ótima ferramenta de aprendizado
   - **Como**: Mostrar findings em code reviews, sessões de treinamento
   - **Exemplo**: "Veja como SAST detectou este SQL Injection..."
   - **Benefício**: Desenvolvedores aprendem padrões seguros

9. **Mantenha ferramentas atualizadas**
   - **Por quê**: Novas vulnerabilidades e regras são adicionadas constantemente
   - **Como**: Atualizar regras e versões de ferramentas regularmente
   - **Exemplo**: Atualizar Semgrep rules mensalmente
   - **Benefício**: Detecta vulnerabilidades mais recentes

10. **Integre com ferramentas de tracking**
    - **Por quê**: Rastreabilidade e gestão de vulnerabilidades
    - **Como**: Integrar SAST com Jira, GitHub Issues, etc.
    - **Exemplo**: Criar issue automaticamente para cada Critical
    - **Benefício**: Nenhuma vulnerabilidade fica esquecida

### Anti-padrões Comuns

1. **Não ignore todos os findings de uma vez**
   - **Problema**: Marcar tudo como "Won't Fix" sem análise
   - **Solução**: Validar cada finding individualmente
   - **Impacto**: Vulnerabilidades reais podem passar despercebidas

2. **Não execute SAST apenas antes do release**
   - **Problema**: Encontrar problemas tarde, quando correção é cara
   - **Solução**: Executar continuamente (CI/CD, pre-commit)
   - **Impacto**: Correções tardias são caras e podem causar atrasos

3. **Não confie cegamente em SAST**
   - **Problema**: SAST não encontra tudo (especialmente problemas de runtime)
   - **Solução**: Combinar com DAST, IAST, testes manuais
   - **Impacto**: Falsa sensação de segurança

4. **Não configure Quality Gates muito rígidos inicialmente**
   - **Problema**: Bloqueia todo desenvolvimento se código legado tem problemas
   - **Solução**: Começar permissivo, apertar gradualmente
   - **Impacto**: Desenvolvedores podem desabilitar SAST se muito restritivo

5. **Não trate todos os findings com mesma prioridade**
   - **Problema**: Critical e Low recebem mesma atenção
   - **Solução**: Priorizar por severidade e contexto
   - **Impacto**: Recursos mal alocados, problemas críticos podem não ser corrigidos

6. **Não use apenas ferramentas open-source sem avaliar**
   - **Problema**: Ferramentas gratuitas podem não ser suficientes
   - **Solução**: Avaliar necessidade de ferramentas comerciais
   - **Impacto**: Pode faltar cobertura em projetos enterprise

7. **Não execute SAST sem contexto de negócio**
   - **Problema**: Tratar vulnerabilidade em código não usado igual a código crítico
   - **Solução**: Considerar contexto (código ativo? em produção? dados sensíveis?)
   - **Impacto**: Priorização incorreta de esforços

8. **Não mantenha regras desatualizadas**
   - **Problema**: Regras antigas podem não detectar vulnerabilidades novas
   - **Solução**: Atualizar regras regularmente
   - **Impacto**: Vulnerabilidades novas não são detectadas

---

## 💼 Aplicação no Contexto CWI

**📝 Nota:** Os cenários abaixo são exemplos hipotéticos criados para fins educacionais, ilustrando como os conceitos de SAST podem ser aplicados em diferentes contextos e setores.

### Cenário Hipotético 1: Cliente Financeiro (Fintech)

**Situação**: Projeto de Open Banking desenvolvido em Node.js/TypeScript. Requisitos de compliance PCI-DSS e regulamentações do Banco Central.

**Papel do QA com SAST**:

1. **Configurar SAST apropriado para o contexto**
   - Ferramentas: SonarQube + Semgrep + ESLint Security Plugin
   - Foco: SQL Injection, hardcoded secrets, autenticação insegura
   - Regras customizadas: Detectar padrões específicos de Open Banking

2. **Validar vulnerabilidades críticas para o setor**
   - SQL Injection em APIs de consulta de extrato
   - Exposição de credenciais/chaves API em código
   - Broken Authentication em fluxos OAuth2
   - Insecure Deserialization em processamento de dados bancários

3. **Integrar SAST no pipeline CI/CD**
   ```yaml
   # Pipeline com Quality Gate rigoroso para financeiro
   - Quality Gate: 0 Critical vulnerabilities
   - Quality Gate: Máximo 2 High vulnerabilities
   - Bloqueio automático de merge se não passar
   ```

4. **Priorizar findings por risco financeiro**
   - Critical: Vulnerabilidades que podem comprometer dados de cartão (PCI-DSS)
   - High: Vulnerabilidades em APIs de transferência
   - Medium: Vulnerabilidades em áreas de menor risco

**Exemplo de Finding Crítico**:
```typescript
// SAST detecta: Hardcoded API Key
const OPEN_BANKING_API_KEY = "sk_live_abc123..."  // ← Critical finding

// Correção implementada:
const OPEN_BANKING_API_KEY = process.env.OPEN_BANKING_API_KEY  // ✅
```

### Cenário Hipotético 2: Plataforma Educacional (EdTech)

**Situação**: Plataforma de ensino online desenvolvida em Python/Django. Requisitos de compliance LGPD (especialmente dados de menores).

**Papel do QA com SAST**:

1. **Configurar SAST para proteção de dados sensíveis**
   - Ferramentas: Bandit + Semgrep + SonarQube
   - Foco: XSS, SQL Injection, exposição de dados pessoais, LGPD violations
   - Regras customizadas: Detectar acesso a dados de menores sem autorização

2. **Validar vulnerabilidades críticas para o setor**
   - SQL Injection que pode expor dados de alunos
   - XSS em áreas de mensagens/comentários
   - Exposição de dados pessoais em logs ou mensagens de erro
   - Broken Access Control que permite acesso a dados de outros alunos

3. **Implementar regras específicas para LGPD**
   ```yaml
   # Regra Semgrep customizada para LGPD
   - id: lgpd-personal-data-logging
     patterns:
       - pattern: logging.info(f"...$DATA...")
       - metavariable-regex:
           metavariable: $DATA
           regex: (cpf|rg|email|phone|address)
     message: "Personal data potentially logged. LGPD violation risk."
   ```

**Exemplo de Finding Crítico**:
```python
# SAST detecta: SQL Injection + Exposição de dados pessoais
def get_student_grades(student_id):
    query = f"SELECT * FROM grades WHERE student_id = {student_id}"  # ← SQL Injection
    return db.execute(query)  # Pode expor dados de outros alunos (LGPD)

# Correção implementada:
def get_student_grades(student_id, current_user_id):
    if student_id != current_user_id:
        raise PermissionError("Cannot access other student data")  # ✅ Access Control
    query = "SELECT * FROM grades WHERE student_id = %s"  # ✅ Prepared Statement
    return db.execute(query, (student_id,))
```

### Cenário Hipotético 3: Ecommerce

**Situação**: Plataforma de ecommerce desenvolvida em Java/Spring Boot. Requisitos de compliance PCI-DSS para processamento de pagamentos.

**Papel do QA com SAST**:

1. **Configurar SAST para segurança de pagamentos**
   - Ferramentas: SonarQube + FindSecBugs + Semgrep
   - Foco: SQL Injection, XSS, manipulação de preços, exposição de dados de cartão
   - Regras customizadas: Detectar manipulação de valores de transação

2. **Validar vulnerabilidades críticas para ecommerce**
   - SQL Injection em busca de produtos
   - Manipulação de preços no cliente (preço deve ser validado server-side)
   - Exposição de dados de cartão em logs ou mensagens de erro
   - Broken Access Control que permite acesso a pedidos de outros clientes

3. **Quality Gate específico para PCI-DSS**
   ```yaml
   # PCI-DSS exige:
   - 0 Critical vulnerabilities relacionados a dados de cartão
   - 0 Hardcoded secrets/chaves
   - 0 SQL Injection em áreas de pagamento
   - Bloqueio automático se qualquer uma dessas condições falhar
   ```

**Exemplo de Finding Crítico**:
```java
// SAST detecta: Price Manipulation + SQL Injection
@PostMapping("/checkout")
public Order checkout(@RequestBody OrderRequest request) {
    // ❌ Preço vem do cliente (pode ser manipulado)
    double price = request.getPrice();  
    
    // ❌ SQL Injection
    String query = "INSERT INTO orders VALUES (" + request.getUserId() + ", " + price + ")";
    db.execute(query);
    
    return order;
}

// Correção implementada:
@PostMapping("/checkout")
public Order checkout(@RequestBody OrderRequest request) {
    // ✅ Preço vem do servidor
    Product product = productRepository.findById(request.getProductId());
    double price = product.getPrice();  // Validado server-side
    
    // ✅ Prepared Statement
    String query = "INSERT INTO orders (user_id, price) VALUES (?, ?)";
    db.execute(query, request.getUserId(), price);
    
    return order;
}
```

### Cenário Hipotético 4: Aplicações de IA

**Situação**: Projeto de IA/ML desenvolvido em Python com TensorFlow. Processamento de dados sensíveis e modelos de inferência.

**Papel do QA com SAST**:

1. **Configurar SAST para segurança em IA**
   - Ferramentas: Bandit + Semgrep + ferramentas específicas de ML
   - Foco: Insecure deserialization, exposição de modelos, vazamento de dados de treinamento
   - Regras customizadas: Detectar padrões inseguros em pipelines de ML

2. **Validar vulnerabilidades específicas de IA**
   - Pickle/Joblib deserialization insegura (model poisoning)
   - Exposição de dados de treinamento em código ou logs
   - Hardcoded paths para modelos/dados sensíveis
   - Command Injection em processamento de dados

3. **Regras customizadas para ML Security**
   ```yaml
   # Regra para detectar insecure pickle
   - id: insecure-pickle-load
     patterns:
       - pattern: pickle.load($FILE)
       - pattern: joblib.load($FILE)
     message: "Insecure deserialization. Risk of model poisoning."
     metadata:
       cwe: "CWE-502: Deserialization of Untrusted Data"
   ```

**Exemplo de Finding Crítico**:
```python
# SAST detecta: Insecure Deserialization (Model Poisoning risk)
def load_model(model_path):
    import pickle
    # ❌ Pickle não é seguro para modelos não confiáveis
    with open(model_path, 'rb') as f:
        model = pickle.load(f)  # ← Critical: Model poisoning risk
    return model

# Correção implementada:
def load_model(model_path):
    import tensorflow as tf
    # ✅ TensorFlow SavedModel é mais seguro
    model = tf.keras.models.load_model(model_path)  # ✅
    return model
```

### Comparação de Prioridades por Setor

| Vulnerabilidade SAST | Financeiro | Educacional | Ecommerce | IA |
|---------------------|------------|-------------|-----------|-----|
| **SQL Injection** | 🔴 CRÍTICA | 🔴 CRÍTICA | 🔴 CRÍTICA | 🟠 ALTA |
| **Hardcoded Secrets** | 🔴 CRÍTICA | 🟠 ALTA | 🔴 CRÍTICA | 🔴 CRÍTICA |
| **XSS** | 🟠 ALTA | 🔴 CRÍTICA | 🔴 CRÍTICA | 🟡 MÉDIA |
| **Broken Access Control** | 🔴 CRÍTICA | 🔴 CRÍTICA | 🔴 CRÍTICA | 🟠 ALTA |
| **Insecure Deserialization** | 🟠 ALTA | 🟡 MÉDIA | 🟠 ALTA | 🔴 CRÍTICA |
| **Price Manipulation** | 🟠 ALTA | 🟡 MÉDIA | 🔴 CRÍTICA | 🟡 MÉDIA |

**Legenda**: 🔴 Crítica | 🟠 Alta | 🟡 Média

### Workflow de SAST por Setor

**Financeiro (PCI-DSS)**:
```
1. SAST em cada commit (pre-commit hook)
2. Quality Gate rigoroso (0 Critical)
3. Validação manual de todos os High
4. Compliance report automático
5. Bloqueio de deploy se não passar
```

**Educacional (LGPD)**:
```
1. SAST em cada PR (CI/CD)
2. Quality Gate médio (0 Critical, máx 5 High)
3. Foco especial em dados de menores
4. LGPD compliance checks automáticos
```

**Ecommerce (PCI-DSS)**:
```
1. SAST em cada PR + nightly scans
2. Quality Gate rigoroso (0 Critical em área de pagamento)
3. Validação especial de manipulação de preços
4. PCI-DSS compliance report
```

**IA/ML**:
```
1. SAST em cada PR
2. Quality Gate específico (foco em deserialization)
3. Regras customizadas para ML patterns
4. Validação de segurança de modelos
```
---

## 📚 Referências Externas

### Documentação Oficial

- **[OWASP - Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)**: Lista completa de ferramentas SAST
- **[SonarQube Documentation](https://docs.sonarqube.org/latest/)**: Documentação completa do SonarQube
- **[Semgrep Documentation](https://semgrep.dev/docs/)**: Documentação oficial do Semgrep
- **[Checkmarx SAST Documentation](https://checkmarx.com/resource/documents/)**: Documentação do Checkmarx
- **[CWE - Common Weakness Enumeration](https://cwe.mitre.org/)**: Lista completa de vulnerabilidades de software

### Artigos e Tutoriais

- **[OWASP Top 10](https://owasp.org/www-project-top-ten/)**: Top 10 vulnerabilidades web mais críticas
- **[SAST vs DAST: What's the Difference?](https://www.synopsys.com/blogs/software-security/sast-vs-dast/)**: Comparação detalhada
- **[Reducing False Positives in SAST](https://www.veracode.com/blog/secure-development/how-reduce-false-positives-sast-tools)**: Guia prático
- **[SAST Best Practices](https://www.checkmarx.com/knowledge/knowledge-base/sast-best-practices/)**: Melhores práticas

### Ferramentas e Recursos

- **[Semgrep Registry](https://semgrep.dev/r)**: Regras prontas do Semgrep
- **[SonarQube Rules](https://rules.sonarsource.com/)**: Catálogo de regras SonarQube
- **[Bandit Rules](https://bandit.readthedocs.io/en/latest/plugins/index.html)**: Regras disponíveis no Bandit
- **[FindSecBugs](https://find-sec-bugs.github.io/)**: Plugin de segurança para SpotBugs (Java)

### Comunidade

- **[OWASP Community](https://owasp.org/www-community/)**: Comunidade global de segurança
- **[Semgrep Slack](https://r2c.dev/slack)**: Comunidade Semgrep
- **[SonarSource Community](https://community.sonarsource.com/)**: Fórum da comunidade SonarSource

---

## 📝 Resumo

### Principais Conceitos

- **SAST**: Análise estática de código sem executar aplicação
- **Ferramentas Principais**: SonarQube (completo), Semgrep (rápido), Checkmarx (enterprise)
- **Tipos de Análise**: Pattern matching, data flow, control flow, taint analysis
- **Severidade**: Critical, High, Medium, Low
- **False Positives**: Findings que não são vulnerabilidades reais - precisam validação
- **Quality Gates**: Bloqueiam merge se critérios de segurança não atendidos

### Pontos-Chave para Lembrar

- ✅ **Execute SAST cedo**: Integre em CI/CD e pre-commit hooks
- ✅ **Valide findings**: Nem tudo que SAST reporta é vulnerabilidade real
- ✅ **Priorize por risco**: Considere severidade, exploitability, impacto, contexto
- ✅ **Combine ferramentas**: Use múltiplas ferramentas para cobertura máxima
- ✅ **Configure Quality Gates**: Bloqueie código vulnerável antes de merge
- ✅ **Tune regras**: Customize para reduzir false positives
- ✅ **Mantenha atualizado**: Atualize regras e ferramentas regularmente
- ✅ **Use para educar**: SAST é ótima ferramenta de aprendizado para devs

### Próximos Passos

- Próxima aula: DAST - Testes Dinâmicos (aplicação em execução)
- Praticar configurando SAST em projetos reais
- Explorar regras customizadas para padrões específicos do seu contexto
- Integrar SAST com outras ferramentas (SCA, DAST) para cobertura completa

---

## ✅ Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Contexto histórico do SAST
- [x] Comparação detalhada com outras metodologias (DAST, IAST, SCA)
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos (SonarQube, Semgrep, CI/CD)
- [x] Tabelas comparativas de ferramentas
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 1.5: Fundamentos de Segurança em QA](./lesson-1-5.md)  
**Próxima Aula**: [Aula 2.2: DAST - Testes Dinâmicos](./lesson-2-2.md)  
**Voltar ao Módulo**: [Módulo 2: Testes de Segurança na Prática](../index.md)