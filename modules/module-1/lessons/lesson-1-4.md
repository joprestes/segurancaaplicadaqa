---
layout: lesson
title: "Aula 1.4: Threat Modeling e Análise de Riscos"
slug: threat-modeling
module: module-1
lesson_id: lesson-1-4
duration: "90 minutos"
level: "Intermediário"
prerequisites: ["lesson-1-3"]
exercises:
  - lesson-1-4-exercise-1-stride-basico
  - lesson-1-4-exercise-2-identificar-ameacas
  - lesson-1-4-exercise-3-analise-riscos
  - lesson-1-4-exercise-4-threat-model-completo
  - lesson-1-4-exercise-5-mitigacao-priorizacao
video:
  file: "assets/videos/Modelagem_de_Ameacas-lesson-1-4.mp4"
  title: "Threat Modeling: Identificando Ameaças Antes de Acontecerem"
  thumbnail: "assets/images/infografico-lesson-1-4.png"
  description: "Aprenda técnicas de modelagem de ameaças (STRIDE, PASTA, DREAD) e como aplicá-las em diferentes contextos de projeto para identificar riscos de segurança proativamente."
  duration: "60-75 minutos"
permalink: /modules/fundamentos-seguranca-qa/lessons/threat-modeling/
---

<!-- # Aula 1.4: Threat Modeling e Análise de Riscos -->

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Entender o que é threat modeling e sua importância
- Aplicar metodologias de threat modeling (STRIDE, PASTA, DREAD)
- Identificar ameaças em arquiteturas de aplicação
- Analisar e priorizar riscos de segurança
- Criar threat models práticos para projetos reais
- Aplicar threat modeling em contextos CWI (Financeiro, Educacional, Ecommerce)

## 📚 Introdução ao Threat Modeling

### O que é Threat Modeling?

**Threat Modeling** é um processo estruturado para identificar, documentar e mitigar ameaças de segurança em uma aplicação ou sistema antes que sejam exploradas.

#### 🎭 Analogia: Mapa de Tesouro vs Mapa de Ameaças

Imagine que você está planejando uma viagem:

**Mapa de Tesouro (Abordagem Tradicional)**:
- Você só pensa nos lugares bonitos para visitar
- Não considera perigos no caminho
- Descobre problemas quando já está na viagem
- Pode ser tarde demais ❌

**Mapa de Ameaças (Threat Modeling)**:
- Você identifica perigos antes de viajar
- Planeja rotas alternativas
- Prepara-se para problemas potenciais
- Viaja mais seguro ✅

Na segurança de software, threat modeling é o "mapa de ameaças" que ajuda a identificar problemas antes que aconteçam.

### Por que Threat Modeling é Importante?

#### Benefícios do Threat Modeling

| Benefício | Descrição | Impacto |
|-----------|-----------|---------|
| **Prevenção** | Identifica ameaças antes de desenvolver | Reduz vulnerabilidades |
| **Custo-Benefício** | Mais barato prevenir que corrigir | Economia significativa |
| **Arquitetura Segura** | Design considera segurança desde o início | Produtos mais seguros |
| **Compliance** | Atende requisitos de segurança | Menos riscos regulatórios |
| **Educação** | Time aprende sobre segurança | Cultura de segurança |

#### Quando Fazer Threat Modeling?

**Momentos Ideais**:
- ✅ Durante fase de design (Shift-Left)
- ✅ Quando arquitetura muda significativamente
- ✅ Antes de adicionar novas funcionalidades críticas
- ✅ Após incidentes de segurança
- ✅ Regularmente (revisão anual)

---

## 🔍 Metodologias de Threat Modeling

### 1. STRIDE

**STRIDE** é uma metodologia desenvolvida pela Microsoft que categoriza ameaças em 6 tipos:

#### Componentes do STRIDE

| Letra | Ameaça | Descrição | Exemplo |
|-------|--------|-----------|---------|
| **S** | **Spoofing** | Falsificar identidade | Login falso, email spoofing |
| **T** | **Tampering** | Alterar dados ou código | Modificar dados em trânsito |
| **R** | **Repudiation** | Negar ações realizadas | Usuário nega ter feito transferência |
| **I** | **Information Disclosure** | Expor informações | Vazamento de dados, logs expostos |
| **D** | **Denial of Service** | Impedir acesso legítimo | DDoS, força bruta |
| **E** | **Elevation of Privilege** | Obter privilégios não autorizados | Usuário comum vira admin |

#### Como Aplicar STRIDE

**Processo**:
1. Identificar componentes do sistema
2. Para cada componente, perguntar: "Quais ameaças STRIDE são possíveis?"
3. Documentar ameaças encontradas
4. Priorizar por risco
5. Propor mitigações

**Exemplo Prático**:

```
Componente: API de Autenticação

S - Spoofing: Atacante pode falsificar identidade?
  → Ameaça: Login sem senha válida
  → Mitigação: Autenticação forte, MFA

T - Tampering: Dados podem ser alterados?
  → Ameaça: Modificar token de sessão
  → Mitigação: Assinatura digital de tokens

R - Repudiation: Ações podem ser negadas?
  → Ameaça: Usuário nega login
  → Mitigação: Logs de auditoria

I - Information Disclosure: Informações podem ser expostas?
  → Ameaça: Token exposto em logs
  → Mitigação: Não logar dados sensíveis

D - Denial of Service: Serviço pode ser negado?
  → Ameaça: Força bruta bloqueia conta
  → Mitigação: Rate limiting inteligente

E - Elevation of Privilege: Privilégios podem ser elevados?
  → Ameaça: Usuário comum vira admin
  → Mitigação: Validação de role no servidor
```

---

### 2. PASTA

**PASTA** (Process for Attack Simulation and Threat Analysis) é uma metodologia mais estruturada em 7 etapas:

1. **Define Objectives**: Definir objetivos do atacante
2. **Define Technical Scope**: Definir escopo técnico
3. **Application Decomposition**: Decompor aplicação
4. **Threat Analysis**: Analisar ameaças
5. **Vulnerability Analysis**: Analisar vulnerabilidades
6. **Attack Modeling**: Modelar ataques
7. **Risk Analysis**: Analisar riscos

**Quando Usar PASTA**:
- Projetos complexos
- Quando precisa de análise mais detalhada
- Quando compliance exige metodologia formal

---

### 3. DREAD

**DREAD** é uma metodologia para **priorizar** ameaças baseada em 5 fatores:

| Fator | Descrição | Escala |
|-------|-----------|--------|
| **D**amage | Dano potencial | 0-10 |
| **R**eproducibility | Facilidade de reproduzir | 0-10 |
| **E**xploitability | Facilidade de explorar | 0-10 |
| **A**ffected Users | Usuários afetados | 0-10 |
| **D**iscoverability | Facilidade de descobrir | 0-10 |

**Cálculo de Risco**:
```
Risco = (Damage + Reproducibility + Exploitability + Affected Users + Discoverability) / 5
```

**Exemplo**:

```
Ameaça: SQL Injection em endpoint de busca

D - Damage: 9 (acesso a todos os dados)
R - Reproducibility: 10 (sempre funciona)
E - Exploitability: 8 (fácil de explorar)
A - Affected Users: 10 (todos os usuários)
D - Discoverability: 9 (fácil de descobrir)

Risco = (9 + 10 + 8 + 10 + 9) / 5 = 9.2 (CRÍTICO)
```

---

## 🏗️ Processo de Threat Modeling Passo a Passo

### Passo 1: Identificar Ativos

**O que são ativos?**
Ativos são recursos valiosos que precisam ser protegidos.

**Tipos de Ativos**:
- Dados (informações de usuários, dados financeiros)
- Sistemas (servidores, bancos de dados)
- Funcionalidades (transferências, pagamentos)
- Reputação (confiança dos clientes)

**Exemplo**:
```
Ativos de uma aplicação financeira:
- Dados de cartão de crédito
- Informações bancárias de usuários
- Sistema de transferências
- API de pagamentos
- Reputação da empresa
```

---

### Passo 2: Identificar Pontos de Entrada

**O que são pontos de entrada?**
Pontos onde atacantes podem interagir com o sistema.

**Tipos de Pontos de Entrada**:
- APIs REST/GraphQL
- Interfaces web
- Upload de arquivos
- Integrações com terceiros
- Mensageria

**Exemplo**:
```
Pontos de entrada de uma API:
- POST /api/login
- GET /api/users/<id>
- POST /api/transfer
- POST /api/upload
```

---

### Passo 3: Identificar Ameaças

Use STRIDE para identificar ameaças em cada componente:

**Template de Ameaça**:
```markdown
## Threat T-XXX: [Nome da Ameaça]

**Componente**: [Componente afetado]
**Categoria STRIDE**: [S/T/R/I/D/E]
**Descrição**: [Descrição detalhada]
**Impacto**: [Alto/Médio/Baixo]
**Probabilidade**: [Alta/Média/Baixa]
**Risco**: [Crítico/Alto/Médio/Baixo]
**Mitigação**: [Como mitigar]
```

---

### Passo 4: Analisar Riscos

Use DREAD ou análise qualitativa para priorizar:

**Priorização**:
- **Crítico**: Corrigir imediatamente
- **Alto**: Corrigir em breve
- **Médio**: Corrigir quando possível
- **Baixo**: Monitorar

---

### Passo 5: Propor Mitigações

Para cada ameaça crítica/alta, propor mitigações:

**Tipos de Mitigação**:
- Controles preventivos (evitar ameaça)
- Controles detectivos (detectar ameaça)
- Controles corretivos (corrigir após ameaça)

![Infográfico: Threat Modeling - Metodologia e Processo Completo]({{ '/assets/images/infografico-lesson-1-4.png' | relative_url }})

---

## 💼 Casos Práticos CWI

> **Nota**: Os casos abaixo são exemplos hipotéticos criados para fins educacionais, ilustrando como os conceitos podem ser aplicados.

### Caso Hipotético 1: Aplicação Financeira - API de Transferências

**Arquitetura**:
```
Cliente → API Gateway → API Transferências → Banco de Dados
```

**Threat Modeling**:

**Ativos**:
- Dados bancários
- Sistema de transferências
- Dinheiro dos clientes

**Pontos de Entrada**:
- POST /api/transfer
- GET /api/accounts/<id>

**Ameaças Identificadas**:

1. **Broken Access Control (IDOR)**
   - **STRIDE**: Elevation of Privilege (E)
   - **Risco**: Crítico
   - **Mitigação**: Validação de propriedade da conta

2. **Tampering de Transferências**
   - **STRIDE**: Tampering (T)
   - **Risco**: Crítico
   - **Mitigação**: Validação de regras de negócio, assinatura digital

3. **Repudiation de Transferências**
   - **STRIDE**: Repudiation (R)
   - **Risco**: Alto
   - **Mitigação**: Logs de auditoria imutáveis

---

### Caso Hipotético 2: Plataforma Educacional - Área do Aluno

**Arquitetura**:
```
Aluno → Frontend → API → Banco de Dados (Dados de Alunos)
```

**Threat Modeling**:

**Ativos**:
- Dados de menores (LGPD)
- Notas e avaliações
- Informações pessoais

**Ameaças Identificadas**:

1. **Information Disclosure**
   - **STRIDE**: Information Disclosure (I)
   - **Risco**: Crítico (dados de menores)
   - **Mitigação**: Isolamento rigoroso, criptografia

2. **Broken Access Control**
   - **STRIDE**: Elevation of Privilege (E)
   - **Risco**: Crítico
   - **Mitigação**: Validação de relacionamento aluno-turma

---

### Caso Hipotético 3: Ecommerce - Sistema de Checkout

**Arquitetura**:
```
Cliente → Frontend → API Checkout → Gateway Pagamento → Banco
```

**Threat Modeling**:

**Ativos**:
- Dados de cartão (PCI-DSS)
- Sistema de pagamentos
- Integridade de preços

**Ameaças Identificadas**:

1. **Tampering de Preços**
   - **STRIDE**: Tampering (T)
   - **Risco**: Crítico
   - **Mitigação**: Validação de preços no servidor

2. **Information Disclosure de Cartões**
   - **STRIDE**: Information Disclosure (I)
   - **Risco**: Crítico (PCI-DSS)
   - **Mitigação**: Tokenização, nunca armazenar dados completos

---

## 🛠️ Ferramentas de Threat Modeling

### Ferramentas Disponíveis

| Ferramenta | Tipo | Descrição |
|------------|------|-----------|
| **Microsoft TMT** | Desktop | Gratuita, baseada em STRIDE |
| **OWASP Threat Dragon** | Web/Desktop | Open source, integração com OWASP |
| **IriusRisk** | Web | Comercial, metodologia completa |
| **Draw.io** | Web | Genérico, pode usar para diagramas |

### Microsoft Threat Modeling Tool (TMT)

**Como Usar**:
1. Baixar e instalar TMT
2. Criar diagrama de arquitetura
3. Adicionar componentes e fluxos
4. TMT gera ameaças automaticamente (STRIDE)
5. Analisar e priorizar ameaças
6. Documentar mitigações

---

## 📊 Documentação de Threat Model

### Template de Threat Model Completo

```markdown
# Threat Model - [Nome da Aplicação]

## Informações Gerais
- **Data**: [Data]
- **Versão**: [Versão]
- **Responsável**: [Nome]
- **Metodologia**: [STRIDE/PASTA/DREAD]

## Arquitetura
[Diagrama da arquitetura]

## Ativos
1. [Ativo 1]
2. [Ativo 2]

## Pontos de Entrada
1. [Ponto de entrada 1]
2. [Ponto de entrada 2]

## Ameaças Identificadas

### Críticas
1. [Ameaça 1]
2. [Ameaça 2]

### Altas
1. [Ameaça 3]

## Mitigações
- [Mitigação 1]
- [Mitigação 2]

## Plano de Validação
- [Teste 1]
- [Teste 2]
```

---

## ✅ Checklist de Threat Modeling

### Preparação
- [ ] Arquitetura documentada
- [ ] Componentes identificados
- [ ] Fluxos de dados mapeados
- [ ] Ativos identificados

### Identificação de Ameaças
- [ ] STRIDE aplicado a todos os componentes
- [ ] Ameaças documentadas
- [ ] Categorização STRIDE aplicada
- [ ] Ameaças priorizadas

### Análise de Riscos
- [ ] Riscos calculados (DREAD ou qualitativo)
- [ ] Priorização realizada
- [ ] Ameaças críticas identificadas

### Mitigação
- [ ] Mitigações propostas para ameaças críticas/altas
- [ ] Mitigações são implementáveis
- [ ] Plano de validação criado

### Documentação
- [ ] Threat model documentado
- [ ] Diagramas incluídos
- [ ] Ameaças e mitigações claras
- [ ] Revisão realizada

---

## 🎯 Próximos Passos

Após dominar Threat Modeling, você estará preparado para:

- **Aula 1.5**: Compliance e Regulamentações - LGPD, PCI-DSS, SOC2
- **Módulo 2**: Testes de Segurança na Prática - Aplicar conhecimento em testes
- **Módulo 3**: Segurança por Setor - Aplicar threat modeling por contexto

---

**Duração da Aula**: 90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 1.3 (Shift-Left Security)
