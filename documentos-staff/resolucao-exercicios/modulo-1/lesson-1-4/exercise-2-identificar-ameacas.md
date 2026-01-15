---
exercise_id: lesson-1-4-exercise-2-identificar-ameacas
title: "Exercício 1.4.2: Identificar Ameaças em Arquitetura Complexa"
lesson_id: lesson-1-4
module: module-1
difficulty: "Intermediário"
last_updated: 2025-01-15
---

# Exercício 1.4.2: Identificar Ameaças em Arquitetura Complexa

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **identificação de ameaças** em arquiteturas mais complexas através da **análise detalhada** de componentes e fluxos.

### Tarefa Principal

1. Analisar arquitetura complexa
2. Identificar ameaças por componente
3. Identificar ameaças em fluxos de dados
4. Documentar ameaças encontradas

---

## ✅ Soluções Detalhadas

### Parte 1: Analisar Arquitetura

**Arquitetura:**
```
┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
│  Cliente │──────│   API    │──────│  Banco   │      │ Gateway  │
│   Web    │ HTTPS│  Gateway │      │  Dados   │      │Pagamento │
└──────────┘      └──────────┘      └──────────┘      └──────────┘
                        │                  │                  │
                        │                  │                  │
                        ▼                  ▼                  ▼
                   ┌──────────┐      ┌──────────┐      ┌──────────┐
                   │   API   │      │  Cache   │      │  Email   │
                   │  Users  │      │  Redis   │      │ Service  │
                   └──────────┘      └──────────┘      └──────────┘
```

**Componentes Identificados:**
- **Cliente Web**: Frontend (interface do usuário)
- **API Gateway**: Roteamento, rate limiting, autenticação
- **API de Usuários**: Backend com endpoints `/api/users`, `/api/profile`
- **Banco de Dados**: Armazena dados de usuários
- **Cache Redis**: Cache de sessões e dados frequentes
- **Gateway de Pagamento**: Processamento de pagamentos
- **Email Service**: Envio de emails

**Fluxos de Dados Identificados:**
1. Cliente → API Gateway: Requisições HTTP
2. API Gateway → API Users: Roteamento de requisições
3. API Users → Banco de Dados: Consulta/atualização de dados
4. API Users → Cache Redis: Armazenamento de sessões
5. API Users → Gateway Pagamento: Processamento de pagamentos
6. API Users → Email Service: Envio de emails

**Pontos de Entrada:**
- `/api/login` (POST): Login de usuários
- `/api/users/<id>` (GET, PUT): Consulta/atualização de perfil
- `/api/payment` (POST): Processamento de pagamentos

**Ativos Sensíveis:**
- Credenciais de login (senhas)
- Dados pessoais de usuários
- Dados de pagamento (cartões)
- Tokens de sessão
- Chaves de API

**Validação Técnica:**
- ✅ Arquitetura complexa identificada
- ✅ Componentes principais listados
- ✅ Fluxos de dados mapeados
- ✅ Pontos de entrada identificados
- ✅ Ativos sensíveis listados

---

### Parte 2: Identificar Ameaças por Componente - API Gateway

**Solução Esperada:**

#### S - Spoofing

**Ameaça**: Falsificação de identidade (acesso não autorizado através de roteamento incorreto)

**Impacto**: Crítico (acesso não autorizado)

**Mitigação**: Autenticação forte, validação de tokens, rate limiting

#### T - Tampering

**Ameaça**: Modificação de requisições (MITM, modificação de headers)

**Impacto**: Crítico (bypass de autenticação/autorização)

**Mitigação**: HTTPS obrigatório, validação de integridade, assinatura digital

#### I - Information Disclosure

**Ameaça**: Vazamento de informações em logs ou headers

**Impacto**: Alto (exposição de dados sensíveis)

**Mitigação**: Logs sanitizados, headers limpos, não logar dados sensíveis

#### D - Denial of Service

**Ameaça**: Sobrecarga do gateway (ataque DDoS, roteamento incorreto)

**Impacto**: Alto (serviço indisponível)

**Mitigação**: Rate limiting, monitoramento de tráfego, balanceamento de carga

**Validação Técnica:**
- ✅ STRIDE aplicado para API Gateway
- ✅ Ameaças específicas de gateway identificadas
- ✅ Mitigações técnicas específicas

---

### Parte 2: Identificar Ameaças por Componente - Cache Redis

**Solução Esperada:**

#### T - Tampering

**Ameaça**: Cache poisoning (dados corrompidos no cache)

**Impacto**: Alto (dados incorretos servidos)

**Mitigação**: Validação de dados antes de cachear, TTL apropriado, invalidação de cache

#### I - Information Disclosure

**Ameaça**: Acesso não autorizado ao cache (dados sensíveis em cache)

**Impacto**: Crítico (exposição de dados sensíveis)

**Mitigação**: Isolamento de cache, criptografia de dados sensíveis em cache, acesso restrito

#### D - Denial of Service

**Ameaça**: Sobrecarga do Redis (chaves expiradas incorretamente, cache thrashing)

**Impacto**: Alto (degradação de performance)

**Mitigação**: Configuração adequada de TTL, monitoramento de memória, eviction policies

**Validação Técnica:**
- ✅ STRIDE aplicado para Cache Redis
- ✅ Ameaças específicas de cache identificadas
- ✅ Mitigações técnicas específicas

---

### Parte 2: Identificar Ameaças por Componente - Gateway de Pagamento

**Solução Esperada:**

#### I - Information Disclosure

**Ameaça**: Vazamento de dados de cartão (logs, mensagens de erro, tráfego)

**Impacto**: Crítico (violação PCI-DSS)

**Mitigação**: Tokenização, nunca armazenar dados de cartão, HTTPS obrigatório, logs sanitizados

#### T - Tampering

**Ameaça**: Modificação de transações (alteração de valor, destino)

**Impacto**: Crítico (fraude financeira)

**Mitigação**: Validação de integridade, assinatura digital, logs imutáveis

#### R - Repudiation

**Ameaça**: Negação de transações (usuário nega ter feito transação)

**Impacto**: Alto (disputas, fraude)

**Mitigação**: Logs imutáveis, assinatura digital, confirmação ao usuário

**Validação Técnica:**
- ✅ STRIDE aplicado para Gateway de Pagamento
- ✅ Ameaças específicas de pagamento identificadas
- ✅ PCI-DSS considerado

---

### Parte 3: Identificar Ameaças em Fluxos - Processamento de Pagamento

**Solução Esperada:**

**Fluxo:**
1. Cliente envia dados de pagamento → API Gateway
2. API Gateway → API Users (roteamento)
3. API Users valida dados
4. API Users → Gateway Pagamento (processamento)
5. Gateway Pagamento → API Users (confirmação)
6. API Users atualiza status
7. API Users → Email Service (confirmação)

**Ameaças Identificadas:**

**Ameaça 1: Vazamento de Dados de Cartão no Fluxo**
- **Onde**: Passos 1, 2, 3 (dados de cartão em trânsito)
- **Risco**: Crítico
- **Mitigação**: Tokenização, HTTPS obrigatório, não armazenar dados de cartão

**Ameaça 2: Modificação de Valor de Transação**
- **Onde**: Passos 2, 3 (roteamento e validação)
- **Risco**: Crítico
- **Mitigação**: Validação de integridade, logs imutáveis, assinatura digital

**Ameaça 3: Man-in-the-Middle no Fluxo**
- **Onde**: Todos os passos (comunicação entre componentes)
- **Risco**: Crítico
- **Mitigação**: HTTPS obrigatório, certificados válidos, network segmentation

**Ameaça 4: Negação de Transação**
- **Onde**: Passos 4, 5, 6 (processamento e confirmação)
- **Risco**: Alto
- **Mitigação**: Logs imutáveis, confirmação ao usuário, assinatura digital

**Validação Técnica:**
- ✅ Ameaças identificadas em fluxo específico
- ✅ Localização precisa no fluxo
- ✅ Risco adequado (Crítico/Alto)
- ✅ Mitigações técnicas específicas

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Análise de Arquitetura:**
- [ ] Componentes principais identificados (pelo menos 4-5)
- [ ] Fluxos de dados mapeados (pelo menos 3-4 fluxos)
- [ ] Pontos de entrada identificados
- [ ] Ativos sensíveis listados

**Identificação de Ameaças:**
- [ ] STRIDE aplicado para pelo menos 3 componentes
- [ ] Pelo menos 2-3 ameaças identificadas por componente
- [ ] Ameaças documentadas com descrição e impacto

**Ameaças em Fluxos:**
- [ ] Pelo menos 1 fluxo analisado detalhadamente
- [ ] Pelo menos 2-3 ameaças identificadas no fluxo
- [ ] Localização da ameaça no fluxo documentada

### ⭐ Importantes (Recomendados para Resposta Completa)

**Análise de Arquitetura:**
- [ ] Todos os componentes principais identificados
- [ ] Todos os fluxos de dados mapeados
- [ ] Análise detalhada de cada componente

**Identificação de Ameaças:**
- [ ] STRIDE aplicado para todos os componentes principais
- [ ] Múltiplas ameaças identificadas por componente (3-5)
- [ ] Ameaças específicas do componente identificadas (não genéricas)

**Ameaças em Fluxos:**
- [ ] Múltiplos fluxos analisados (2-3)
- [ ] Ameaças específicas do fluxo identificadas
- [ ] Mitigações propostas para cada ameaça

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Aprofundamento:**
- [ ] Ameaças não óbvias identificadas
- [ ] Análise de risco detalhada (probabilidade, impacto)
- [ ] Múltiplas mitigações por ameaça (defense in depth)

**Aplicação:**
- [ ] Arquitetura real ou muito complexa analisada
- [ ] Ameaças específicas de integrações identificadas
- [ ] Processo de revisão documentado

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Análise de Arquitetura**: Aluno consegue analisar arquiteturas complexas?
2. **Identificação de Ameaças**: Aluno identifica ameaças específicas de cada componente?
3. **Análise de Fluxos**: Aluno identifica ameaças em fluxos de dados?

### Erros Comuns

1. **Erro: Ameaças genéricas**
   - **Situação**: Aluno identifica ameaças genéricas que aplicam a qualquer componente
   - **Feedback**: "Boa identificação de ameaças! Para tornar análise mais útil, identifique ameaças específicas de cada componente: para Cache Redis, considere 'cache poisoning' e 'expiração incorreta de TTL'. Para Gateway de Pagamento, considere 'vazamento de dados de cartão' e 'modificação de transações'. Isso torna análise mais valiosa."

2. **Erro: Não analisar fluxos**
   - **Situação**: Aluno identifica ameaças apenas por componente, não considera fluxos
   - **Feedback**: "Boa análise por componente! Lembre-se de também analisar fluxos de dados: ameaças podem ocorrer na comunicação entre componentes. Analise cada passo do fluxo (ex: Cliente → Gateway → API → Banco) e identifique ameaças específicas de cada etapa."

### Dicas para Feedback

- ✅ **Reconheça**: Análise completa de arquitetura, identificação de ameaças específicas, análise de fluxos
- ❌ **Corrija**: Ameaças genéricas, falta de análise de fluxos, ameaças não específicas
- 💡 **Incentive**: Ameaças não óbvias, análise de integrações, múltiplas mitigações

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Aplicações Reais**: Aplicações reais têm arquiteturas complexas
2. **Habilidade Essencial**: QA precisa saber analisar arquiteturas complexas
3. **Análise Completa**: Ensina análise por componente e por fluxo
4. **Especificidade**: Desenvolve capacidade de identificar ameaças específicas

**Conexão com o Curso:**
- Aula 1.4: Threat Modeling (teoria) → Este exercício (prática de arquiteturas complexas)
- Pré-requisito para: Exercícios avançados de threat modeling (1.4.3-1.4.5)
- Base para: Análise de arquiteturas reais

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Análise de Arquitetura:**
"Arquitetura identificada: Cliente Web → API Gateway → API Users → Banco de Dados. Componentes adicionais: Cache Redis, Gateway Pagamento, Email Service. Fluxos mapeados: login (Cliente → Gateway → API → Banco), pagamento (Cliente → Gateway → API → Gateway Pagamento → API → Email). Pontos de entrada: /api/login, /api/users/<id>, /api/payment. Ativos sensíveis: credenciais, dados pessoais, dados de cartão, tokens."

**Ameaças por Componente:**
"API Gateway: S-Spoofing (falsificação de identidade via roteamento incorreto), T-Tampering (modificação de requisições MITM), I-Information Disclosure (vazamento em logs), D-DoS (sobrecarga). Cache Redis: T-Cache poisoning (dados corrompidos), I-Acesso não autorizado (dados sensíveis em cache), D-Sobrecarga (chaves expiradas incorretamente). Gateway Pagamento: I-Vazamento de dados de cartão (PCI-DSS), T-Modificação de transações (fraude), R-Negação de transações (disputas)."

**Ameaças em Fluxos:**
"Fluxo de Pagamento: Passo 1-3 (vazamento de dados de cartão em trânsito - Crítico), Passo 2-3 (modificação de valor - Crítico), Todos os passos (MITM - Crítico), Passo 4-6 (negação de transação - Alto). Mitigações: tokenização, HTTPS, validação de integridade, logs imutáveis."

**Características da Resposta:**
- ✅ Análise completa de arquitetura
- ✅ STRIDE aplicado para múltiplos componentes
- ✅ Ameaças específicas identificadas
- ✅ Análise de fluxos detalhada
- ✅ Mitigações técnicas específicas

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
