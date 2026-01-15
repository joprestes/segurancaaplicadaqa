---
exercise_id: lesson-1-4-exercise-4-threat-model-completo
title: "Exercício 1.4.4: Criar Threat Model Completo"
lesson_id: lesson-1-4
module: module-1
difficulty: "Avançado"
last_updated: 2025-01-15
---

# Exercício 1.4.4: Criar Threat Model Completo

## 📋 Enunciado Completo

Este exercício tem como objetivo criar um **threat model completo** para uma aplicação real, aplicando todas as técnicas aprendidas.

### Tarefa Principal

1. Escolher aplicação (Ecommerce, Educacional, Financeira)
2. Criar threat model completo usando STRIDE + DREAD
3. Documentar ameaças e mitigações
4. Criar plano de validação

---

## ✅ Soluções Detalhadas

### Parte 1: Escolher Aplicação - Sistema de Ecommerce

**Solução Esperada:**

**Aplicação Escolhida**: Sistema de Ecommerce

**Arquitetura:**
```
Cliente Web → API Gateway → API REST → Banco de Dados
                      │
                      ├──→ Cache Redis
                      ├──→ Gateway Pagamento
                      └──→ Email Service
```

**Funcionalidades:**
- Login de clientes
- Catálogo de produtos
- Carrinho de compras
- Checkout e pagamento
- Área do cliente (pedidos, dados pessoais)

**Componentes Identificados:**
- **Cliente Web**: Frontend (React/Vue)
- **API Gateway**: Roteamento, autenticação, rate limiting
- **API REST**: Endpoints `/api/login`, `/api/products`, `/api/cart`, `/api/checkout`, `/api/orders`
- **Banco de Dados**: Armazena produtos, pedidos, clientes
- **Cache Redis**: Cache de produtos, sessões
- **Gateway Pagamento**: Processamento de pagamentos (PCI-DSS)
- **Email Service**: Confirmações de pedidos

**Ativos Sensíveis:**
- Credenciais de clientes (senhas)
- Dados pessoais (nome, email, endereço)
- Dados de pagamento (cartões - PCI-DSS)
- Dados de pedidos (histórico de compras)

**Validação Técnica:**
- ✅ Aplicação escolhida e arquitetura documentada
- ✅ Componentes principais identificados
- ✅ Ativos sensíveis listados

---

### Parte 2: Criar Threat Model Completo

**Solução Esperada - Threat Model:**

```markdown
# Threat Model - Sistema de Ecommerce

## Informações Gerais
- Data: 2025-01-15
- Versão: 1.0
- Responsável: Equipe QA
- Metodologia: STRIDE + DREAD

## Arquitetura
[Diagrama da arquitetura - conforme acima]

## Ativos
1. Credenciais de clientes (senhas)
2. Dados pessoais (nome, email, endereço)
3. Dados de pagamento (cartões - PCI-DSS)
4. Dados de pedidos (histórico de compras)
5. Dados de produtos (catálogo)

## Pontos de Entrada
1. /api/login (POST): Login de clientes
2. /api/products (GET): Catálogo de produtos
3. /api/cart (GET, POST, DELETE): Carrinho de compras
4. /api/checkout (POST): Checkout e pagamento
5. /api/orders/<id> (GET): Consulta de pedidos

## Ameaças Identificadas

### Críticas (DREAD > 8.0)

#### T-001: SQL Injection em Busca de Produtos
**Componente**: API REST - /api/products?q=
**STRIDE**: I - Information Disclosure
**DREAD**: 9.6 (D:9, R:10, E:9, A:10, D:10)
**Descrição**: Endpoint de busca vulnerável a SQL Injection
**Mitigação**: Prepared statements, validação de entrada
**Validação**: Teste de SQL Injection, validação de código

#### T-002: Broken Access Control em Pedidos
**Componente**: API REST - /api/orders/<id>
**STRIDE**: I - Information Disclosure
**DREAD**: 9.0 (D:8, R:10, E:9, A:9, D:9)
**Descrição**: Clientes podem acessar pedidos de outros
**Mitigação**: Validação de propriedade no servidor
**Validação**: Teste de IDOR, validação de código

#### T-003: Vazamento de Dados de Cartão
**Componente**: Gateway Pagamento, API REST
**STRIDE**: I - Information Disclosure
**DREAD**: 9.8 (D:10, R:10, E:8, A:10, D:10)
**Descrição**: Dados de cartão podem ser vazados em logs ou tráfego
**Mitigação**: Tokenização, nunca armazenar dados de cartão, HTTPS obrigatório
**Validação**: Verificação de logs, teste de HTTPS, validação de tokenização

### Altas (DREAD 6.0-8.0)

#### T-004: Senha Fraca Permitida
**Componente**: API REST - /api/login
**STRIDE**: S - Spoofing
**DREAD**: 8.2 (D:6, R:10, E:7, A:8, D:10)
**Descrição**: Sistema aceita senhas muito simples
**Mitigação**: Política de senhas forte (12+ caracteres, complexidade)
**Validação**: Teste de política de senhas

#### T-005: Cache Poisoning em Produtos
**Componente**: Cache Redis
**STRIDE**: T - Tampering
**DREAD**: 7.0 (D:7, R:8, E:6, A:8, D:7)
**Descrição**: Dados corrompidos no cache podem ser servidos
**Mitigação**: Validação de dados antes de cachear, TTL apropriado
**Validação**: Teste de cache poisoning

### Médias (DREAD 4.0-6.0)

#### T-006: Negação de Transação
**Componente**: Gateway Pagamento
**STRIDE**: R - Repudiation
**DREAD**: 5.5 (D:5, R:8, E:4, A:6, D:6)
**Descrição**: Cliente pode negar ter feito transação
**Mitigação**: Logs imutáveis, confirmação ao cliente, assinatura digital
**Validação**: Verificação de logs, teste de confirmação

## Mitigações Prioritárias

### P1 - IMEDIATO (24h)
1. Corrigir SQL Injection em busca (T-001)
2. Corrigir Broken Access Control em pedidos (T-002)
3. Validar tokenização de dados de cartão (T-003)

### P2 - Este Sprint (3 dias)
4. Implementar política de senhas forte (T-004)
5. Validar cache de produtos (T-005)

### P3 - Próximo Sprint (1 semana)
6. Implementar logs imutáveis para transações (T-006)

## Plano de Validação

### Testes de Segurança
- [ ] Teste de SQL Injection em todos os campos de busca
- [ ] Teste de IDOR em todos os endpoints com ID
- [ ] Verificação de tokenização de dados de cartão
- [ ] Teste de política de senhas
- [ ] Teste de cache poisoning
- [ ] Verificação de logs de transações

### Validação de Código
- [ ] Code review focado em segurança
- [ ] Validação de prepared statements
- [ ] Validação de validação de propriedade
- [ ] Validação de tokenização

### Validação de Configuração
- [ ] Verificação de HTTPS obrigatório
- [ ] Verificação de configuração de cache
- [ ] Verificação de logs sanitizados
```

**Validação Técnica:**
- ✅ Threat model completo e estruturado
- ✅ STRIDE + DREAD aplicados
- ✅ Ameaças priorizadas
- ✅ Mitigações propostas
- ✅ Plano de validação criado

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Escolha de Aplicação:**
- [ ] Aplicação escolhida (Ecommerce, Educacional, ou Financeira)
- [ ] Arquitetura documentada
- [ ] Componentes principais identificados
- [ ] Ativos sensíveis listados

**Threat Model:**
- [ ] STRIDE aplicado para pelo menos 3 componentes
- [ ] DREAD aplicado para pelo menos 5 ameaças
- [ ] Pelo menos 5-7 ameaças identificadas
- [ ] Mitigações propostas para ameaças críticas

**Priorização:**
- [ ] Ameaças priorizadas (P1/P2/P3)
- [ ] Priorização justificada

### ⭐ Importantes (Recomendados para Resposta Completa)

**Threat Model:**
- [ ] STRIDE + DREAD aplicados completamente
- [ ] 10+ ameaças identificadas
- [ ] Ameaças categorizadas por severidade (Críticas, Altas, Médias)
- [ ] Mitigações detalhadas para cada ameaça crítica

**Plano de Validação:**
- [ ] Plano de validação criado
- [ ] Testes de segurança definidos
- [ ] Validação de código incluída
- [ ] Validação de configuração incluída

**Documentação:**
- [ ] Threat model bem estruturado e profissional
- [ ] Template padronizado usado
- [ ] Informações completas (data, versão, responsável)

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Aprofundamento:**
- [ ] Ameaças não óbvias identificadas
- [ ] Análise de risco detalhada
- [ ] Múltiplas mitigações por ameaça (defense in depth)

**Aplicação:**
- [ ] Threat model aplicado em projeto real
- [ ] Processo de revisão documentado
- [ ] Integração com processo de desenvolvimento

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Threat Model Completo**: Aluno consegue criar threat model profissional?
2. **Aplicação de Metodologias**: Aluno aplica STRIDE + DREAD completamente?
3. **Priorização**: Aluno prioriza ameaças adequadamente?
4. **Plano de Validação**: Aluno cria plano de validação completo?

### Erros Comuns

1. **Erro: Threat model incompleto**
   - **Situação**: Aluno cria threat model sem plano de validação ou mitigações
   - **Feedback**: "Boa identificação de ameaças! Para tornar threat model completo, inclua: mitigações detalhadas para cada ameaça crítica, plano de validação com testes específicos, e priorização de implementação. Isso torna threat model acionável."

2. **Erro: Ameaças não priorizadas**
   - **Situação**: Aluno identifica ameaças mas não prioriza
   - **Feedback**: "Boa identificação de ameaças! Lembre-se de priorizar: use DREAD para calcular risco, categorize por severidade (Críticas, Altas, Médias), e defina prioridades de implementação (P1/P2/P3). Isso aloca recursos adequadamente."

### Dicas para Feedback

- ✅ **Reconheça**: Threat model completo, aplicação de metodologias, priorização adequada, plano de validação
- ❌ **Corrija**: Threat model incompleto, falta de priorização, plano de validação ausente
- 💡 **Incentive**: Ameaças não óbvias, múltiplas mitigações, processo de revisão

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Prática Completa**: Integra todas as técnicas de threat modeling aprendidas
2. **Habilidade Essencial**: QA precisa saber criar threat models completos
3. **Aplicação Real**: Threat models são usados em projetos reais
4. **Prevenção**: Threat modeling previne vulnerabilidades antes do desenvolvimento

**Conexão com o Curso:**
- Aula 1.4: Threat Modeling (teoria) → Este exercício (prática completa)
- Integra todos os exercícios anteriores de threat modeling
- Base para: Threat modeling em projetos reais

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Threat Model Criado:**
"Threat model completo para Sistema de Ecommerce. Arquitetura: Cliente → API Gateway → API REST → Banco de Dados. Componentes: Gateway, API, Banco, Cache, Gateway Pagamento. STRIDE aplicado para todos os componentes. DREAD aplicado para 10+ ameaças. Ameaças críticas (DREAD > 8.0): SQL Injection (9.6), Broken Access Control (9.0), Vazamento de Cartão (9.8). Mitigações propostas: prepared statements, validação de propriedade, tokenização. Priorização: P1 (24h) para críticas, P2 (3 dias) para altas. Plano de validação: testes de segurança, code review, validação de configuração."

**Características da Resposta:**
- ✅ Threat model completo e estruturado
- ✅ STRIDE + DREAD aplicados completamente
- ✅ 10+ ameaças identificadas e priorizadas
- ✅ Mitigações detalhadas propostas
- ✅ Plano de validação completo

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
