---
exercise_id: lesson-1-5-exercise-4-compliance-por-setor
title: "Exercício 1.5.4: Compliance por Setor"
lesson_id: lesson-1-5
module: module-1
difficulty: "Avançado"
last_updated: 2025-01-15
---

# Exercício 1.5.4: Compliance por Setor

## 📋 Enunciado Completo

Este exercício tem como objetivo **aplicar compliance específico por setor** através da criação de checklists e validação de requisitos específicos para Financeiro, Educacional e Ecommerce.

### Tarefa Principal

1. Entender requisitos de compliance por setor
2. Criar checklists específicos por setor
3. Validar compliance multi-regulamentação
4. Aplicar compliance em contextos específicos

---

## ✅ Soluções Detalhadas

### Parte 1: Projeto Financeiro - Fintech

**Aplicação**: Plataforma de Pagamentos

**Regulamentações Aplicáveis:**
- PCI-DSS (pagamentos)
- LGPD (dados pessoais)
- Resolução BCB (Banco Central)
- Open Banking (compartilhamento de dados)

**Solução Esperada - Checklist Financeiro:**

```markdown
# Checklist Compliance Financeiro - Plataforma de Pagamentos

## PCI-DSS (Prioridade Crítica)

### Requisito 3: Proteger Dados Armazenados
- [ ] Dados de cartão tokenizados (nunca armazenar número completo)
- [ ] Apenas últimos 4 dígitos armazenados para identificação (se necessário)
- [ ] CVV nunca armazenado (mesmo após transação)
- [ ] Dados de cartão não aparecem em logs

### Requisito 4: Criptografar em Trânsito
- [ ] HTTPS obrigatório em todo o fluxo de pagamento
- [ ] TLS 1.2+ obrigatório (não TLS 1.0, 1.1)
- [ ] Certificados SSL válidos e atualizados

### Requisito 6: Sistemas Seguros
- [ ] Secure coding practices (OWASP Top 10)
- [ ] Testes de segurança realizados (SQL Injection, XSS, Broken Access Control)
- [ ] Dependências atualizadas (sem CVE conhecidos)
- [ ] Code reviews de segurança realizados

### Requisito 8: Autenticação Forte
- [ ] Autenticação forte (senhas 12+ caracteres, complexidade)
- [ ] MFA obrigatório para operações sensíveis (transferências acima de R$ 1.000)
- [ ] Sessões expiram após inatividade

### Requisito 10: Monitoramento
- [ ] Logs de todas as transações (processamento, consulta, modificação)
- [ ] Logs retidos por pelo menos 1 ano
- [ ] Monitoramento em tempo real configurado (alertas de fraude)

## LGPD (Prioridade Alta)

### Princípio da Finalidade
- [ ] Finalidade do tratamento clara (pagamentos, transferências)
- [ ] Dados usados apenas para finalidade declarada
- [ ] Política de privacidade clara e acessível

### Princípio da Segurança
- [ ] Criptografia de dados pessoais (HTTPS, hash de senhas)
- [ ] Controle de acesso (isolamento de contas)
- [ ] Logs de auditoria (acesso a dados pessoais)

### Direitos do Titular
- [ ] Usuário pode acessar seus dados
- [ ] Usuário pode corrigir dados
- [ ] Usuário pode excluir dados
- [ ] Usuário pode solicitar portabilidade

## Resolução BCB (Prioridade Alta)

### Autenticação Forte
- [ ] Autenticação forte implementada
- [ ] MFA obrigatório para operações sensíveis

### Controles de Segurança
- [ ] Controles de segurança implementados
- [ ] Monitoramento de transações
- [ ] Prevenção de fraudes

## Open Banking (Prioridade Média)

### Consentimento para Compartilhamento
- [ ] Consentimento explícito para compartilhamento de dados
- [ ] Usuário pode revogar consentimento

### APIs Seguras
- [ ] APIs seguras (HTTPS, autenticação, autorização)
- [ ] Controle de acesso (apenas dados autorizados)

### Logs de Compartilhamento
- [ ] Logs de todas as operações de compartilhamento
- [ ] Auditoria de compartilhamento de dados
```

**Validação Técnica:**
- ✅ Checklist criado para contexto financeiro
- ✅ PCI-DSS priorizado (pagamentos)
- ✅ LGPD considerado (dados pessoais)
- ✅ Resolução BCB e Open Banking incluídos

---

### Parte 1: Projeto Educacional - EdTech

**Aplicação**: Plataforma de E-learning

**Regulamentações Aplicáveis:**
- LGPD (dados pessoais, especialmente dados de menores)
- Não aplicável: PCI-DSS (não processa pagamentos)

**Solução Esperada - Checklist Educacional:**

```markdown
# Checklist Compliance Educacional - Plataforma de E-learning

## LGPD (Prioridade Crítica - Especialmente Dados de Menores)

### Princípio da Finalidade
- [ ] Finalidade clara (ensino, certificados, avaliações)
- [ ] Dados usados apenas para finalidade declarada
- [ ] Política de privacidade clara e acessível (linguagem simples)

### Princípio da Necessidade
- [ ] Apenas dados necessários coletados (CPF apenas para certificados)
- [ ] Dados mínimos solicitados
- [ ] Não há coleta excessiva

### Princípio da Transparência
- [ ] Política de privacidade acessível (link visível, linguagem simples)
- [ ] Usuário informado sobre uso de dados (antes de coletar)
- [ ] Termos claros e compreensíveis (especialmente para pais/responsáveis)

### Princípio da Segurança
- [ ] Dados protegidos adequadamente (criptografia, controle de acesso)
- [ ] Criptografia implementada (HTTPS, hash de senhas, dados sensíveis)
- [ ] Controle de acesso ativo (isolamento de dados entre alunos)
- [ ] Logs de auditoria (acesso a dados de menores especialmente protegidos)

### Princípio da Prevenção
- [ ] Medidas preventivas implementadas (validação de entrada, prepared statements)
- [ ] Testes de segurança realizados (SQL Injection, Broken Access Control)
- [ ] Vulnerabilidades corrigidas

### Proteção de Dados de Menores (Prioridade Crítica)
- [ ] Consentimento de responsável obrigatório (para menores de 18 anos)
- [ ] Dados de menores têm proteção adicional (criptografia adicional, acesso restrito)
- [ ] Dados de menores isolados (acesso restrito apenas a responsáveis e professores autorizados)
- [ ] Política específica para menores (linguagem apropriada)

### Direitos do Titular
- [ ] Usuário pode acessar seus dados (ou responsável para menores)
- [ ] Usuário pode corrigir dados
- [ ] Usuário pode excluir dados
- [ ] Usuário pode solicitar portabilidade
```

**Validação Técnica:**
- ✅ Checklist criado para contexto educacional
- ✅ LGPD priorizado (especialmente dados de menores)
- ✅ Proteção de menores especialmente considerada
- ✅ PCI-DSS não aplicável (não processa pagamentos)

---

### Parte 1: Projeto Ecommerce

**Aplicação**: Loja Online

**Regulamentações Aplicáveis:**
- PCI-DSS (pagamentos)
- LGPD (dados pessoais de clientes)

**Solução Esperada - Checklist Ecommerce:**

```markdown
# Checklist Compliance Ecommerce - Loja Online

## PCI-DSS (Prioridade Crítica)

### Requisito 3: Proteger Dados Armazenados
- [ ] Dados de cartão tokenizados (usar gateway de pagamento)
- [ ] Apenas últimos 4 dígitos armazenados para identificação (se necessário)
- [ ] CVV nunca armazenado

### Requisito 4: Criptografar em Trânsito
- [ ] HTTPS obrigatório em todo o checkout
- [ ] TLS 1.2+ obrigatório

### Requisito 6: Sistemas Seguros
- [ ] Secure coding practices
- [ ] Testes de segurança realizados
- [ ] Dependências atualizadas

### Requisito 10: Monitoramento
- [ ] Logs de todas as transações
- [ ] Monitoramento de fraudes

## LGPD (Prioridade Alta)

### Princípio da Finalidade
- [ ] Finalidade clara (vendas, entregas, atendimento)
- [ ] Dados usados apenas para finalidade declarada

### Princípio da Segurança
- [ ] Criptografia de dados pessoais (HTTPS, hash de senhas)
- [ ] Controle de acesso (isolamento de pedidos entre clientes)
- [ ] Logs de auditoria

### Direitos do Titular
- [ ] Cliente pode acessar seus dados (pedidos, dados pessoais)
- [ ] Cliente pode corrigir dados
- [ ] Cliente pode excluir dados
- [ ] Cliente pode solicitar portabilidade

## Prevenção de Fraude (Prioridade Alta)

### Validação de Transações
- [ ] Validação de integridade de preços (clientes não podem modificar preços)
- [ ] Validação de estoque (prevenir overselling)
- [ ] Rate limiting em checkout (prevenir abusos)

### Monitoramento de Fraudes
- [ ] Monitoramento de transações suspeitas
- [ ] Alertas de fraude configurados
- [ ] Bloqueio de transações fraudulentas
```

**Validação Técnica:**
- ✅ Checklist criado para contexto ecommerce
- ✅ PCI-DSS priorizado (pagamentos)
- ✅ LGPD considerado (dados de clientes)
- ✅ Prevenção de fraude incluída

---

### Parte 2: Validar Compliance Multi-Regulamentação

**Solução Esperada:**

```markdown
# Relatório de Compliance Multi-Regulamentação

## Aplicação: Plataforma de Pagamentos (Fintech)

### Regulamentações Aplicáveis
- PCI-DSS (crítico - pagamentos)
- LGPD (alta - dados pessoais)
- Resolução BCB (alta - regulamentação bancária)
- Open Banking (média - compartilhamento de dados)

### Status de Conformidade

#### PCI-DSS
- **Status**: ✅ Conforme
- **Controles Validados**: Tokenização, HTTPS obrigatório, autenticação forte, logs
- **Evidências**: Dados tokenizados, certificado SSL válido, testes de autenticação passando

#### LGPD
- **Status**: ✅ Conforme
- **Controles Validados**: Consentimento, direitos do titular, proteção de dados
- **Evidências**: Consentimento implementado, endpoints de direitos funcionando

#### Resolução BCB
- **Status**: ✅ Conforme
- **Controles Validados**: Autenticação forte, MFA, monitoramento de transações
- **Evidências**: MFA implementado, alertas configurados

#### Open Banking
- **Status**: ⚠️ Parcialmente Conforme
- **Controles Validados**: Consentimento para compartilhamento, APIs seguras
- **Observações**: Logs de compartilhamento podem ser melhorados

### Não Conformidades Encontradas
1. **Open Banking**: Logs de compartilhamento podem ser melhorados (P3 - melhorar quando possível)

### Recomendações Prioritárias
1. **P1 - IMEDIATO**: Validar tokenização de dados de cartão (PCI-DSS)
2. **P1 - IMEDIATO**: Implementar MFA obrigatório para transferências (PCI-DSS, Resolução BCB)
3. **P2 - Este Sprint**: Melhorar logs de compartilhamento (Open Banking)
4. **P3 - Próximo Sprint**: Documentar integração de compliance (matriz de requisitos)
```

**Validação Técnica:**
- ✅ Compliance multi-regulamentação validada
- ✅ Status de conformidade documentado para cada regulamentação
- ✅ Não conformidades identificadas
- ✅ Recomendações priorizadas

---

### Parte 3: Criar Matriz de Requisitos

**Solução Esperada:**

```markdown
# Matriz de Requisitos de Compliance - Financeiro

## Requisitos por Regulamentação

| Requisito | PCI-DSS | LGPD | Resolução BCB | Open Banking | Prioridade |
|-----------|---------|------|---------------|--------------|------------|
| Tokenização de Cartão | ✅ Req 3 | - | - | - | P1 - Crítico |
| HTTPS Obrigatório | ✅ Req 4 | ✅ Segurança | ✅ Segurança | ✅ APIs Seguras | P1 - Crítico |
| Autenticação Forte | ✅ Req 8 | ✅ Segurança | ✅ Autenticação | - | P1 - Crítico |
| MFA Obrigatório | ✅ Req 8 | - | ✅ Autenticação | - | P1 - Crítico |
| Logs de Transações | ✅ Req 10 | ✅ Auditoria | ✅ Monitoramento | ✅ Logs Compartilhamento | P1 - Crítico |
| Consentimento | - | ✅ Finalidade | - | ✅ Compartilhamento | P2 - Alta |
| Direitos do Titular | - | ✅ Direitos | - | ✅ Direitos | P2 - Alta |
| Proteção de Dados | ✅ Req 3 | ✅ Segurança | ✅ Segurança | ✅ Confidencialidade | P1 - Crítico |

## Requisitos Comuns (Múltiplas Regulamentações)
1. **HTTPS Obrigatório**: PCI-DSS (Req 4), LGPD (Segurança), Resolução BCB (Segurança), Open Banking (APIs Seguras)
2. **Autenticação Forte**: PCI-DSS (Req 8), LGPD (Segurança), Resolução BCB (Autenticação)
3. **Logs de Auditoria**: PCI-DSS (Req 10), LGPD (Auditoria), Resolução BCB (Monitoramento), Open Banking (Logs)
4. **Proteção de Dados**: PCI-DSS (Req 3), LGPD (Segurança), Resolução BCB (Segurança), Open Banking (Confidencialidade)
```

**Validação Técnica:**
- ✅ Matriz de requisitos criada
- ✅ Requisitos mapeados para cada regulamentação
- ✅ Requisitos comuns identificados
- ✅ Prioridades definidas

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Checklists por Setor:**
- [ ] Checklists criados para pelo menos 2 setores (Financeiro, Educacional, ou Ecommerce)
- [ ] Cada checklist tem pelo menos 10-15 itens
- [ ] Regulamentações aplicáveis identificadas para cada setor

**Validação Multi-Regulamentação:**
- [ ] Compliance multi-regulamentação validada para pelo menos 1 setor
- [ ] Status de conformidade documentado

**Matriz:**
- [ ] Matriz de requisitos criada (mínimo básico)

### ⭐ Importantes (Recomendados para Resposta Completa)

**Checklists por Setor:**
- [ ] Checklists criados para 3 setores (Financeiro, Educacional, Ecommerce)
- [ ] Cada checklist tem 20+ itens detalhados
- [ ] Checklists são específicos para cada setor (não genéricos)
- [ ] Prioridades definidas (P1/P2/P3)

**Validação Multi-Regulamentação:**
- [ ] Compliance multi-regulamentação validada para todos os setores
- [ ] Status de conformidade completo para cada regulamentação
- [ ] Não conformidades identificadas e priorizadas

**Matriz:**
- [ ] Matriz completa criada
- [ ] Requisitos mapeados para todas as regulamentações
- [ ] Requisitos comuns identificados

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Checklists:**
- [ ] Checklists customizados para aplicações específicas
- [ ] Integração com frameworks existentes (ISO 27001)
- [ ] Processo de atualização documentado

**Validação:**
- [ ] Processo completo de validação multi-regulamentação documentado
- [ ] Métricas de compliance definidas
- [ ] Preparação para auditorias múltiplas documentada

**Aplicação:**
- [ ] Checklists aplicados em projetos reais
- [ ] Compliance validado e documentado
- [ ] Não conformidades corrigidas

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Compliance por Setor**: Aluno adapta compliance para diferentes setores?
2. **Multi-Regulamentação**: Aluno valida compliance multi-regulamentação?
3. **Matriz de Requisitos**: Aluno cria matriz de requisitos comuns?

### Erros Comuns

1. **Erro: Checklist genérico para todos os setores**
   - **Situação**: Aluno usa mesmo checklist para Financeiro, Educacional e Ecommerce
   - **Feedback**: "Boa criação de checklist! Lembre-se de adaptar para cada setor: Financeiro prioriza PCI-DSS e Resolução BCB, Educacional prioriza LGPD (especialmente dados de menores) e não precisa PCI-DSS se não processa pagamentos, Ecommerce prioriza PCI-DSS e prevenção de fraude. Adaptação aumenta efetividade."

2. **Erro: Não identificar requisitos comuns**
   - **Situação**: Aluno valida cada regulamentação isoladamente sem identificar requisitos comuns
   - **Feedback**: "Boa validação de compliance! Para tornar mais eficiente, identifique requisitos comuns: 'HTTPS obrigatório' é requerido por PCI-DSS, LGPD, Resolução BCB e Open Banking. Implementar uma vez atende múltiplas regulamentações. Isso aumenta eficiência."

### Dicas para Feedback

- ✅ **Reconheça**: Checklists adaptados por setor, validação multi-regulamentação, matriz de requisitos
- ❌ **Corrija**: Checklist genérico, validação isolada, falta de matriz
- 💡 **Incentive**: Checklists customizados, identificação de requisitos comuns, processo de validação contínua

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Aplicação Real**: Diferentes setores têm diferentes requisitos de compliance
2. **Habilidade Essencial**: QA precisa saber adaptar compliance para diferentes contextos
3. **Eficiência**: Identificar requisitos comuns aumenta eficiência
4. **Multi-Regulamentação**: Aplicações reais precisam atender múltiplas regulamentações

**Conexão com o Curso:**
- Aula 1.5: Compliance e Regulamentações (teoria) → Este exercício (prática por setor)
- Integra todos os exercícios anteriores de compliance (LGPD, PCI-DSS, SOC2)
- Base para: Aplicação de compliance em projetos reais

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Checklists Criados:**
"Checklists criados para 3 setores. Financeiro: Prioriza PCI-DSS (tokenização, HTTPS, MFA), LGPD (direitos do titular), Resolução BCB (autenticação forte, monitoramento), Open Banking (consentimento, APIs seguras). Educacional: Prioriza LGPD (especialmente proteção de menores), consentimento de responsável, isolamento de dados. Ecommerce: Prioriza PCI-DSS (tokenização, HTTPS), LGPD (direitos do titular), prevenção de fraude."

**Matriz:**
"Matriz criada: HTTPS obrigatório requerido por PCI-DSS, LGPD, Resolução BCB, Open Banking. Autenticação forte requerida por PCI-DSS, LGPD, Resolução BCB. Logs de auditoria requeridos por PCI-DSS, LGPD, Resolução BCB, Open Banking. Requisitos comuns identificados para aumentar eficiência."

**Validação:**
"Compliance multi-regulamentação validado: PCI-DSS ✅, LGPD ✅, Resolução BCB ✅, Open Banking ⚠️ (logs podem melhorar). Não conformidades identificadas e priorizadas. Recomendações: P1 - Validar tokenização (PCI-DSS), P2 - Melhorar logs (Open Banking)."

**Características da Resposta:**
- ✅ Checklists adaptados para cada setor
- ✅ Multi-regulamentação validada
- ✅ Matriz de requisitos criada
- ✅ Requisitos comuns identificados
- ✅ Recomendações priorizadas

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
