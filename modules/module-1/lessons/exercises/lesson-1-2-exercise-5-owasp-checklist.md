---
layout: exercise
title: "Exercício 1.2.5: OWASP Top 10 Checklist Completo"
slug: "owasp-checklist"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Avançado"
permalink: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-2-exercise-5-owasp-checklist/
lesson_url: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/owasp-top-10/
---

## Objetivo

Este exercício tem como objetivo criar um **checklist completo de testes de segurança** baseado no OWASP Top 10 para uso em projetos reais.

Ao completar este exercício, você será capaz de:

- Criar checklist de testes para todas as vulnerabilidades OWASP Top 10
- Aplicar checklist em aplicações reais
- Documentar resultados de testes
- Priorizar vulnerabilidades por contexto

---

## Descrição

Você precisa criar um checklist completo e prático de testes de segurança baseado no OWASP Top 10, adaptado para diferentes contextos (Financeiro, Educacional, Ecommerce).

### Contexto

Como QA de segurança, você precisa de um checklist sistemático para garantir que todas as vulnerabilidades críticas sejam testadas. Este exercício desenvolve essa capacidade criando um checklist reutilizável.

---

## Requisitos

### Parte 1: Criar Checklist Base

Crie um checklist para cada vulnerabilidade do OWASP Top 10:

**Formato Sugerido**:
```markdown
## [Nome da Vulnerabilidade]

### Testes Básicos
- [ ] Teste 1: Descrição
- [ ] Teste 2: Descrição

### Testes Avançados
- [ ] Teste 3: Descrição

### Ferramentas Recomendadas
- Ferramenta 1: Descrição
- Ferramenta 2: Descrição

### Criticidade por Setor
- Financeiro: [Alta/Média/Baixa]
- Educacional: [Alta/Média/Baixa]
- Ecommerce: [Alta/Média/Baixa]
```

**Tarefas**:
- [ ] Criar checklist para Broken Access Control
- [ ] Criar checklist para Cryptographic Failures
- [ ] Criar checklist para Injection
- [ ] Criar checklist para Insecure Design
- [ ] Criar checklist para Security Misconfiguration
- [ ] Criar checklist para Vulnerable Components
- [ ] Criar checklist para Auth Failures
- [ ] Criar checklist para Data Integrity
- [ ] Criar checklist para Logging Failures
- [ ] Criar checklist para SSRF

---

### Parte 2: Adaptar por Contexto

Adapte o checklist para diferentes contextos:

#### Checklist Financeiro

**Tarefas**:
- [ ] Priorizar vulnerabilidades críticas para financeiro
- [ ] Adicionar testes específicos de PCI-DSS
- [ ] Incluir validações de Open Banking
- [ ] Adicionar testes de fraude

**Exemplo**:
```markdown
## Checklist Financeiro - OWASP Top 10

### Prioridade Crítica
1. Broken Access Control (acesso a contas)
2. Cryptographic Failures (dados de cartão)
3. Injection (dados bancários)

### Testes Específicos Financeiro
- [ ] Validar isolamento de contas entre clientes
- [ ] Testar criptografia de dados de cartão (PCI-DSS)
- [ ] Verificar rate limiting em transações
- [ ] Validar logs de auditoria (compliance)
```

#### Checklist Educacional

**Tarefas**:
- [ ] Priorizar vulnerabilidades críticas para educacional
- [ ] Adicionar testes específicos de LGPD (dados de menores)
- [ ] Incluir validações de isolamento de dados
- [ ] Adicionar testes de privacidade

#### Checklist Ecommerce

**Tarefas**:
- [ ] Priorizar vulnerabilidades críticas para ecommerce
- [ ] Adicionar testes de prevenção de fraude
- [ ] Incluir validações de integridade de preços
- [ ] Adicionar testes de transações

---

### Parte 3: Criar Template de Documentação

Crie um template para documentar resultados dos testes:

**Tarefas**:
- [ ] Criar template de relatório de testes
- [ ] Incluir seções para cada vulnerabilidade
- [ ] Adicionar campos para evidências (screenshots, logs)
- [ ] Criar sistema de priorização (Crítica, Alta, Média, Baixa)

**Template Sugerido**:
```markdown
# Relatório de Testes de Segurança - OWASP Top 10

## Informações Gerais
- **Aplicação**: [Nome]
- **Data**: [Data]
- **Testador**: [Nome]
- **Contexto**: [Financeiro/Educacional/Ecommerce]

## Resumo Executivo
- Total de vulnerabilidades encontradas: [X]
- Críticas: [X]
- Altas: [X]
- Médias: [X]
- Baixas: [X]

## Vulnerabilidades Encontradas

### [Vulnerabilidade]
- **Tipo**: [OWASP Top 10 #]
- **Severidade**: [Crítica/Alta/Média/Baixa]
- **Descrição**: [Descrição]
- **Evidência**: [Screenshot/Log]
- **Impacto**: [Impacto]
- **Recomendação**: [Como corrigir]
```

---

### Parte 4: Aplicar Checklist em Aplicação Real

Aplique o checklist em uma aplicação real ou de exemplo:

**Tarefas**:
- [ ] Escolher aplicação para testar (OWASP WebGoat, Juice Shop, ou própria)
- [ ] Executar checklist completo
- [ ] Documentar resultados usando template
- [ ] Priorizar vulnerabilidades encontradas
- [ ] Criar recomendações de correção

---

## Contexto CWI

### Caso Real: Checklist em Projeto Financeiro

Em um projeto financeiro da CWI, criamos checklist OWASP Top 10 adaptado para contexto financeiro. O checklist foi usado em todas as releases para garantir segurança.

**Resultados**:
- 15 vulnerabilidades identificadas antes de produção
- 8 vulnerabilidades críticas corrigidas
- Zero incidentes de segurança em produção
- Compliance PCI-DSS mantido

**Lição Aprendida**:
- Checklist sistemático é essencial
- Adaptação por contexto aumenta eficácia
- Documentação facilita correção
- Revisão regular do checklist é importante

---

## Checklist Completo de Referência

### 1. Broken Access Control
- [ ] Testar IDOR em todos os endpoints
- [ ] Validar controles de autorização
- [ ] Testar privilege escalation
- [ ] Verificar isolamento entre usuários

### 2. Cryptographic Failures
- [ ] Verificar hash de senhas
- [ ] Confirmar HTTPS obrigatório
- [ ] Validar algoritmos de criptografia
- [ ] Verificar gerenciamento de chaves

### 3. Injection
- [ ] Testar SQL Injection
- [ ] Testar NoSQL Injection
- [ ] Testar Command Injection
- [ ] Validar uso de prepared statements

### 4. Insecure Design
- [ ] Verificar rate limiting
- [ ] Testar validação de regras de negócio
- [ ] Validar isolamento de recursos
- [ ] Verificar autenticação forte

### 5. Security Misconfiguration
- [ ] Verificar headers de segurança
- [ ] Testar mensagens de erro
- [ ] Validar configurações padrão
- [ ] Verificar serviços desnecessários

### 6. Vulnerable Components
- [ ] Executar scanner de dependências
- [ ] Verificar atualizações disponíveis
- [ ] Validar versões de bibliotecas
- [ ] Remover dependências não usadas

### 7. Auth Failures
- [ ] Testar força bruta (rate limiting)
- [ ] Verificar invalidação de sessão
- [ ] Validar política de senhas
- [ ] Testar MFA quando aplicável

### 8. Data Integrity
- [ ] Verificar assinaturas de código
- [ ] Validar integridade de CI/CD
- [ ] Testar validação de dados
- [ ] Verificar proteção de backups

### 9. Logging Failures
- [ ] Verificar logging de eventos de segurança
- [ ] Testar monitoramento em tempo real
- [ ] Validar retenção de logs
- [ ] Verificar análise de logs

### 10. SSRF
- [ ] Testar URLs internas
- [ ] Validar whitelist de domínios
- [ ] Verificar bloqueio de IPs privados
- [ ] Testar network segmentation

---

## Dicas

1. **Seja sistemático**: Siga o checklist em ordem
2. **Documente tudo**: Screenshots, logs, payloads
3. **Priorize**: Foque primeiro nas vulnerabilidades críticas
4. **Adapte**: Ajuste checklist para contexto específico
5. **Atualize**: Revise checklist regularmente

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Aplicar checklist em projetos reais
- Criar checklists customizados por projeto
- Integrar testes de segurança no processo de QA
- Aula 1.3: Shift-Left Security

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Todos os exercícios anteriores (1.2.1 a 1.2.4)
