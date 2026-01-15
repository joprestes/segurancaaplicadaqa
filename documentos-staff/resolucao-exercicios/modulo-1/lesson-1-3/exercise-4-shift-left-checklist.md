---
exercise_id: lesson-1-3-exercise-4-shift-left-checklist
title: "Exercício 1.3.4: Checklist Shift-Left Security"
lesson_id: lesson-1-3
module: module-1
difficulty: "Avançado"
last_updated: 2026-01-14
---

# Exercício 1.3.4: Checklist Shift-Left Security

## 📋 Enunciado Completo

Este exercício tem como objetivo criar um **checklist completo de Shift-Left Security** para uso em projetos reais, garantindo que segurança seja integrada em todas as fases do SDLC.

### Tarefa Principal

1. Criar checklist de Shift-Left Security por fase do SDLC
2. Adaptar checklist para diferentes contextos
3. Criar métricas de efetividade
4. Aplicar checklist em projeto

---

## ✅ Soluções Detalhadas

### Parte 1: Checklist por Fase do SDLC

**Solução Esperada:**

#### Fase de Requisitos

**Security Requirements:**
- [ ] Security requirements definidos junto com requisitos funcionais
- [ ] Requisitos de compliance incluídos (LGPD, PCI-DSS, SOC2)
- [ ] Requisitos são específicos e mensuráveis (não vagos)
- [ ] Requisitos são testáveis (pode criar testes)
- [ ] Requisitos priorizados por criticidade

**Participação de QA:**
- [ ] QA participa de reuniões de requisitos
- [ ] QA questiona requisitos de segurança ausentes
- [ ] QA valida que requisitos são testáveis
- [ ] QA cria casos de teste baseados em security requirements

**Documentação:**
- [ ] Security requirements documentados
- [ ] Template padronizado usado
- [ ] Requisitos revisados e aprovados
- [ ] Rastreabilidade mantida

**Validação Técnica:**
- ✅ Checklist cobre principais atividades de requisitos
- ✅ Participação de QA considerada
- ✅ Compliance incluído

---

#### Fase de Design

**Threat Modeling:**
- [ ] Threat modeling realizado para funcionalidades críticas
- [ ] STRIDE aplicado sistematicamente
- [ ] Ameaças documentadas com descrição e impacto
- [ ] Mitigações propostas para cada ameaça
- [ ] Ameaças priorizadas por risco

**Arquitetura de Segurança:**
- [ ] Arquitetura de segurança definida
- [ ] Controles de segurança no design
- [ ] Defense in depth considerado
- [ ] Princípio de menor privilégio aplicado

**Participação de QA:**
- [ ] QA participa de sessões de threat modeling
- [ ] QA valida que ameaças têm mitigações
- [ ] QA cria testes baseados em ameaças identificadas

**Validação Técnica:**
- ✅ Checklist cobre threat modeling e arquitetura
- ✅ Participação de QA considerada

---

#### Fase de Desenvolvimento

**Secure Coding:**
- [ ] Code reviews de segurança realizados
- [ ] Secure coding practices seguidas (OWASP Top 10)
- [ ] Bibliotecas seguras usadas (sem vulnerabilidades conhecidas)
- [ ] Dependências atualizadas (patch management)
- [ ] Secrets não hardcoded (variáveis de ambiente)

**Code Review de Segurança:**
- [ ] Code reviews focados em segurança realizados
- [ ] Vulnerabilidades conhecidas verificadas (SQL Injection, XSS, etc.)
- [ ] Validação de entrada verificada
- [ ] Controles de acesso verificados
- [ ] Criptografia verificada quando aplicável

**Participação de QA:**
- [ ] QA realiza code reviews focados em segurança
- [ ] QA verifica compliance com security requirements
- [ ] QA valida testes de segurança incluídos

**Validação Técnica:**
- ✅ Checklist cobre secure coding e code review
- ✅ Participação de QA considerada

---

#### Fase de Testes

**Security Testing:**
- [ ] Testes de segurança incluídos no plano de testes
- [ ] Testes automatizados de segurança criados
- [ ] Testes manuais de segurança executados
- [ ] OWASP Top 10 testado
- [ ] Security requirements validados

**Validação de Vulnerabilidades:**
- [ ] Vulnerabilidades encontradas documentadas
- [ ] Vulnerabilidades priorizadas por risco
- [ ] Processo de correção definido
- [ ] Testes de regressão criados

**Participação de QA:**
- [ ] QA executa testes de segurança
- [ ] QA documenta vulnerabilidades encontradas
- [ ] QA valida correções de vulnerabilidades

**Validação Técnica:**
- ✅ Checklist cobre testes de segurança
- ✅ Validação de vulnerabilidades considerada

---

#### Fase de Produção

**Security Monitoring:**
- [ ] Monitoramento de segurança configurado
- [ ] Logs de segurança configurados (login, acesso, operações)
- [ ] Alertas de segurança configurados (tentativas de força bruta, acesso não autorizado)
- [ ] Resposta a incidentes definida

**Observabilidade:**
- [ ] Logs centralizados (SIEM)
- [ ] Métricas de segurança coletadas
- [ ] Dashboard de segurança criado
- [ ] Análise de tendências realizada

**Participação de QA:**
- [ ] QA valida monitoramento de segurança
- [ ] QA verifica logs de segurança
- [ ] QA participa de resposta a incidentes

**Validação Técnica:**
- ✅ Checklist cobre monitoramento e observabilidade
- ✅ Participação de QA considerada

---

### Parte 2: Adaptar por Contexto

**Solução Esperada - Checklist Financeiro:**

```markdown
## Checklist Financeiro - Shift-Left Security

### Fase de Requisitos
- [ ] Requisitos PCI-DSS incluídos
- [ ] Requisitos de Open Banking incluídos (se aplicável)
- [ ] Requisitos de auditoria incluídos
- [ ] Requisitos de prevenção de fraude incluídos

### Fase de Design
- [ ] Threat modeling para transferências bancárias
- [ ] Arquitetura de segurança para dados de cartão
- [ ] Controles de isolamento de contas
- [ ] Validação de integridade de transações

### Fase de Desenvolvimento
- [ ] Code review focando em PCI-DSS
- [ ] Validação de proteção de dados de cartão
- [ ] Secure coding para operações financeiras
- [ ] Bibliotecas de pagamento seguras

### Fase de Testes
- [ ] Testes de isolamento de contas
- [ ] Testes de prevenção de fraude
- [ ] Testes de compliance PCI-DSS
- [ ] Testes de integridade de transações

### Fase de Produção
- [ ] Monitoramento de transações suspeitas
- [ ] Logs de auditoria de todas as transações
- [ ] Alertas de fraude configurados
- [ ] Resposta a incidentes financeiros
```

**Validação Técnica:**
- ✅ Adaptado para contexto financeiro
- ✅ PCI-DSS considerado em todas as fases
- ✅ Prevenção de fraude incluída

---

### Parte 3: Criar Métricas

**Solução Esperada:**

**Métricas de Shift-Left Security:**
- % de security requirements cobertos por testes
- Número de vulnerabilidades encontradas por fase (requisitos, design, desenvolvimento, testes)
- Tempo médio de correção de vulnerabilidades por fase
- % de code reviews focados em segurança
- Número de ameaças identificadas em threat modeling
- % de mitigações implementadas
- Taxa de retest de vulnerabilidades
- Tempo médio de resposta a incidentes

**Dashboard de Métricas:**

| Métrica | Meta | Atual | Status |
|---------|------|-------|--------|
| % Security Requirements Cobertos | 90% | 75% | ⚠️ |
| Vulnerabilidades em Produção | 0 | 2 | ❌ |
| Tempo Médio de Correção | < 24h | 48h | ❌ |
| % Code Reviews de Segurança | 100% | 85% | ⚠️ |

**Validação Técnica:**
- ✅ Métricas relevantes definidas
- ✅ Metas estabelecidas
- ✅ Dashboard criado

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Checklist por Fase:**
- [ ] Checklist criado para pelo menos 3 fases do SDLC
- [ ] Cada fase tem pelo menos 5 itens de checklist
- [ ] Participação de QA considerada em cada fase

**Adaptação por Contexto:**
- [ ] Checklist adaptado para pelo menos 1 contexto (Financeiro/Educacional/Ecommerce)
- [ ] Adaptação específica para contexto (compliance, requisitos específicos)

**Métricas:**
- [ ] Pelo menos 3-4 métricas definidas
- [ ] Métricas relevantes para Shift-Left Security

### ⭐ Importantes (Recomendados para Resposta Completa)

**Checklist por Fase:**
- [ ] Checklist criado para todas as 5 fases do SDLC
- [ ] Cada fase tem 8-10 itens de checklist
- [ ] Checklists são específicos e acionáveis

**Adaptação por Contexto:**
- [ ] Checklist adaptado para 2-3 contextos diferentes
- [ ] Adaptação bem detalhada para cada contexto
- [ ] Compliance específico considerado

**Métricas:**
- [ ] 5-8 métricas definidas
- [ ] Metas estabelecidas para métricas
- [ ] Dashboard de métricas criado

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Checklist:**
- [ ] Checklist customizado para projeto específico
- [ ] Integração com ferramentas (Jira, GitHub)
- [ ] Processo de atualização do checklist documentado

**Métricas:**
- [ ] Métricas automatizadas (dashboards em tempo real)
- [ ] Análise de tendências (gráficos, relatórios)
- [ ] Processo de melhoria contínua baseado em métricas

**Aplicação:**
- [ ] Checklist aplicado em projeto real
- [ ] Resultados documentados
- [ ] Melhorias identificadas e implementadas

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Criação de Checklist**: Aluno consegue criar checklist completo por fase?
2. **Adaptação**: Aluno adapta checklist para diferentes contextos?
3. **Métricas**: Aluno define métricas relevantes?

### Erros Comuns

1. **Erro: Checklist genérico**
   - **Situação**: Aluno cria checklist muito genérico ("fazer testes de segurança")
   - **Feedback**: "Boa ideia criar checklist! Para torná-lo mais útil, seja específico: em vez de 'fazer testes de segurança', liste 'testar SQL Injection em todos os campos de entrada', 'testar IDOR em endpoints com ID', etc. Isso torna checklist acionável."

2. **Erro: Não considerar todas as fases**
   - **Situação**: Aluno cria checklist apenas para fase de testes
   - **Feedback**: "Checklist criado! Lembre-se que Shift-Left Security começa na fase de requisitos. Inclua checklist para todas as fases: requisitos, design, desenvolvimento, testes, produção. Isso garante segurança desde o início."

### Dicas para Feedback

- ✅ **Reconheça**: Checklist completo, adaptação por contexto, métricas relevantes
- ❌ **Corrija**: Checklist genérico, falta de adaptação, métricas irrelevantes
- 💡 **Incentive**: Checklist customizado, métricas automatizadas, aplicação prática

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Sistemático**: Checklist garante aplicação consistente de Shift-Left Security
2. **Adaptável**: Ensina a adaptar para diferentes contextos
3. **Mensurável**: Métricas permitem medir efetividade
4. **Prático**: Checklist pode ser usado em projetos reais

**Conexão com o Curso:**
- Aula 1.3: Shift-Left Security (teoria) → Este exercício (prática sistemática)
- Integra todos os conceitos da aula 1.3
- Base para: Aplicação em projetos reais

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Checklist Criado:**
"Checklist completo para todas as 5 fases do SDLC. Fase de Requisitos: security requirements definidos, compliance incluído, QA participa. Fase de Design: threat modeling realizado, arquitetura de segurança definida. Fase de Desenvolvimento: code reviews de segurança, secure coding practices. Fase de Testes: testes automatizados de segurança, OWASP Top 10 testado. Fase de Produção: monitoramento configurado, logs de segurança."

**Adaptação:**
"Checklist financeiro prioriza PCI-DSS em todas as fases: requisitos PCI-DSS incluídos, arquitetura para dados de cartão, code review focando em PCI-DSS, testes de compliance PCI-DSS, monitoramento de transações suspeitas."

**Métricas:**
"8 métricas definidas: % security requirements cobertos (meta: 90%), vulnerabilidades em produção (meta: 0), tempo médio de correção (meta: < 24h), % code reviews de segurança (meta: 100%). Dashboard criado com status atual vs meta."

**Características da Resposta:**
- ✅ Checklist completo para todas as fases
- ✅ Adaptação bem feita para contexto específico
- ✅ Métricas relevantes e dashboard criado
- ✅ Aplicável em projetos reais

---

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
