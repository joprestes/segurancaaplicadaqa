---
exercise_id: lesson-1-5-exercise-5-auditoria-qa
title: "Exercício 1.5.5: Auditoria QA - Preparação e Execução"
lesson_id: lesson-1-5
module: module-1
difficulty: "Avançado"
last_updated: 2026-01-14
---

# Exercício 1.5.5: Auditoria QA - Preparação e Execução

## 📋 Enunciado Completo

Este exercício tem como objetivo **preparar e executar uma auditoria de compliance** do ponto de vista do QA, incluindo coleta de evidências, documentação e resposta a não conformidades.

### Tarefa Principal

1. Preparar evidências para auditoria
2. Executar auditoria interna de compliance
3. Documentar não conformidades
4. Criar planos de ação corretiva
5. Responder a auditorias externas

---

## ✅ Soluções Detalhadas

### Parte 1: Preparar Evidências

**Solução Esperada - Template de Evidências:**

```markdown
# Evidências de Compliance - LGPD

## Requisito: Princípio da Segurança

### Evidências Documentais
- [ ] **Política de Segurança**: documento "politica-seguranca-v1.0.pdf"
  - **Localização**: Confluence /docs/politicas/seguranca
  - **Data**: 2026-01-10
  - **Versão**: 1.0
  - **Status**: ✅ Atualizado

- [ ] **Procedimento de Criptografia**: documento "procedimento-criptografia-v1.0.pdf"
  - **Localização**: Confluence /docs/procedimentos/criptografia
  - **Data**: 2026-01-10
  - **Versão**: 1.0
  - **Status**: ✅ Atualizado

### Evidências Técnicas
- [ ] **Screenshot: Certificado SSL**: "ssl-certificate-2026-01-14.png"
  - **Descrição**: Certificado SSL válido, TLS 1.2+, emitido por Let's Encrypt
  - **Localização**: Screenshots/ssl-certificate.png
  - **Data**: 2026-01-14
  - **Status**: ✅ Válido

- [ ] **Log: Hash de Senhas no Banco**: "hash-senhas-bcrypt-2026-01-14.log"
  - **Descrição**: Query no banco mostrando senhas em hash bcrypt (não texto plano)
  - **Localização**: Logs/hash-senhas.log
  - **Data**: 2026-01-14
  - **Status**: ✅ Confirmado

### Evidências de Teste
- [ ] **Teste: HTTPS Obrigatório**: "test-https-redirect-2026-01-14.json"
  - **Nome do Teste**: test_https_redirect
  - **Resultado**: ✅ Passou
  - **Data**: 2026-01-14
  - **Evidência**: Resultado do teste mostrando redirecionamento automático

- [ ] **Teste: Controle de Acesso**: "test-idor-prevention-2026-01-14.json"
  - **Nome do Teste**: test_idor_prevention
  - **Resultado**: ✅ Passou
  - **Data**: 2026-01-14
  - **Evidência**: Resultado do teste mostrando 403 Forbidden para acesso não autorizado

### Validação
- [ ] Evidências são suficientes? ✅ Sim
- [ ] Evidências são claras? ✅ Sim
- [ ] Evidências são acessíveis? ✅ Sim (Confluence, GitHub)
```

**Validação Técnica:**
- ✅ Template de evidências criado
- ✅ Evidências categorizadas (documentais, técnicas, teste)
- ✅ Localização e status documentados
- ✅ Validação de evidências incluída

---

### Parte 2: Executar Auditoria Interna

**Solução Esperada - Plano de Auditoria:**

```markdown
# Plano de Auditoria Interna - LGPD

## Informações Gerais
- **Aplicação**: Plataforma de E-learning
- **Data**: 2026-01-14
- **Auditor**: Equipe QA
- **Escopo**: Compliance LGPD (todos os 10 princípios)

## Cronograma de Auditoria

### Fase 1: Preparação (Dia 1)
- [ ] Revisar documentação de compliance (políticas, procedimentos)
- [ ] Preparar checklist de auditoria
- [ ] Coletar evidências existentes
- [ ] Preparar planilha de evidências

### Fase 2: Execução (Dias 2-3)
- [ ] Executar checklist de compliance
- [ ] Coletar evidências técnicas (screenshots, logs, testes)
- [ ] Validar controles implementados
- [ ] Documentar não conformidades encontradas

### Fase 3: Relatório (Dia 4)
- [ ] Consolidar evidências coletadas
- [ ] Criar relatório de auditoria
- [ ] Priorizar não conformidades
- [ ] Criar planos de ação corretiva

## Checklist de Auditoria

### Princípio da Segurança
- [ ] ✅ HTTPS obrigatório - Evidência: Certificado SSL válido
- [ ] ✅ Hash de senhas - Evidência: Query no banco mostrando bcrypt
- [ ] ✅ Controle de acesso - Evidência: Teste de IDOR passando
- [ ] ✅ Logs de auditoria - Evidência: Logs de acesso existentes

### Direitos do Titular
- [ ] ✅ Direito de acesso - Evidência: Endpoint /api/user/data (GET) funcionando
- [ ] ✅ Direito de correção - Evidência: Endpoint /api/user/data (PUT) funcionando
- [ ] ✅ Direito de exclusão - Evidência: Endpoint /api/user/data (DELETE) funcionando
- [ ] ⚠️ Direito de portabilidade - Evidência: Endpoint /api/user/data/export pendente

## Não Conformidades Encontradas

### NC-001: Direito de Portabilidade Não Implementado
- **Requisito**: LGPD - Direitos do Titular
- **Severidade**: Média
- **Descrição**: Endpoint de portabilidade de dados não está implementado
- **Evidência**: Teste de endpoint /api/user/data/export retorna 404
- **Prazo Correção**: 1 semana
- **Responsável**: Dev Backend
```

**Validação Técnica:**
- ✅ Plano de auditoria criado
- ✅ Cronograma definido
- ✅ Checklist de auditoria incluído
- ✅ Não conformidades documentadas

---

### Parte 3: Criar Planos de Ação Corretiva

**Solução Esperada:**

```markdown
# Planos de Ação Corretiva - LGPD

## Não Conformidade NC-001: Direito de Portabilidade Não Implementado

### Descrição
Endpoint de portabilidade de dados (/api/user/data/export) não está implementado.

### Requisito Afetado
LGPD - Direitos do Titular (direito de portabilidade)

### Impacto
Média (usuário não pode exportar seus dados)

### Plano de Correção

#### Passo 1: Implementar Endpoint
- **Ação**: Criar endpoint `/api/user/data/export` (GET)
- **Responsável**: Dev Backend
- **Prazo**: 2 dias
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

#### Passo 2: Implementar Exportação
- **Ação**: Implementar exportação de dados em formato estruturado (JSON)
- **Responsável**: Dev Backend
- **Prazo**: 1 dia
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

#### Passo 3: Testar Endpoint
- **Ação**: Criar testes automatizados para endpoint de exportação
- **Responsável**: QA
- **Prazo**: 1 dia
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

#### Passo 4: Validar Correção
- **Ação**: Executar testes e validar que endpoint funciona corretamente
- **Responsável**: QA
- **Prazo**: 0.5 dia
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

### Validação Final
- [ ] Endpoint implementado e funcionando
- [ ] Testes automatizados passando
- [ ] Endpoint documentado
- [ ] Evidência coletada (screenshot, teste)

### Prazo Total
3.5 dias

### Responsável Geral
Dev Backend + QA
```

**Validação Técnica:**
- ✅ Plano de ação corretiva criado
- ✅ Passos detalhados com prazos e responsáveis
- ✅ Validação final documentada
- ✅ Prazo total definido

---

### Parte 4: Responder a Auditorias Externas

**Solução Esperada - Processo de Resposta:**

```markdown
# Processo de Resposta a Auditorias Externas

## Fase 1: Preparação (Antes da Auditoria)

### Coletar Evidências
- [ ] Revisar todas as evidências existentes
- [ ] Organizar evidências por requisito (LGPD, PCI-DSS, SOC2)
- [ ] Validar que evidências são suficientes e claras
- [ ] Preparar apresentação de evidências

### Preparar Documentação
- [ ] Políticas e procedimentos atualizados e acessíveis
- [ ] Checklist de compliance revisado e atualizado
- [ ] Relatórios de testes de segurança atualizados
- [ ] Logs de auditoria organizados e acessíveis

### Preparar Equipe
- [ ] Designar responsáveis por cada área (Dev, QA, Security, Compliance)
- [ ] Treinar equipe sobre processo de auditoria
- [ ] Preparar respostas para perguntas comuns

## Fase 2: Durante a Auditoria

### Apresentar Evidências
- [ ] Apresentar evidências de forma organizada
- [ ] Explicar controles implementados
- [ ] Demonstrar que controles estão funcionando (testes, screenshots)

### Responder Perguntas
- [ ] Responder perguntas de forma clara e direta
- [ ] Fornecer evidências quando solicitado
- [ ] Documentar perguntas e respostas

### Documentar Observações
- [ ] Documentar observações do auditor
- [ ] Documentar não conformidades identificadas
- [ ] Documentar recomendações do auditor

## Fase 3: Após a Auditoria

### Revisar Relatório
- [ ] Revisar relatório de auditoria recebido
- [ ] Validar não conformidades identificadas
- [ ] Priorizar não conformidades

### Criar Planos de Ação
- [ ] Criar plano de ação corretiva para cada não conformidade
- [ ] Definir responsáveis e prazos
- [ ] Implementar correções

### Validação de Correções
- [ ] Validar que correções foram implementadas
- [ ] Coletar evidências de correções
- [ ] Responder ao auditor com evidências de correções
```

**Validação Técnica:**
- ✅ Processo de resposta criado
- ✅ Fases bem definidas (antes, durante, depois)
- ✅ Responsabilidades definidas
- ✅ Validação de correções incluída

---

### Parte 5: Criar Relatório de Auditoria

**Solução Esperada:**

```markdown
# Relatório de Auditoria Interna - LGPD

## Informações Gerais
- **Aplicação**: Plataforma de E-learning
- **Data da Auditoria**: 2026-01-14
- **Auditor**: Equipe QA
- **Escopo**: Compliance LGPD (todos os 10 princípios)
- **Metodologia**: Checklist de compliance + validação técnica

## Resumo Executivo

### Status Geral
- **Conformidade**: 90% (9 de 10 princípios conforme)
- **Não Conformidades**: 1 (princípio de Direitos do Titular - portabilidade)
- **Recomendações**: 2 (melhorias opcionais)

### Principais Descobertas
1. ✅ Princípio da Segurança: Conforme (HTTPS, hash de senhas, controle de acesso, logs)
2. ✅ Princípio da Finalidade: Conforme (política clara, dados usados apenas para finalidade declarada)
3. ⚠️ Direitos do Titular: Parcialmente Conforme (portabilidade não implementada)

## Detalhamento por Princípio

### Princípio da Segurança ✅ CONFORME
- **Controles Validados**: HTTPS obrigatório, hash de senhas (bcrypt), controle de acesso, logs de auditoria
- **Evidências**: Certificado SSL válido, query no banco mostrando hash, testes de controle de acesso passando, logs existentes
- **Status**: ✅ Conforme

### Direitos do Titular ⚠️ PARCIALMENTE CONFORME
- **Controles Validados**: Direito de acesso (✅), correção (✅), exclusão (✅), portabilidade (❌)
- **Evidências**: Endpoints GET, PUT, DELETE funcionando, endpoint EXPORT retorna 404
- **Status**: ⚠️ Parcialmente Conforme (portabilidade não implementada)

## Não Conformidades

### NC-001: Direito de Portabilidade Não Implementado
- **Requisito**: LGPD - Direitos do Titular
- **Severidade**: Média
- **Impacto**: Usuário não pode exportar seus dados
- **Plano de Correção**: Implementar endpoint /api/user/data/export (prazo: 3.5 dias)
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

## Recomendações

### Prioridade P1 (Alta - Implementar Este Sprint)
- Implementar direito de portabilidade (NC-001)

### Prioridade P2 (Média - Implementar Próximo Sprint)
- Melhorar documentação de políticas (clareza adicional)
- Implementar métricas de compliance (dashboards)

### Prioridade P3 (Baixa - Implementar Quando Possível)
- Implementar notificação automática de incidentes
- Melhorar processo de consentimento (UX)

## Próximos Passos
1. Implementar correções para não conformidades (prazo: 1 semana)
2. Validar que correções foram implementadas
3. Re-auditar princípio de Direitos do Titular após correções
4. Documentar melhorias implementadas
```

**Validação Técnica:**
- ✅ Relatório de auditoria criado
- ✅ Status geral documentado
- ✅ Não conformidades identificadas e priorizadas
- ✅ Recomendações incluídas
- ✅ Próximos passos definidos

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Preparação de Evidências:**
- [ ] Template de evidências criado
- [ ] Pelo menos 5-7 evidências coletadas (documentais, técnicas, teste)
- [ ] Evidências organizadas por requisito

**Execução de Auditoria:**
- [ ] Plano de auditoria criado (cronograma, checklist)
- [ ] Pelo menos 5-7 requisitos auditados
- [ ] Não conformidades documentadas (se houver)

**Planos de Ação:**
- [ ] Plano de ação corretiva criado para pelo menos 1 não conformidade
- [ ] Prazos e responsáveis definidos

### ⭐ Importantes (Recomendados para Resposta Completa)

**Preparação de Evidências:**
- [ ] Template completo de evidências criado
- [ ] 10+ evidências coletadas (documentais, técnicas, teste)
- [ ] Evidências validadas (suficientes, claras, acessíveis)

**Execução de Auditoria:**
- [ ] Plano de auditoria completo e detalhado
- [ ] Todos os requisitos relevantes auditados (10+ requisitos)
- [ ] Não conformidades bem documentadas (descrição, severidade, impacto)

**Planos de Ação:**
- [ ] Planos de ação corretiva criados para todas as não conformidades
- [ ] Planos detalhados (passos, prazos, responsáveis, validação)
- [ ] Prazos realistas definidos

**Processo de Resposta:**
- [ ] Processo de resposta a auditorias externas criado
- [ ] Fases bem definidas (antes, durante, depois)

**Relatório:**
- [ ] Relatório de auditoria completo criado
- [ ] Status geral documentado
- [ ] Recomendações incluídas

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Processo:**
- [ ] Processo completo de auditoria documentado
- [ ] Métricas de auditoria definidas (tempo de correção, taxa de não conformidades)
- [ ] Processo de validação contínua documentado

**Aplicação:**
- [ ] Auditoria executada em projeto real
- [ ] Evidências coletadas e validadas
- [ ] Correções implementadas e validadas

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Preparação de Evidências**: Aluno prepara evidências adequadamente?
2. **Execução de Auditoria**: Aluno executa auditoria sistematicamente?
3. **Planos de Ação**: Aluno cria planos de ação corretiva efetivos?
4. **Processo de Resposta**: Aluno entende processo de resposta a auditorias?

### Erros Comuns

1. **Erro: Evidências insuficientes**
   - **Situação**: Aluno lista evidências mas não valida se são suficientes
   - **Feedback**: "Boa lista de evidências! Para garantir que são suficientes, valide: 'evidências são suficientes? (todas as exigências cobertas)', 'evidências são claras? (fáceis de entender)', 'evidências são acessíveis? (localização documentada)'. Validação garante que evidências atendem auditorias."

2. **Erro: Planos de ação vagos**
   - **Situação**: Aluno cria plano "implementar endpoint" sem detalhar passos
   - **Feedback**: "Boa criação de plano! Para torná-lo acionável, detalhe passos: 'Passo 1: Criar endpoint /api/user/data/export (GET)', 'Passo 2: Implementar exportação em formato JSON', 'Passo 3: Criar testes automatizados'. Isso torna plano implementável."

### Dicas para Feedback

- ✅ **Reconheça**: Evidências bem organizadas, auditoria sistemática, planos de ação detalhados
- ❌ **Corrija**: Evidências insuficientes, planos vagos, processo incompleto
- 💡 **Incentive**: Processo completo, validação contínua, métricas de auditoria

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Prática Real**: Auditorias de compliance são processos formais que QA precisa saber executar
2. **Habilidade Essencial**: QA precisa saber preparar evidências e executar auditorias
3. **Prevenção**: Auditorias internas previnem não conformidades em auditorias externas
4. **Compliance**: Garante conformidade contínua com regulamentações

**Conexão com o Curso:**
- Aula 1.5: Compliance e Regulamentações (teoria) → Este exercício (prática de auditoria)
- Integra todos os exercícios anteriores de compliance (LGPD, PCI-DSS, SOC2)
- Base para: Execução de auditorias em projetos reais

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Evidências Preparadas:**
"15 evidências coletadas organizadas por requisito. Princípio da Segurança: Certificado SSL válido (screenshot), hash de senhas no banco (query), controle de acesso (testes passando), logs de auditoria (arquivos de log). Todas validadas: suficientes, claras, acessíveis."

**Auditoria Executada:**
"Auditoria executada: 10 princípios LGPD auditados usando checklist. 9 princípios conforme (90%), 1 não conformidade encontrada (direito de portabilidade não implementado). Evidências coletadas: screenshots, logs, testes. Não conformidade documentada: NC-001 - Direito de portabilidade, severidade média, prazo 1 semana."

**Plano de Ação:**
"Plano criado: Passo 1 - Criar endpoint /api/user/data/export (2 dias, Dev Backend). Passo 2 - Implementar exportação JSON (1 dia, Dev Backend). Passo 3 - Criar testes (1 dia, QA). Passo 4 - Validar correção (0.5 dia, QA). Prazo total: 3.5 dias. Validação final: endpoint funcionando, testes passando."

**Características da Resposta:**
- ✅ Evidências bem organizadas e validadas
- ✅ Auditoria sistemática executada
- ✅ Não conformidades bem documentadas
- ✅ Planos de ação detalhados e acionáveis
- ✅ Processo completo documentado

---

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
