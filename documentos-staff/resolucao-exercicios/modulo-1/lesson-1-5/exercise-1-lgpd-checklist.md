---
exercise_id: lesson-1-5-exercise-1-lgpd-checklist
title: "Exercício 1.5.1: Checklist LGPD para Projeto"
lesson_id: lesson-1-5
module: module-1
difficulty: "Básico"
last_updated: 2025-01-15
---

# Exercício 1.5.1: Checklist LGPD para Projeto

## 📋 Enunciado Completo

Este exercício tem como objetivo criar um **checklist completo de compliance LGPD** para um projeto real, aplicando os princípios e requisitos da LGPD.

### Tarefa Principal

1. Entender aplicação e dados coletados
2. Criar checklist LGPD seguindo os 10 princípios
3. Identificar requisitos técnicos necessários
4. Validar conformidade com LGPD

---

## ✅ Soluções Detalhadas

### Parte 1: Entender a Aplicação

**Aplicação**: Plataforma de E-learning

**Funcionalidades:**
- Cadastro de usuários (nome, email, CPF, data de nascimento)
- Cursos online
- Certificados digitais
- Área do aluno com dados pessoais
- Integração com pagamentos

**Dados Coletados:**
- **Dados pessoais**: nome, email, CPF, telefone
- **Dados sensíveis**: nenhum inicialmente (mas pode coletar dados de menores)
- **Dados de navegação**: cookies, logs

**Validação Técnica:**
- ✅ Aplicação identificada
- ✅ Funcionalidades listadas
- ✅ Dados coletados categorizados (pessoais, sensíveis, navegação)

---

### Parte 2: Criar Checklist LGPD

**Solução Esperada - Checklist LGPD:**

```markdown
# Checklist LGPD - Plataforma de E-learning

## 1. Princípio da Finalidade
- [ ] Finalidade do tratamento está clara? (cadastro, cursos, certificados)
- [ ] Dados são usados apenas para finalidade declarada?
- [ ] Não há uso secundário não autorizado?
- [ ] Política de privacidade descreve finalidade claramente?

**Validação**: Revisar política de privacidade, verificar que dados não são usados para outras finalidades

**Evidências Necessárias**:
- Política de privacidade acessível
- Consentimento específico por finalidade
- Logs de uso de dados

---

## 2. Princípio da Adequação
- [ ] Dados coletados são adequados à finalidade? (CPF necessário para certificados?)
- [ ] Não há coleta de dados desnecessários? (CPF pode não ser necessário)
- [ ] Dados são relevantes? (data de nascimento necessária?)

**Validação**: Revisar campos de cadastro, verificar que todos os campos são necessários

**Evidências Necessárias**:
- Justificativa para cada dado coletado
- Revisão de campos de cadastro
- Documentação de adequação

---

## 3. Princípio da Necessidade
- [ ] Apenas dados necessários são coletados? (mínimo de dados)
- [ ] Dados mínimos são solicitados? (nome, email suficientes para cadastro básico)
- [ ] Não há coleta excessiva? (CPF pode ser solicitado apenas para certificados)

**Validação**: Revisar formulários, verificar que apenas dados necessários são coletados

**Evidências Necessárias**:
- Revisão de formulários
- Justificativa de necessidade
- Política de dados mínimos

---

## 4. Princípio da Transparência
- [ ] Política de privacidade está acessível? (link visível, fácil de encontrar)
- [ ] Usuário é informado sobre uso de dados? (antes de coletar)
- [ ] Termos são claros e compreensíveis? (linguagem simples)
- [ ] Usuário entende quais dados são coletados e por quê?

**Validação**: Revisar política de privacidade, verificar acessibilidade e clareza

**Evidências Necessárias**:
- Política de privacidade acessível
- Texto claro e compreensível
- Consentimento informado

---

## 5. Princípio da Segurança
- [ ] Dados estão protegidos adequadamente? (criptografia, controle de acesso)
- [ ] Criptografia está implementada? (HTTPS, hash de senhas, dados sensíveis)
- [ ] Controle de acesso está ativo? (usuários só acessam seus próprios dados)
- [ ] Logs de auditoria estão sendo registrados? (acesso a dados pessoais)

**Validação**: Verificar criptografia em trânsito e repouso, testar controle de acesso, verificar logs

**Evidências Necessárias**:
- Certificado SSL/TLS válido
- Hash de senhas no banco (bcrypt)
- Testes de controle de acesso
- Logs de auditoria

---

## 6. Princípio da Prevenção
- [ ] Medidas preventivas estão implementadas? (validação de entrada, prepared statements)
- [ ] Testes de segurança são realizados? (SQL Injection, Broken Access Control)
- [ ] Vulnerabilidades são corrigidas? (processo de correção definido)

**Validação**: Executar testes de segurança, verificar que vulnerabilidades são corrigidas

**Evidências Necessárias**:
- Resultados de testes de segurança
- Processo de correção de vulnerabilidades
- Histórico de correções

---

## 7. Princípio da Não Discriminação
- [ ] Dados não são usados para discriminar? (não usar para discriminação)
- [ ] Algoritmos são justos? (se usar algoritmos, não discriminatórios)
- [ ] Decisões automatizadas são transparentes? (se usar, usuário informado)

**Validação**: Revisar uso de dados, verificar que não há discriminação

**Evidências Necessárias**:
- Política de não discriminação
- Revisão de algoritmos (se aplicável)
- Transparência em decisões automatizadas

---

## 8. Princípio da Responsabilização
- [ ] Controles estão documentados? (políticas, procedimentos)
- [ ] Evidências de compliance existem? (logs, testes, validações)
- [ ] Responsáveis estão definidos? (DPO, responsáveis por dados)

**Validação**: Revisar documentação, verificar que evidências existem

**Evidências Necessárias**:
- Documentação de controles
- Evidências de compliance (logs, testes)
- Designação de responsáveis (DPO)

---

## 9. Direitos do Titular
- [ ] Usuário pode acessar seus dados? (endpoint /api/user/data)
- [ ] Usuário pode corrigir seus dados? (endpoint /api/user/data PUT)
- [ ] Usuário pode excluir seus dados? (endpoint /api/user/data DELETE)
- [ ] Usuário pode revogar consentimento? (opção de revogar)
- [ ] Usuário pode solicitar portabilidade? (exportar dados)

**Validação**: Testar endpoints de direitos do titular, verificar que funcionam

**Evidências Necessárias**:
- Endpoints implementados e funcionando
- Testes de direitos do titular
- Documentação de como exercer direitos

---

## 10. Proteção de Dados de Menores
- [ ] Dados de menores têm proteção adicional? (consentimento de responsável, criptografia adicional)
- [ ] Consentimento de responsável é obtido? (para menores de 18 anos)
- [ ] Dados de menores são isolados? (acesso restrito)
- [ ] Política específica para menores? (linguagem apropriada)

**Validação**: Verificar proteção de dados de menores, testar consentimento de responsável

**Evidências Necessárias**:
- Política específica para menores
- Consentimento de responsável implementado
- Criptografia adicional para dados de menores
- Acesso restrito a dados de menores

---

## Resumo de Conformidade

### Conforme ✅
- [ ] 8+ princípios implementados corretamente
- [ ] Direitos do titular implementados
- [ ] Proteção de dados de menores (se aplicável)

### Parcialmente Conforme ⚠️
- [ ] Alguns princípios implementados parcialmente
- [ ] Necessita melhorias

### Não Conforme ❌
- [ ] Princípios não implementados
- [ ] Necessita correções urgentes

---

## Recomendações

### Prioridade P1 (Crítico - Corrigir Imediatamente)
- Implementar direitos do titular (acesso, correção, exclusão)
- Implementar proteção de dados de menores (se aplicável)
- Implementar controle de acesso adequado

### Prioridade P2 (Alta - Corrigir Este Sprint)
- Revisar política de privacidade (clareza, acessibilidade)
- Implementar logs de auditoria
- Revisar coleta de dados (minimizar dados coletados)

### Prioridade P3 (Média - Corrigir Próximo Sprint)
- Implementar portabilidade de dados
- Revisar uso secundário de dados
- Documentar controles implementados
```

**Validação Técnica:**
- ✅ Checklist completo cobrindo os 10 princípios LGPD
- ✅ Validação documentada para cada princípio
- ✅ Evidências necessárias listadas
- ✅ Recomendações priorizadas

---

### Parte 3: Requisitos Técnicos

**Solução Esperada:**

**Requisitos Técnicos Necessários:**

1. **Consentimento Explícito**
   - Implementar: Checkbox obrigatório no cadastro
   - Validação: Teste de cadastro sem consentimento (deve falhar)
   - Evidência: Screenshot de checkbox, logs de consentimento

2. **Revogação de Consentimento**
   - Implementar: Opção de revogar consentimento na área do usuário
   - Validação: Teste de revogação (dados devem ser removidos ou anonimizados)
   - Evidência: Endpoint de revogação funcionando

3. **Direito de Acesso**
   - Implementar: Endpoint `/api/user/data` (GET) retorna todos os dados do usuário
   - Validação: Teste de acesso (usuário pode acessar seus dados)
   - Evidência: Endpoint funcionando, formato JSON estruturado

4. **Direito de Correção**
   - Implementar: Endpoint `/api/user/data` (PUT) permite corrigir dados
   - Validação: Teste de correção (dados devem ser atualizados)
   - Evidência: Endpoint funcionando, logs de alteração

5. **Direito de Exclusão**
   - Implementar: Endpoint `/api/user/data` (DELETE) permite excluir dados
   - Validação: Teste de exclusão (dados devem ser removidos ou anonimizados)
   - Evidência: Endpoint funcionando, confirmação de exclusão

6. **Direito de Portabilidade**
   - Implementar: Endpoint `/api/user/data/export` retorna dados em formato estruturado (JSON)
   - Validação: Teste de exportação (dados devem ser exportáveis)
   - Evidência: Endpoint funcionando, formato adequado

7. **Criptografia de Dados**
   - Implementar: HTTPS obrigatório, hash de senhas (bcrypt), criptografia de dados sensíveis
   - Validação: Verificação de HTTPS, verificação de hash de senhas, verificação de criptografia
   - Evidência: Certificado SSL válido, hash de senhas no banco, dados criptografados

8. **Logs de Auditoria**
   - Implementar: Logging de todas as operações em dados pessoais (acesso, correção, exclusão)
   - Validação: Verificação de logs (todas as operações devem ser logadas)
   - Evidência: Logs de auditoria existentes e acessíveis

9. **Controle de Acesso**
   - Implementar: Validação de propriedade (usuários só acessam seus próprios dados)
   - Validação: Teste de IDOR (usuário não pode acessar dados de outros)
   - Evidência: Testes de controle de acesso passando

10. **Proteção de Dados de Menores**
    - Implementar: Consentimento de responsável, criptografia adicional, acesso restrito
    - Validação: Teste de consentimento de responsável, verificação de proteção adicional
    - Evidência: Consentimento de responsável funcionando, proteção adicional implementada

**Validação Técnica:**
- ✅ Requisitos técnicos identificados e detalhados
- ✅ Implementação descrita claramente
- ✅ Validação documentada para cada requisito
- ✅ Evidências necessárias listadas

---

### Parte 4: Validar Conformidade

**Solução Esperada:**

**Plano de Validação:**

```markdown
# Plano de Validação LGPD

## Casos de Teste por Princípio

### Princípio da Finalidade
- **Teste 1**: Verificar que política de privacidade descreve finalidade claramente
  - **Passos**: Acessar política de privacidade, ler descrição de finalidade
  - **Resultado Esperado**: Finalidade descrita claramente
  - **Evidência**: Screenshot da política

- **Teste 2**: Verificar que dados não são usados para outras finalidades
  - **Passos**: Verificar logs de uso de dados, validar que dados são usados apenas para finalidade declarada
  - **Resultado Esperado**: Dados usados apenas para finalidade declarada
  - **Evidência**: Logs de uso de dados

### Princípio da Transparência
- **Teste 1**: Verificar que política de privacidade está acessível
  - **Passos**: Acessar site, verificar que link para política está visível
  - **Resultado Esperado**: Link para política visível e acessível
  - **Evidência**: Screenshot da página com link

- **Teste 2**: Verificar que termos são claros e compreensíveis
  - **Passos**: Ler política de privacidade, verificar clareza
  - **Resultado Esperado**: Texto claro e compreensível (sem jargões desnecessários)
  - **Evidência**: Revisão de política

### Princípio da Segurança
- **Teste 1**: Verificar HTTPS obrigatório
  - **Passos**: Acessar site via HTTP, verificar redirecionamento para HTTPS
  - **Resultado Esperado**: Redirecionamento automático para HTTPS
  - **Evidência**: Screenshot de redirecionamento, certificado SSL válido

- **Teste 2**: Verificar hash de senhas no banco
  - **Passos**: Verificar banco de dados, confirmar que senhas estão em hash (bcrypt)
  - **Resultado Esperado**: Senhas em hash, nunca em texto plano
  - **Evidência**: Query no banco mostrando hash de senhas

- **Teste 3**: Verificar controle de acesso
  - **Passos**: Login como usuário 1, tentar acessar dados do usuário 2
  - **Resultado Esperado**: 403 Forbidden
  - **Evidência**: Teste de IDOR, log de acesso negado

### Direitos do Titular
- **Teste 1**: Verificar direito de acesso
  - **Passos**: Login como usuário, acessar `/api/user/data` (GET)
  - **Resultado Esperado**: Retorna todos os dados do usuário em formato JSON
  - **Evidência**: Resposta JSON com dados do usuário

- **Teste 2**: Verificar direito de correção
  - **Passos**: Login como usuário, corrigir dados via `/api/user/data` (PUT)
  - **Resultado Esperado**: Dados atualizados, confirmação retornada
  - **Evidência**: Dados atualizados no banco, log de alteração

- **Teste 3**: Verificar direito de exclusão
  - **Passos**: Login como usuário, excluir dados via `/api/user/data` (DELETE)
  - **Resultado Esperado**: Dados removidos ou anonimizados, confirmação retornada
  - **Evidência**: Dados removidos/anonimizados no banco, log de exclusão

- **Teste 4**: Verificar direito de portabilidade
  - **Passos**: Login como usuário, exportar dados via `/api/user/data/export`
  - **Resultado Esperado**: Dados exportados em formato estruturado (JSON)
  - **Evidência**: Arquivo JSON com dados exportados

### Proteção de Dados de Menores
- **Teste 1**: Verificar consentimento de responsável
  - **Passos**: Cadastrar menor de 18 anos, verificar que consentimento de responsável é requerido
  - **Resultado Esperado**: Consentimento de responsável obrigatório
  - **Evidência**: Formulário de consentimento de responsável

- **Teste 2**: Verificar proteção adicional
  - **Passos**: Verificar que dados de menores têm criptografia adicional e acesso restrito
  - **Resultado Esperado**: Criptografia adicional implementada, acesso restrito
  - **Evidência**: Configuração de criptografia, logs de acesso restrito
```

**Validação Técnica:**
- ✅ Casos de teste criados para cada princípio relevante
- ✅ Steps to reproduce detalhados
- ✅ Resultados esperados definidos
- ✅ Evidências necessárias listadas

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Checklist LGPD:**
- [ ] Checklist criado cobrindo pelo menos 8 dos 10 princípios LGPD
- [ ] Cada princípio tem pelo menos 2-3 itens de checklist
- [ ] Validação documentada para cada princípio

**Requisitos Técnicos:**
- [ ] Pelo menos 5-6 requisitos técnicos identificados
- [ ] Requisitos são específicos e implementáveis
- [ ] Validação documentada para cada requisito

**Plano de Validação:**
- [ ] Pelo menos 5-6 casos de teste criados
- [ ] Casos de teste cobrem princípios principais (Segurança, Direitos do Titular)

### ⭐ Importantes (Recomendados para Resposta Completa)

**Checklist LGPD:**
- [ ] Checklist criado cobrindo todos os 10 princípios LGPD
- [ ] Cada princípio tem 4-5 itens de checklist detalhados
- [ ] Evidências necessárias listadas para cada princípio
- [ ] Recomendações priorizadas

**Requisitos Técnicos:**
- [ ] 8-10 requisitos técnicos identificados
- [ ] Implementação detalhada para cada requisito
- [ ] Validação bem documentada
- [ ] Evidências necessárias listadas

**Plano de Validação:**
- [ ] Casos de teste criados para todos os princípios relevantes
- [ ] Steps to reproduce detalhados
- [ ] Resultados esperados bem definidos
- [ ] Evidências necessárias listadas

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Checklist:**
- [ ] Checklist customizado para aplicação específica
- [ ] Considera dados sensíveis e especiais (menores)
- [ ] Integra com outros frameworks de compliance (ISO 27001, SOC2)

**Requisitos Técnicos:**
- [ ] Requisitos técnicos implementados e testados
- [ ] Integração com sistemas existentes considerada
- [ ] Processo de atualização documentado

**Plano de Validação:**
- [ ] Testes automatizados criados
- [ ] Processo de validação contínua documentado
- [ ] Métricas de compliance definidas

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Aplicação LGPD**: Aluno consegue aplicar princípios LGPD em projeto?
2. **Checklist**: Aluno cria checklist completo e prático?
3. **Requisitos Técnicos**: Aluno identifica requisitos técnicos necessários?
4. **Validação**: Aluno cria plano de validação adequado?

### Erros Comuns

1. **Erro: Checklist genérico**
   - **Situação**: Aluno cria checklist genérico que aplica a qualquer aplicação
   - **Feedback**: "Boa criação de checklist! Para torná-lo mais útil, adapte para aplicação específica: em e-learning, considere 'dados de menores têm proteção adicional?', 'certificados digitais requerem CPF?' Adaptação aumenta efetividade."

2. **Erro: Requisitos técnicos vagos**
   - **Situação**: Aluno lista "implementar direitos do titular" sem detalhar como
   - **Feedback**: "Boa identificação de requisitos! Para torná-los implementáveis, detalhe: 'direito de acesso' pode incluir 'endpoint /api/user/data (GET) retorna todos os dados do usuário em formato JSON'. Isso torna requisito acionável."

### Dicas para Feedback

- ✅ **Reconheça**: Checklist completo, requisitos técnicos específicos, plano de validação adequado
- ❌ **Corrija**: Checklist genérico, requisitos vagos, plano de validação incompleto
- 💡 **Incentive**: Checklist customizado, requisitos implementados, validação automatizada

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Compliance Essencial**: LGPD é regulamentação obrigatória no Brasil
2. **Habilidade Essencial**: QA precisa saber validar compliance LGPD
3. **Prevenção**: Checklist previne não conformidades antes de auditorias
4. **Direitos do Titular**: Ensina implementação de direitos do titular

**Conexão com o Curso:**
- Aula 1.5: Compliance e Regulamentações (teoria) → Este exercício (prática de LGPD)
- Pré-requisito para: Exercícios avançados de compliance (1.5.2-1.5.5)
- Base para: Validação de compliance em projetos reais

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Checklist LGPD:**
"Checklist completo cobrindo todos os 10 princípios LGPD. Princípio da Finalidade: política clara, dados usados apenas para finalidade declarada, sem uso secundário. Princípio da Segurança: HTTPS obrigatório, hash de senhas, controle de acesso, logs de auditoria. Direitos do Titular: endpoints implementados (GET, PUT, DELETE, EXPORT). Proteção de Menores: consentimento de responsável, criptografia adicional."

**Requisitos Técnicos:**
"10 requisitos técnicos identificados: consentimento explícito (checkbox obrigatório), revogação de consentimento (opção na área do usuário), direito de acesso (/api/user/data GET), direito de correção (/api/user/data PUT), direito de exclusão (/api/user/data DELETE), direito de portabilidade (/api/user/data/export), criptografia (HTTPS, hash, dados sensíveis), logs de auditoria, controle de acesso (validação de propriedade), proteção de menores (consentimento responsável)."

**Plano de Validação:**
"Casos de teste criados para todos os princípios relevantes. Teste de HTTPS: redirecionamento automático verificado. Teste de hash: senhas em bcrypt no banco. Teste de direitos do titular: endpoints GET, PUT, DELETE, EXPORT funcionando. Teste de proteção de menores: consentimento de responsável requerido. Evidências coletadas: screenshots, logs, testes automatizados."

**Características da Resposta:**
- ✅ Checklist completo cobrindo todos os princípios
- ✅ Requisitos técnicos específicos e implementáveis
- ✅ Plano de validação completo com casos de teste
- ✅ Evidências documentadas

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
