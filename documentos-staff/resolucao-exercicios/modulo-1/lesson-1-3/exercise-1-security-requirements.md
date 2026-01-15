---
exercise_id: lesson-1-3-exercise-1-security-requirements
title: "Exercício 1.3.1: Criar Security Requirements"
lesson_id: lesson-1-3
module: module-1
difficulty: "Básico"
last_updated: 2025-01-15
---

# Exercício 1.3.1: Criar Security Requirements

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **criação de security requirements** através da **definição de requisitos de segurança** para funcionalidades específicas.

### Tarefa Principal

1. Identificar security requirements para funcionalidades específicas
2. Documentar requirements de forma clara e testável
3. Aplicar requisitos de compliance (LGPD, PCI-DSS)
4. Validar que requisitos são implementáveis e testáveis

---

## ✅ Soluções Detalhadas

### Parte 1: Análise de Funcionalidade - Sistema de Login

**Solução Esperada:**

#### Security Requirement SR-001: Autenticação Forte

**Funcionalidade**: Sistema de Login

**Descrição**: Sistema deve implementar autenticação forte para prevenir acesso não autorizado.

**Criticidade**: Alta

**Requisitos Específicos:**
- Senhas devem ter mínimo de 12 caracteres
- Senhas devem conter: maiúsculas, minúsculas, números e caracteres especiais
- MFA obrigatório para operações sensíveis (opcional para login básico)
- Rate limiting: máximo 5 tentativas de login por minuto por IP
- Sessões devem expirar após 30 minutos de inatividade
- Senhas devem ser armazenadas com hash bcrypt (nunca texto plano)
- Senhas não devem ser reutilizáveis (histórico de últimas 5 senhas)

**Compliance**: LGPD, PCI-DSS (se aplicável)

**Validação:**
- Teste de política de senhas (tentar criar senha com menos de 12 caracteres → deve falhar)
- Teste de rate limiting (tentar login 6 vezes em 1 minuto → deve bloquear)
- Teste de expiração de sessão (aguardar 30 minutos → sessão deve expirar)
- Verificação de hash de senhas no banco (senhas não devem estar em texto plano)
- Teste de MFA quando aplicável (validar que MFA é obrigatório para operações sensíveis)

**Validação Técnica:**
- ✅ Requisitos são específicos e mensuráveis
- ✅ Requisitos são testáveis (pode criar testes para validar)
- ✅ Compliance considerado (LGPD, PCI-DSS)
- ✅ Criticidade apropriada (Alta para login)

---

#### Security Requirement SR-002: Gestão de Sessão Segura

**Funcionalidade**: Sistema de Login

**Descrição**: Sistema deve implementar gestão de sessão segura para prevenir acesso não autorizado.

**Criticidade**: Alta

**Requisitos Específicos:**
- Tokens de sessão devem ser aleatórios e não previsíveis
- Tokens devem ser invalidades no logout
- Tokens devem ser invalidades após mudança de senha
- Sessões devem expirar após 30 minutos de inatividade
- Sessões devem expirar após 24 horas de uso
- Tokens devem ser transmitidos via HTTPS apenas
- Sessões devem ser únicas por dispositivo

**Compliance**: LGPD

**Validação:**
- Teste de invalidação no logout (logout → token deve ser inválido)
- Teste de invalidação após mudança de senha (mudança de senha → todas as sessões devem ser invalidades)
- Teste de expiração por inatividade (aguardar 30 minutos → sessão deve expirar)
- Verificação de HTTPS obrigatório (tentar HTTP → deve redirecionar para HTTPS)

**Validação Técnica:**
- ✅ Requisitos específicos e implementáveis
- ✅ Considera cenários de invalidação
- ✅ Considera compliance (LGPD)

---

### Parte 1: Análise de Funcionalidade - Transferência Bancária

**Solução Esperada:**

#### Security Requirement SR-003: Validação de Propriedade

**Funcionalidade**: Transferência Bancária

**Contexto**: Aplicação Financeira (Fintech)

**Descrição**: Sistema deve validar que usuário só pode transferir de suas próprias contas.

**Criticidade**: Crítica

**Requisitos Específicos:**
- Validar que conta origem pertence ao usuário autenticado
- Validar que conta destino existe e está ativa
- Validar limite de transferência por dia (ex: R$ 10.000)
- Validar limite de transferência por transação (ex: R$ 5.000)
- MFA obrigatório para transferências acima de R$ 1.000
- Logs de auditoria para todas as transferências (origem, destino, valor, data/hora, IP)

**Compliance**: PCI-DSS, LGPD

**Validação:**
- Teste de validação de propriedade (tentar transferir de conta de outro usuário → deve retornar 403)
- Teste de limites (tentar transferir acima do limite → deve falhar)
- Teste de MFA (transferência acima de R$ 1.000 sem MFA → deve requerer MFA)
- Verificação de logs (todas as transferências devem ser logadas)

**Validação Técnica:**
- ✅ Considera contexto financeiro específico
- ✅ Inclui requisitos de auditoria
- ✅ Compliance PCI-DSS considerado
- ✅ Requisitos testáveis

---

#### Security Requirement SR-004: Integridade de Transação

**Funcionalidade**: Transferência Bancária

**Contexto**: Aplicação Financeira (Fintech)

**Descrição**: Sistema deve garantir integridade de transações para prevenir fraudes.

**Criticidade**: Crítica

**Requisitos Específicos:**
- Transações devem ser atômicas (all-or-nothing)
- Transações devem ter nonce único para prevenir replay attacks
- Transações devem ser validadas em múltiplas camadas (cliente, servidor, banco)
- Transações devem ser assinadas digitalmente
- Histórico completo de transações deve ser mantido (auditoria)

**Compliance**: PCI-DSS

**Validação:**
- Teste de atomicidade (falha no meio → transação deve ser revertida)
- Teste de replay attack (repetir transação com mesmo nonce → deve falhar)
- Verificação de assinatura digital (transações devem ser assinadas)

**Validação Técnica:**
- ✅ Considera prevenção de fraudes
- ✅ Inclui mecanismos técnicos (nonce, assinatura digital)
- ✅ Testável e implementável

---

### Parte 1: Análise de Funcionalidade - Área do Aluno

**Solução Esperada:**

#### Security Requirement SR-005: Isolamento de Dados

**Funcionalidade**: Área do Aluno

**Contexto**: Plataforma Educacional (EdTech)

**Descrição**: Sistema deve garantir isolamento de dados entre alunos para proteger privacidade.

**Criticidade**: Alta

**Requisitos Específicos:**
- Alunos não podem acessar dados de outros alunos
- Alunos só podem acessar dados de suas próprias turmas
- Professores só podem acessar dados de suas turmas
- Logs de acesso devem ser mantidos (quem acessou, quando, o quê)
- Dados de menores devem ter proteção adicional (criptografia adicional, acesso restrito)

**Compliance**: LGPD (especialmente proteção de dados de menores)

**Validação:**
- Teste de isolamento (aluno tenta acessar dados de outro aluno → deve retornar 403)
- Teste de isolamento por turma (aluno tenta acessar dados de outra turma → deve retornar 403)
- Verificação de logs (todos os acessos devem ser logados)
- Verificação de proteção adicional para menores (criptografia, acesso restrito)

**Validação Técnica:**
- ✅ Considera contexto educacional
- ✅ LGPD especialmente considerado (dados de menores)
- ✅ Requisitos específicos e testáveis

---

### Parte 1: Análise de Funcionalidade - Checkout de Ecommerce

**Solução Esperada:**

#### Security Requirement SR-006: Proteção de Dados de Pagamento

**Funcionalidade**: Checkout de Ecommerce

**Contexto**: Ecommerce

**Descrição**: Sistema deve proteger dados de cartão de crédito conforme PCI-DSS.

**Criticidade**: Crítica

**Requisitos Específicos:**
- Dados de cartão não devem ser armazenados em texto plano
- Dados de cartão devem ser tokenizados (usar token de gateway de pagamento)
- Transações devem ser feitas via gateway de pagamento confiável (não diretamente no sistema)
- HTTPS obrigatório em todo o fluxo de checkout
- Logs não devem conter dados de cartão (apenas últimos 4 dígitos para identificação)
- Validação de CVV não deve ser armazenada após transação

**Compliance**: PCI-DSS

**Validação:**
- Verificação de tokenização (dados de cartão não devem estar no banco)
- Teste de HTTPS obrigatório (tentar HTTP → deve redirecionar)
- Verificação de logs (logs não devem conter dados de cartão completos)
- Teste de validação de CVV (CVV não deve ser armazenado)

**Validação Técnica:**
- ✅ PCI-DSS totalmente considerado
- ✅ Requisitos específicos e implementáveis
- ✅ Testável e validável

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Identificação de Requirements:**
- [ ] Identifica pelo menos 3-4 security requirements para funcionalidade escolhida
- [ ] Requirements são específicos e mensuráveis (não vagos)
- [ ] Requirements consideram contexto da funcionalidade

**Documentação:**
- [ ] Requirements documentados usando template padronizado
- [ ] Criticidade definida (Alta/Média/Baixa)
- [ ] Compliance considerado quando aplicável (LGPD, PCI-DSS)

**Validação:**
- [ ] Requirements são testáveis (pode criar testes para validar)
- [ ] Como validar cada requirement é documentado
- [ ] Requirements são implementáveis (tecnologicamente viáveis)

### ⭐ Importantes (Recomendados para Resposta Completa)

**Completude:**
- [ ] Cria 5+ security requirements para funcionalidade escolhida
- [ ] Requirements cobrem diferentes aspectos (autenticação, autorização, dados, compliance)
- [ ] Requirements priorizados por criticidade

**Qualidade:**
- [ ] Requirements são bem detalhados (requisitos específicos listados)
- [ ] Validação bem documentada (como testar cada requirement)
- [ ] Compliance apropriadamente considerado

**Contexto:**
- [ ] Requirements adaptados para contexto específico (Financeiro, Educacional, Ecommerce)
- [ ] Considera necessidades específicas do setor
- [ ] Requirements refletem melhoras práticas do setor

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Aprofundamento:**
- [ ] Cria requirements para múltiplas funcionalidades (3-4)
- [ ] Requirements incluem métricas e SLAs (ex: tempo máximo de resposta)
- [ ] Requirements consideram arquitetura e design (não apenas implementação)

**Compliance:**
- [ ] Requirements detalhados para compliance específico (PCI-DSS, LGPD, SOC2)
- [ ] Considera auditoria e rastreabilidade
- [ ] Requirements incluem processos de conformidade

**Documentação:**
- [ ] Template customizado e profissional
- [ ] Rastreabilidade de requirements (link para requisitos funcionais)
- [ ] Versionamento e histórico de mudanças

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Identificação de Security Requirements**: Aluno consegue identificar requisitos de segurança necessários?
2. **Documentação**: Aluno documenta requirements de forma clara e testável?
3. **Compliance**: Aluno considera compliance apropriado (LGPD, PCI-DSS)?
4. **Validação**: Aluno garante que requirements são testáveis?

### Erros Comuns

1. **Erro: Requirements vagos**
   - **Situação**: Aluno cria requirement "Sistema deve ser seguro"
   - **Feedback**: "Boa tentativa! Para tornar requirement mais útil, seja específico: em vez de 'deve ser seguro', liste requisitos específicos como 'senhas devem ter mínimo de 12 caracteres' ou 'rate limiting de 5 tentativas por minuto'. Isso torna requirement testável."

2. **Erro: Não considerar compliance**
   - **Situação**: Aluno cria requirements para funcionalidade financeira mas não menciona PCI-DSS
   - **Feedback**: "Requirements criados! Lembre-se que funcionalidades financeiras precisam atender PCI-DSS. Inclua requirements específicos como 'dados de cartão devem ser tokenizados' e 'logs não devem conter dados de cartão completos'."

3. **Erro: Requirements não testáveis**
   - **Situação**: Aluno cria requirement sem documentar como validar
   - **Feedback**: "Requirement criado! Para torná-lo completo, documente como validar: liste testes que podem ser executados para verificar se requirement foi implementado. Ex: 'Teste: tentar criar senha com menos de 12 caracteres → deve falhar'."

### Dicas para Feedback

- ✅ **Reconheça**: Requirements específicos, compliance considerado, validação documentada
- ❌ **Corrija**: Requirements vagos, falta de compliance, validação ausente
- 💡 **Incentive**: Multiple functionalidades, métricas e SLAs, rastreabilidade

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Base do Shift-Left**: Security requirements são a base do Shift-Left Security
2. **Habilidade Essencial**: QA precisa saber identificar e documentar security requirements
3. **Prevenção**: Requirements corretos previnem vulnerabilidades antes do desenvolvimento
4. **Compliance**: Ensina a considerar compliance desde o início

**Conexão com o Curso:**
- Aula 1.3: Shift-Left Security (teoria) → Este exercício (prática de requirements)
- Pré-requisito para: Exercício 1.3.2 (Threat Modeling - usa requirements)
- Base para: Todo o processo de segurança desde o início

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Security Requirements Criados (Sistema de Login):**

**SR-001: Autenticação Forte**
- Senhas: mínimo 12 caracteres, complexidade obrigatória
- Rate limiting: 5 tentativas/minuto
- Sessões: expiração 30 minutos inatividade
- Senhas: hash bcrypt, nunca texto plano
- Compliance: LGPD, PCI-DSS
- Validação: Testes de política, rate limiting, hash

**SR-002: Gestão de Sessão Segura**
- Tokens aleatórios e não previsíveis
- Invalidação no logout e mudança de senha
- Expiração por inatividade e tempo total
- HTTPS obrigatório

**Características da Resposta:**
- ✅ Requirements específicos e mensuráveis
- ✅ Compliance considerado
- ✅ Validação bem documentada
- ✅ Múltiplos requirements cobrindo diferentes aspectos

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
