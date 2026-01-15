---
exercise_id: lesson-1-3-exercise-2-threat-modeling-early
title: "Exercício 1.3.2: Threat Modeling na Fase de Design"
lesson_id: lesson-1-3
module: module-1
difficulty: "Intermediário"
last_updated: 2025-01-15
---

# Exercício 1.3.2: Threat Modeling na Fase de Design

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **threat modeling** na fase de design através da **identificação de ameaças** antes do desenvolvimento.

### Tarefa Principal

1. Entender arquitetura da aplicação
2. Aplicar STRIDE para identificar ameaças
3. Documentar ameaças e mitigações
4. Priorizar ameaças por risco

---

## ✅ Soluções Detalhadas

### Parte 1: Entender a Aplicação

**Arquitetura:**
```
Cliente Web → API REST → Banco de Dados
```

**Funcionalidades:**
- Login de usuários
- Consulta de dados pessoais
- Atualização de perfil
- Upload de arquivos

**Componentes Identificados:**
- **Cliente Web** (Frontend): Interface do usuário
- **API REST**: Backend com endpoints `/api/login`, `/api/users/<id>`, `/api/upload`
- **Banco de Dados**: Armazena dados de usuários e arquivos

**Fluxos de Dados:**
1. Cliente → API: Credenciais de login
2. API → Banco: Validação de usuário
3. API → Cliente: Token de sessão
4. Cliente → API: Requisições autenticadas
5. API → Banco: Consulta/atualização de dados

**Pontos de Entrada:**
- `/api/login` (POST): Login de usuários
- `/api/users/<id>` (GET, PUT): Consulta/atualização de perfil
- `/api/upload` (POST): Upload de arquivos

**Ativos Sensíveis:**
- Credenciais de login (senhas)
- Dados pessoais de usuários
- Tokens de sessão
- Arquivos enviados

**Validação Técnica:**
- ✅ Componentes principais identificados
- ✅ Fluxos de dados mapeados
- ✅ Pontos de entrada identificados
- ✅ Ativos sensíveis listados

---

### Parte 2: Aplicar STRIDE - API de Login

**Solução Esperada:**

#### S - Spoofing (Falsificação)

**Ameaça T-001: Spoofing de Identidade**
- **Descrição**: Atacante se faz passar por usuário legítimo
- **Impacto**: Alto (acesso não autorizado)
- **Probabilidade**: Alta
- **Risco**: Alto

**Mitigação:**
- Autenticação forte (senhas complexas, MFA)
- Rate limiting para prevenir força bruta
- Logging de tentativas de login
- CAPTCHA após múltiplas tentativas

**Validação:**
- Teste de força bruta (múltiplas tentativas devem ser bloqueadas)
- Verificação de logs (tentativas devem ser logadas)

---

#### T - Tampering (Alteração)

**Ameaça T-002: Alteração de Requisição de Login**
- **Descrição**: Atacante modifica requisição para bypassar autenticação
- **Impacto**: Crítico (acesso não autorizado)
- **Probabilidade**: Média
- **Risco**: Alto

**Mitigação:**
- Validação no servidor (nunca confiar no cliente)
- HTTPS obrigatório (prevenir MITM)
- Tokens CSRF para prevenir CSRF
- Validação de entrada rigorosa

**Validação:**
- Teste de modificação de requisição (deve ser rejeitada)
- Verificação de HTTPS obrigatório

---

#### R - Repudiation (Repúdio)

**Ameaça T-003: Negação de Ações de Login**
- **Descrição**: Usuário nega ter feito login ou ações realizadas
- **Impacto**: Médio (dificulta auditoria)
- **Probabilidade**: Baixa
- **Risco**: Médio

**Mitigação:**
- Logging completo de todas as ações (login, logout, operações)
- Logs imutáveis (não podem ser modificados)
- Assinatura digital de logs
- Auditoria regular de logs

**Validação:**
- Verificação de logs (todas as ações devem ser logadas)
- Teste de imutabilidade de logs

---

#### I - Information Disclosure (Divulgação de Informação)

**Ameaça T-004: Vazamento de Credenciais**
- **Descrição**: Credenciais expostas em logs, mensagens de erro, ou tráfego
- **Impacto**: Crítico (comprometimento de contas)
- **Probabilidade**: Média
- **Risco**: Crítico

**Mitigação:**
- Nunca logar senhas em texto plano
- Mensagens de erro genéricas (não revelar se usuário existe)
- HTTPS obrigatório (criptografia em trânsito)
- Senhas em hash no banco (bcrypt, nunca texto plano)

**Validação:**
- Verificação de logs (senhas não devem estar em logs)
- Teste de mensagens de erro (genéricas)
- Verificação de hash de senhas no banco

---

#### D - Denial of Service (Negação de Serviço)

**Ameaça T-005: Ataque de Força Bruta**
- **Descrição**: Atacante tenta múltiplas senhas sobrecarregando servidor
- **Impacto**: Alto (serviço indisponível)
- **Probabilidade**: Alta
- **Risco**: Alto

**Mitigação:**
- Rate limiting (máximo 5 tentativas por minuto por IP)
- CAPTCHA após 3 tentativas
- Bloqueio temporário de conta após 10 tentativas
- Monitoramento de padrões anômalos

**Validação:**
- Teste de rate limiting (bloqueio após 5 tentativas)
- Teste de bloqueio de conta (bloqueio após 10 tentativas)

---

#### E - Elevation of Privilege (Elevação de Privilégio)

**Ameaça T-006: Bypass de Autenticação**
- **Descrição**: Atacante consegue fazer login sem credenciais válidas
- **Impacto**: Crítico (acesso não autorizado)
- **Probabilidade**: Baixa
- **Risco**: Crítico

**Mitigação:**
- Validação rigorosa de credenciais no servidor
- Uso de prepared statements (prevenir SQL Injection)
- Tokens de sessão seguros (aleatórios, não previsíveis)
- Expiração de sessões

**Validação:**
- Teste de bypass de autenticação (deve falhar)
- Verificação de tokens de sessão (aleatórios)

---

### Parte 2: Aplicar STRIDE - API de Perfil

**Solução Esperada:**

#### S - Spoofing

**Ameaça T-007: Spoofing de Token de Sessão**
- **Descrição**: Atacante reutiliza token de sessão de outro usuário
- **Impacto**: Crítico
- **Probabilidade**: Média
- **Risco**: Alto

**Mitigação:**
- Tokens únicos por sessão
- Invalidação de tokens no logout
- Expiração de tokens

---

#### T - Tampering

**Ameaça T-008: Modificação de Dados de Perfil**
- **Descrição**: Atacante modifica dados de outro usuário
- **Impacto**: Alto
- **Probabilidade**: Alta
- **Risco**: Alto

**Mitigação:**
- Validação de propriedade (usuário só atualiza seu próprio perfil)
- Validação de entrada no servidor
- Logs de modificações

---

#### I - Information Disclosure

**Ameaça T-009: Vazamento de Dados Pessoais**
- **Descrição**: Dados pessoais expostos para usuários não autorizados
- **Impacto**: Alto (violação LGPD)
- **Probabilidade**: Alta
- **Risco**: Alto

**Mitigação:**
- Validação de acesso (IDOR prevention)
- Isolamento de dados entre usuários
- Criptografia de dados sensíveis

---

### Parte 3: Priorizar Ameaças

**Solução Esperada - Matriz de Priorização:**

| Ameaça | Impacto | Probabilidade | Risco | Prioridade |
|--------|---------|---------------|-------|------------|
| T-004: Vazamento de Credenciais | Crítico | Média | Crítico | P1 - IMEDIATO |
| T-006: Bypass de Autenticação | Crítico | Baixa | Crítico | P1 - IMEDIATO |
| T-002: Alteração de Requisição | Crítico | Média | Alto | P1 - IMEDIATO |
| T-001: Spoofing de Identidade | Alto | Alta | Alto | P2 - Este Sprint |
| T-005: Força Bruta | Alto | Alta | Alto | P2 - Este Sprint |
| T-009: Vazamento de Dados | Alto | Alta | Alto | P2 - Este Sprint |
| T-008: Modificação de Perfil | Alto | Alta | Alto | P2 - Este Sprint |
| T-007: Spoofing de Token | Crítico | Média | Alto | P2 - Este Sprint |
| T-003: Repudiation | Médio | Baixa | Médio | P3 - Próximo Sprint |

**Validação Técnica:**
- ✅ Priorização considera impacto e probabilidade
- ✅ Ameaças críticas priorizadas (P1)
- ✅ Justificativa clara para cada prioridade

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Entendimento da Aplicação:**
- [ ] Componentes principais identificados
- [ ] Fluxos de dados mapeados
- [ ] Pontos de entrada identificados
- [ ] Ativos sensíveis listados

**Aplicação STRIDE:**
- [ ] STRIDE aplicado para pelo menos 2 componentes
- [ ] Pelo menos 3-4 categorias STRIDE aplicadas (S, T, R, I, D, E)
- [ ] Ameaças documentadas com descrição e impacto

**Priorização:**
- [ ] Ameaças priorizadas por risco
- [ ] Matriz de priorização criada

### ⭐ Importantes (Recomendados para Resposta Completa)

**Aplicação STRIDE:**
- [ ] STRIDE aplicado para todos os componentes principais
- [ ] Todas as categorias STRIDE aplicadas (S, T, R, I, D, E)
- [ ] Mitigações documentadas para cada ameaça
- [ ] Validação documentada para cada mitigação

**Priorização:**
- [ ] Priorização justificada (por que cada prioridade)
- [ ] Ameaças críticas identificadas corretamente

**Documentação:**
- [ ] Ameaças bem documentadas (descrição, impacto, mitigação)
- [ ] Template padronizado usado

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Aprofundamento:**
- [ ] Ameaças não óbvias identificadas
- [ ] Análise de risco detalhada (probabilidade, impacto)
- [ ] Múltiplas mitigações por ameaça (defense in depth)

**Aplicação:**
- [ ] Threat model aplicado em projeto real ou de exemplo
- [ ] Mitigações validadas com testes
- [ ] Processo de revisão documentado

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Threat Modeling**: Aluno consegue aplicar STRIDE sistematicamente?
2. **Identificação de Ameaças**: Aluno identifica ameaças relevantes?
3. **Priorização**: Aluno prioriza ameaças adequadamente?
4. **Mitigação**: Aluno propõe mitigações adequadas?

### Erros Comuns

1. **Erro: Não considerar todos os componentes**
   - **Situação**: Aluno aplica STRIDE apenas para API, não considera banco de dados
   - **Feedback**: "Boa aplicação de STRIDE na API! Lembre-se de aplicar para todos os componentes: cliente, API, banco de dados. Cada componente tem ameaças específicas."

2. **Erro: Mitigações vagas**
   - **Situação**: Aluno propõe "usar autenticação forte" sem detalhar
   - **Feedback**: "Boa identificação da ameaça! Para tornar mitigação mais útil, seja específico: 'autenticação forte' pode incluir 'senhas com mínimo 12 caracteres, MFA obrigatório, rate limiting de 5 tentativas por minuto'. Isso torna mitigação implementável."

### Dicas para Feedback

- ✅ **Reconheça**: Identificação correta de ameaças, aplicação sistemática de STRIDE, mitigações adequadas
- ❌ **Corrija**: Aplicação incompleta de STRIDE, mitigações vagas, priorização incorreta
- 💡 **Incentive**: Ameaças não óbvias, múltiplas mitigações, análise de risco detalhada

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Shift-Left Security**: Threat modeling na fase de design previne vulnerabilidades
2. **Habilidade Essencial**: QA precisa saber fazer threat modeling básico
3. **Prevenção**: Identificar ameaças antes do desenvolvimento é mais eficiente
4. **Priorização**: Ensina a priorizar riscos de segurança

**Conexão com o Curso:**
- Aula 1.3: Shift-Left Security (teoria) → Este exercício (prática de threat modeling)
- Pré-requisito para: Aula 1.4 (Threat Modeling aprofundado)
- Base para: Todo processo de segurança desde o design

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**STRIDE Aplicado - API de Login:**

**S - Spoofing:**
"Ameaça T-001: Spoofing de identidade - atacante se faz passar por usuário. Impacto: Alto. Mitigação: Autenticação forte (senhas 12+ caracteres, MFA), rate limiting (5 tentativas/minuto), CAPTCHA. Validação: Teste de força bruta bloqueado."

**T - Tampering:**
"Ameaça T-002: Alteração de requisição - atacante modifica requisição. Impacto: Crítico. Mitigação: Validação no servidor, HTTPS obrigatório, tokens CSRF. Validação: Teste de modificação de requisição rejeitada."

**Priorização:**
"Ameaças críticas (T-002, T-004, T-006) priorizadas como P1 - IMEDIATO. Ameaças altas (T-001, T-005) como P2 - Este Sprint. Justificativa: Impacto crítico requer correção imediata."

**Características da Resposta:**
- ✅ STRIDE aplicado completamente
- ✅ Ameaças bem documentadas
- ✅ Mitigações específicas e implementáveis
- ✅ Priorização justificada

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
