---
exercise_id: lesson-1-4-exercise-1-stride-basico
title: "Exercício 1.4.1: Aplicar STRIDE Básico"
lesson_id: lesson-1-4
module: module-1
difficulty: "Básico"
last_updated: 2025-01-15
---

# Exercício 1.4.1: Aplicar STRIDE Básico

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **aplicação de STRIDE** através da **identificação de ameaças** usando a metodologia STRIDE.

### Tarefa Principal

1. Entender aplicação simples
2. Aplicar STRIDE sistematicamente
3. Documentar ameaças encontradas
4. Priorizar ameaças básicas

---

## ✅ Soluções Detalhadas

### Parte 1: Entender a Aplicação

**Aplicação**: Sistema de Login e Perfil de Usuário

**Arquitetura:**
```
Cliente Web → API REST → Banco de Dados
```

**Funcionalidades:**
- Login de usuários
- Visualização de perfil próprio
- Atualização de perfil

**Componentes Identificados:**
- **Frontend** (Cliente Web): Interface do usuário
- **API REST**: Endpoints `/api/login`, `/api/users/<id>`
- **Banco de Dados**: Tabela `users`

**Validação Técnica:**
- ✅ Arquitetura simples identificada
- ✅ Componentes principais listados
- ✅ Funcionalidades básicas descritas

---

### Parte 2: Aplicar STRIDE - API de Login

**Solução Esperada:**

#### S - Spoofing (Falsificação)

**Ameaça**: Login sem credenciais válidas (força bruta, credenciais comprometidas)

**Impacto**: Alto (acesso não autorizado)

**Mitigação**:
- Autenticação forte (senhas complexas, MFA)
- Rate limiting (máximo 5 tentativas por minuto por IP)
- CAPTCHA após 3 tentativas
- Logging de tentativas de login

**Validação**:
- Teste de força bruta (múltiplas tentativas devem ser bloqueadas)
- Verificação de logs (tentativas devem ser logadas)

**Validação Técnica:**
- ✅ Ameaça identificada corretamente
- ✅ Impacto adequado (Alto)
- ✅ Mitigação específica e implementável
- ✅ Validação documentada

---

#### T - Tampering (Alteração)

**Ameaça**: Modificação de requisição de login (MITM, modificação de parâmetros)

**Impacto**: Crítico (bypass de autenticação)

**Mitigação**:
- HTTPS obrigatório (criptografia em trânsito)
- Validação no servidor (nunca confiar no cliente)
- Tokens CSRF para prevenir CSRF
- Assinatura digital de requisições (opcional)

**Validação**:
- Teste de modificação de requisição (deve ser rejeitada)
- Verificação de HTTPS obrigatório

**Validação Técnica:**
- ✅ Ameaça identificada corretamente
- ✅ Impacto adequado (Crítico)
- ✅ Mitigações técnicas específicas

---

#### R - Repudiation (Repúdio)

**Ameaça**: Usuário nega ter feito login ou ações realizadas

**Impacto**: Médio (dificulta auditoria)

**Mitigação**:
- Logging completo de todas as ações (login, logout, operações)
- Logs imutáveis (não podem ser modificados)
- Assinatura digital de logs
- Auditoria regular de logs

**Validação**:
- Verificação de logs (todas as ações devem ser logadas)
- Teste de imutabilidade de logs

**Validação Técnica:**
- ✅ Ameaça identificada corretamente
- ✅ Impacto adequado (Médio)
- ✅ Mitigações apropriadas

---

#### I - Information Disclosure (Divulgação de Informação)

**Ameaça**: Vazamento de credenciais em logs, mensagens de erro, ou tráfego

**Impacto**: Crítico (comprometimento de contas)

**Mitigação**:
- Nunca logar senhas em texto plano
- Mensagens de erro genéricas (não revelar se usuário existe)
- HTTPS obrigatório (criptografia em trânsito)
- Senhas em hash no banco (bcrypt, nunca texto plano)

**Validação**:
- Verificação de logs (senhas não devem estar em logs)
- Teste de mensagens de erro (genéricas)
- Verificação de hash de senhas no banco

**Validação Técnica:**
- ✅ Ameaça crítica identificada
- ✅ Mitigações cobrem múltiplas camadas

---

#### D - Denial of Service (Negação de Serviço)

**Ameaça**: Ataque de força bruta sobrecarregando servidor

**Impacto**: Alto (serviço indisponível)

**Mitigação**:
- Rate limiting (máximo 5 tentativas por minuto por IP)
- CAPTCHA após 3 tentativas
- Bloqueio temporário de conta após 10 tentativas
- Monitoramento de padrões anômalos

**Validação**:
- Teste de rate limiting (bloqueio após 5 tentativas)
- Teste de bloqueio de conta (bloqueio após 10 tentativas)

**Validação Técnica:**
- ✅ Ameaça identificada corretamente
- ✅ Mitigações escalonadas (rate limiting → CAPTCHA → bloqueio)

---

#### E - Elevation of Privilege (Elevação de Privilégio)

**Ameaça**: Bypass de autenticação sem credenciais válidas

**Impacto**: Crítico (acesso não autorizado)

**Mitigação**:
- Validação rigorosa de credenciais no servidor
- Uso de prepared statements (prevenir SQL Injection)
- Tokens de sessão seguros (aleatórios, não previsíveis)
- Expiração de sessões

**Validação**:
- Teste de bypass de autenticação (deve falhar)
- Verificação de tokens de sessão (aleatórios)

**Validação Técnica:**
- ✅ Ameaça crítica identificada
- ✅ Mitigações técnicas específicas

---

### Parte 2: Aplicar STRIDE - API de Perfil

**Solução Esperada:**

#### S - Spoofing

**Ameaça**: Spoofing de token de sessão (reutilização de token)

**Impacto**: Alto

**Mitigação**: Tokens únicos por sessão, invalidação no logout

#### T - Tampering

**Ameaça**: Modificação de dados de perfil sem autorização

**Impacto**: Alto

**Mitigação**: Validação de propriedade, validação no servidor

#### I - Information Disclosure

**Ameaça**: Vazamento de dados pessoais para usuários não autorizados

**Impacto**: Alto (violação LGPD)

**Mitigação**: Validação de acesso (IDOR prevention), isolamento de dados

**Validação Técnica:**
- ✅ STRIDE aplicado para componente de perfil
- ✅ Ameaças relevantes identificadas

---

### Parte 2: Aplicar STRIDE - Banco de Dados

**Solução Esperada:**

#### I - Information Disclosure

**Ameaça**: Acesso direto ao banco expõe dados

**Impacto**: Crítico

**Mitigação**:
- Controle de acesso ao banco (apenas aplicação)
- Criptografia de dados sensíveis
- Logs de acesso ao banco

#### T - Tampering

**Ameaça**: Modificação direta de dados no banco

**Impacto**: Crítico

**Mitigação**:
- Controle de acesso ao banco
- Logs de todas as modificações
- Backups regulares

#### D - Denial of Service

**Ameaça**: Sobrecarga do banco por queries maliciosas

**Impacto**: Alto

**Mitigação**:
- Rate limiting na API
- Query timeout
- Monitoramento de performance

**Validação Técnica:**
- ✅ STRIDE aplicado para banco de dados
- ✅ Ameaças específicas de banco consideradas

---

### Parte 3: Priorizar Ameaças

**Solução Esperada - Priorização:**

| Ameaça | Componente | Impacto | Prioridade |
|--------|------------|---------|------------|
| Bypass de Autenticação | API Login | Crítico | P1 - IMEDIATO |
| Vazamento de Credenciais | API Login | Crítico | P1 - IMEDIATO |
| Modificação de Requisição | API Login | Crítico | P1 - IMEDIATO |
| Acesso Direto ao Banco | Banco de Dados | Crítico | P1 - IMEDIATO |
| Força Bruta | API Login | Alto | P2 - Este Sprint |
| Vazamento de Dados | API Perfil | Alto | P2 - Este Sprint |
| Modificação de Perfil | API Perfil | Alto | P2 - Este Sprint |
| Repudiation | API Login | Médio | P3 - Próximo Sprint |

**Validação Técnica:**
- ✅ Priorização considera impacto
- ✅ Ameaças críticas priorizadas (P1)
- ✅ Justificativa clara para prioridades

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Aplicação STRIDE:**
- [ ] STRIDE aplicado para pelo menos 2 componentes (API Login, API Perfil, ou Banco)
- [ ] Pelo menos 4-5 categorias STRIDE aplicadas (S, T, R, I, D, E)
- [ ] Pelo menos 1 ameaça identificada por categoria aplicada

**Documentação:**
- [ ] Ameaças documentadas com descrição
- [ ] Impacto definido para cada ameaça

**Priorização:**
- [ ] Ameaças priorizadas (P1/P2/P3)

### ⭐ Importantes (Recomendados para Resposta Completa)

**Aplicação STRIDE:**
- [ ] STRIDE aplicado para todos os 3 componentes (API Login, API Perfil, Banco)
- [ ] Todas as 6 categorias STRIDE aplicadas (S, T, R, I, D, E)
- [ ] Múltiplas ameaças identificadas por categoria (2-3)

**Documentação:**
- [ ] Ameaças bem documentadas (descrição, impacto, mitigação, validação)
- [ ] Mitigações propostas para cada ameaça
- [ ] Validação documentada para cada mitigação

**Priorização:**
- [ ] Priorização justificada (por que cada prioridade)
- [ ] Ameaças críticas identificadas corretamente

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Aprofundamento:**
- [ ] Ameaças não óbvias identificadas
- [ ] Mitigações múltiplas por ameaça (defense in depth)
- [ ] Análise de risco detalhada

**Aplicação:**
- [ ] STRIDE aplicado em projeto real ou mais complexo
- [ ] Mitigações validadas com testes
- [ ] Processo de revisão documentado

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Aplicação STRIDE**: Aluno consegue aplicar STRIDE sistematicamente?
2. **Identificação de Ameaças**: Aluno identifica ameaças relevantes?
3. **Priorização**: Aluno prioriza ameaças adequadamente?

### Erros Comuns

1. **Erro: Não considerar todas as categorias**
   - **Situação**: Aluno aplica apenas S, T, I e ignora R, D, E
   - **Feedback**: "Boa aplicação de STRIDE! Lembre-se de considerar todas as 6 categorias: S, T, R, I, D, E. Mesmo que algumas categorias não tenham ameaças óbvias, é importante documentar que foram consideradas."

2. **Erro: Mitigações vagas**
   - **Situação**: Aluno propõe "usar autenticação forte" sem detalhar
   - **Feedback**: "Boa identificação da ameaça! Para tornar mitigação mais útil, seja específico: 'autenticação forte' pode incluir 'senhas com mínimo 12 caracteres, MFA obrigatório, rate limiting de 5 tentativas por minuto'. Isso torna mitigação implementável."

### Dicas para Feedback

- ✅ **Reconheça**: Aplicação sistemática de STRIDE, identificação correta de ameaças, mitigações adequadas
- ❌ **Corrija**: Aplicação incompleta de STRIDE, mitigações vagas, priorização incorreta
- 💡 **Incentive**: Ameaças não óbvias, múltiplas mitigações, análise de risco detalhada

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Base do Threat Modeling**: STRIDE é metodologia fundamental
2. **Habilidade Essencial**: QA precisa saber aplicar STRIDE
3. **Prevenção**: Identificar ameaças antes do desenvolvimento previne vulnerabilidades
4. **Sistemático**: Ensina processo sistemático de identificação de ameaças

**Conexão com o Curso:**
- Aula 1.4: Threat Modeling (teoria) → Este exercício (prática de STRIDE)
- Pré-requisito para: Exercícios avançados de threat modeling (1.4.2-1.4.5)
- Base para: Todo processo de threat modeling

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**STRIDE Aplicado - API de Login:**

**S - Spoofing:**
"Ameaça: Login sem credenciais válidas (força bruta). Impacto: Alto. Mitigação: Autenticação forte (senhas 12+ caracteres, MFA), rate limiting (5 tentativas/minuto), CAPTCHA após 3 tentativas, logging. Validação: Teste de força bruta bloqueado, verificação de logs."

**T - Tampering:**
"Ameaça: Modificação de requisição de login (MITM). Impacto: Crítico. Mitigação: HTTPS obrigatório, validação no servidor, tokens CSRF. Validação: Teste de modificação de requisição rejeitada."

**I - Information Disclosure:**
"Ameaça: Vazamento de credenciais em logs. Impacto: Crítico. Mitigação: Nunca logar senhas, mensagens de erro genéricas, HTTPS, senhas em hash. Validação: Verificação de logs sem senhas, teste de mensagens genéricas."

**Priorização:**
"Ameaças críticas (T, I, E) priorizadas como P1 - IMEDIATO. Ameaças altas (S, D) como P2 - Este Sprint. Ameaças médias (R) como P3 - Próximo Sprint."

**Características da Resposta:**
- ✅ STRIDE aplicado completamente (todas as 6 categorias)
- ✅ Ameaças bem documentadas (descrição, impacto, mitigação, validação)
- ✅ Mitigações específicas e implementáveis
- ✅ Priorização justificada

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
