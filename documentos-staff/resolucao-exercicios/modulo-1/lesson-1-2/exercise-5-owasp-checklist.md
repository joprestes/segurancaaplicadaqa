---
exercise_id: lesson-1-2-exercise-5-owasp-checklist
title: "Exercício 1.2.5: OWASP Top 10 Checklist Completo"
lesson_id: lesson-1-2
module: module-1
difficulty: "Avançado"
last_updated: 2026-01-14
---

# Exercício 1.2.5: OWASP Top 10 Checklist Completo

## 📋 Enunciado Completo

Este exercício tem como objetivo criar um **checklist completo de testes de segurança** baseado no OWASP Top 10 para uso em projetos reais.

### Tarefa Principal

1. Criar checklist de testes para todas as vulnerabilidades OWASP Top 10
2. Adaptar checklist para diferentes contextos (Financeiro, Educacional, Ecommerce)
3. Criar template de documentação de resultados
4. Aplicar checklist em aplicação de exemplo

---

## ✅ Soluções Detalhadas

### Parte 1: Criar Checklist Base

**Solução Esperada - Checklist OWASP Top 10:**

#### 1. Broken Access Control

**Testes Básicos:**
- [ ] Testar IDOR em todos os endpoints que recebem ID de recurso
- [ ] Validar que usuário não acessa recursos de outros (horizontal access control)
- [ ] Testar privilege escalation (usuário comum não acessa recursos admin)
- [ ] Verificar isolamento de dados entre usuários (contas, pedidos, perfis)
- [ ] Testar validação de propriedade em operações CRUD

**Testes Avançados:**
- [ ] Testar com diferentes tipos de IDs (numérico, UUID, string)
- [ ] Validar controles funcionam após mudança de role
- [ ] Verificar sessões invalidadas não permitem acesso
- [ ] Testar bypass de controles através de parâmetros HTTP

**Ferramentas Recomendadas:**
- Burp Suite (para interceptar e modificar requisições)
- OWASP ZAP (scanner automático)
- Postman (para testes manuais de endpoints)

**Criticidade por Setor:**
- **Financeiro**: Crítica (acesso a dados bancários)
- **Educacional**: Alta (dados de menores - LGPD)
- **Ecommerce**: Alta (dados de pedidos e pagamentos)

**Validação Técnica:**
- ✅ Checklist cobre principais cenários de Broken Access Control
- ✅ Inclui testes básicos e avançados
- ✅ Ferramentas recomendadas são relevantes
- ✅ Criticidade por setor considerada

---

#### 2. Cryptographic Failures

**Testes Básicos:**
- [ ] Verificar que senhas são armazenadas com hash (bcrypt, Argon2, nunca texto plano)
- [ ] Confirmar HTTPS obrigatório em produção
- [ ] Validar algoritmos de criptografia (evitar MD5, SHA1, usar AES-256, TLS 1.2+)
- [ ] Verificar gerenciamento de chaves (chaves não hardcoded, rotação de chaves)

**Testes Avançados:**
- [ ] Verificar criptografia em trânsito (HTTPS) e em repouso (banco de dados)
- [ ] Testar força de hash de senhas (verificar salt, rounds)
- [ ] Validar proteção de dados sensíveis (cartões, CPF, senhas)
- [ ] Verificar não exposição de chaves em logs ou código

**Ferramentas Recomendadas:**
- OWASP Dependency-Check (verificar bibliotecas vulneráveis)
- SSL Labs (testar configuração TLS/SSL)
- Semgrep (buscar hardcoded secrets)

**Criticidade por Setor:**
- **Financeiro**: Crítica (PCI-DSS, dados de cartão)
- **Educacional**: Alta (dados de menores - LGPD)
- **Ecommerce**: Crítica (dados de pagamento - PCI-DSS)

**Validação Técnica:**
- ✅ Checklist cobre criptografia em trânsito e repouso
- ✅ Inclui validação de algoritmos seguros
- ✅ Considera gerenciamento de chaves
- ✅ Ferramentas apropriadas recomendadas

---

#### 3. Injection

**Testes Básicos:**
- [ ] Testar SQL Injection em todos os campos de entrada
- [ ] Testar NoSQL Injection (se usar MongoDB)
- [ ] Testar Command Injection (execução de comandos do sistema)
- [ ] Validar uso de prepared statements ou ORM seguro
- [ ] Testar LDAP Injection (se aplicável)

**Testes Avançados:**
- [ ] Testar blind SQL Injection (quando erro não é visível)
- [ ] Validar sanitização de entrada em todas as camadas
- [ ] Testar injection em headers HTTP (User-Agent, Referer)
- [ ] Verificar validação de entrada no servidor (nunca apenas no cliente)

**Ferramentas Recomendadas:**
- SQLMap (para SQL Injection automatizado)
- Burp Suite (para testes manuais)
- OWASP ZAP (scanner automático)
- Semgrep (para encontrar código vulnerável)

**Criticidade por Setor:**
- **Financeiro**: Crítica (acesso a dados bancários)
- **Educacional**: Alta (acesso a dados de alunos)
- **Ecommerce**: Crítica (acesso a dados de clientes e pedidos)

**Validação Técnica:**
- ✅ Checklist cobre principais tipos de Injection
- ✅ Inclui validação de prevenção (prepared statements)
- ✅ Ferramentas especializadas recomendadas

---

#### 4. Insecure Design

**Testes Básicos:**
- [ ] Verificar rate limiting em endpoints críticos (login, transações)
- [ ] Testar validação de regras de negócio no servidor
- [ ] Validar isolamento de recursos entre usuários/organizações
- [ ] Verificar autenticação forte (MFA quando aplicável)
- [ ] Testar prevenção de race conditions

**Testes Avançados:**
- [ ] Validar arquitetura de segurança (defense in depth)
- [ ] Verificar fail-secure (sistema falha de forma segura)
- [ ] Testar prevenção de abuso de funcionalidades
- [ ] Validar princípio de menor privilégio

**Ferramentas Recomendadas:**
- Threat modeling (para identificar falhas de design)
- Code review (para validar arquitetura)
- Análise de requisitos de segurança

**Criticidade por Setor:**
- **Financeiro**: Crítica (design incorreto pode levar a fraudes)
- **Educacional**: Alta (design incorreto pode expor dados de menores)
- **Ecommerce**: Alta (design incorreto pode permitir fraudes)

**Validação Técnica:**
- ✅ Checklist foca em falhas de design, não apenas implementação
- ✅ Inclui validação de regras de negócio
- ✅ Considera arquitetura de segurança

---

#### 5. Security Misconfiguration

**Testes Básicos:**
- [ ] Verificar headers de segurança (CSP, HSTS, X-Frame-Options)
- [ ] Testar mensagens de erro (não expor informações sensíveis)
- [ ] Validar configurações padrão (senhas padrão, serviços desnecessários)
- [ ] Verificar versões de software e bibliotecas (atualizadas, sem CVE conhecidos)

**Testes Avançados:**
- [ ] Verificar configuração de CORS (apenas origens permitidas)
- [ ] Testar exposição de arquivos de configuração (.env, config.json)
- [ ] Validar configuração de logs (não expor dados sensíveis)
- [ ] Verificar hardening do servidor (firewall, permissões)

**Ferramentas Recomendadas:**
- OWASP ZAP (verificar headers de segurança)
- SSL Labs (testar configuração TLS)
- Nmap (verificar portas abertas)
- Snyk / OWASP Dependency-Check (verificar dependências vulneráveis)

**Criticidade por Setor:**
- **Financeiro**: Alta (configuração incorreta pode expor dados)
- **Educacional**: Média (configuração incorreta pode expor dados de menores)
- **Ecommerce**: Alta (configuração incorreta pode expor dados de clientes)

**Validação Técnica:**
- ✅ Checklist cobre configurações comuns vulneráveis
- ✅ Inclui verificação de headers de segurança
- ✅ Ferramentas adequadas recomendadas

---

#### 6. Vulnerable Components

**Testes Básicos:**
- [ ] Executar scanner de dependências (Snyk, OWASP Dependency-Check)
- [ ] Verificar atualizações disponíveis para todas as dependências
- [ ] Validar versões de bibliotecas (evitar versões com CVE conhecidos)
- [ ] Remover dependências não usadas

**Testes Avançados:**
- [ ] Validar processo de atualização de dependências (patch management)
- [ ] Verificar licenças de dependências (compliance)
- [ ] Testar impacto de vulnerabilidades conhecidas
- [ ] Validar fontes confiáveis de dependências (npm audit, pip check)

**Ferramentas Recomendadas:**
- Snyk (scanner de dependências)
- OWASP Dependency-Check (verificar vulnerabilidades)
- npm audit / pip check (verificar dependências)
- GitHub Dependabot (alertas de segurança)

**Criticidade por Setor:**
- **Financeiro**: Alta (componentes vulneráveis podem comprometer sistema)
- **Educacional**: Média (componentes vulneráveis podem expor dados)
- **Ecommerce**: Alta (componentes vulneráveis podem comprometer pagamentos)

**Validação Técnica:**
- ✅ Checklist cobre principais ferramentas de scanner
- ✅ Inclui processo de atualização
- ✅ Ferramentas especializadas recomendadas

---

#### 7. Authentication Failures

**Testes Básicos:**
- [ ] Testar força bruta (rate limiting deve bloquear após X tentativas)
- [ ] Verificar invalidação de sessão (logout, expiração, mudança de senha)
- [ ] Validar política de senhas (tamanho mínimo, complexidade)
- [ ] Testar MFA quando aplicável (obrigatório para operações sensíveis)

**Testes Avançados:**
- [ ] Testar recuperação de senha (não permitir enumeração de usuários)
- [ ] Verificar proteção contra credential stuffing
- [ ] Validar gestão de sessão (tokens seguros, invalidação adequada)
- [ ] Testar autenticação em múltiplos fatores (2FA, MFA)

**Ferramentas Recomendadas:**
- Burp Suite (para testes de força bruta)
- OWASP ZAP (scanner automático)
- Hydra (para testes automatizados de força bruta - apenas em ambientes autorizados)

**Criticidade por Setor:**
- **Financeiro**: Crítica (autenticação forte é essencial)
- **Educacional**: Alta (proteção de dados de menores)
- **Ecommerce**: Alta (proteção de contas e pagamentos)

**Validação Técnica:**
- ✅ Checklist cobre principais falhas de autenticação
- ✅ Inclui validação de rate limiting e MFA
- ✅ Ferramentas adequadas recomendadas

---

#### 8. Software and Data Integrity Failures

**Testes Básicos:**
- [ ] Verificar assinaturas de código (integridade de releases)
- [ ] Validar integridade de pipeline CI/CD (verificar não comprometimento)
- [ ] Testar validação de dados (integridade de dados recebidos)
- [ ] Verificar proteção de backups (criptografia, acesso restrito)

**Testes Avançados:**
- [ ] Validar uso de bibliotecas de conteúdo inseguro (CDN sem verificação)
- [ ] Testar prevenção de supply chain attacks
- [ ] Verificar verificação de integridade em atualizações
- [ ] Validar processo de assinatura digital

**Ferramentas Recomendadas:**
- Code signing verification
- Análise de pipeline CI/CD
- Validação de checksums
- Análise de dependências

**Criticidade por Setor:**
- **Financeiro**: Alta (integridade é crítica para transações)
- **Educacional**: Média (integridade de dados de alunos)
- **Ecommerce**: Alta (integridade de dados de pedidos e pagamentos)

**Validação Técnica:**
- ✅ Checklist cobre integridade de código e dados
- ✅ Inclui validação de CI/CD
- ✅ Considera supply chain attacks

---

#### 9. Security Logging and Monitoring Failures

**Testes Básicos:**
- [ ] Verificar logging de eventos de segurança (login, logout, falhas de autenticação)
- [ ] Testar monitoramento em tempo real (alertas configurados)
- [ ] Validar retenção de logs (compliance, análise forense)
- [ ] Verificar análise de logs (deteção de anomalias)

**Testes Avançados:**
- [ ] Validar que logs não expõem dados sensíveis (senhas, tokens)
- [ ] Testar centralização de logs (SIEM)
- [ ] Verificar correlação de eventos de segurança
- [ ] Validar resposta a incidentes (runbook, processo)

**Ferramentas Recomendadas:**
- SIEM (Security Information and Event Management)
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Splunk (análise de logs)
- Prometheus + Grafana (monitoramento)

**Criticidade por Setor:**
- **Financeiro**: Alta (compliance, detecção de fraudes)
- **Educacional**: Média (compliance LGPD, proteção de dados)
- **Ecommerce**: Alta (deteção de fraudes, compliance)

**Validação Técnica:**
- ✅ Checklist cobre logging e monitoramento
- ✅ Inclui validação de compliance
- ✅ Ferramentas especializadas recomendadas

---

#### 10. Server-Side Request Forgery (SSRF)

**Testes Básicos:**
- [ ] Testar URLs internas (acesso a localhost, IPs privados)
- [ ] Validar whitelist de domínios permitidos
- [ ] Verificar bloqueio de IPs privados (10.x.x.x, 192.168.x.x, 127.0.0.1)
- [ ] Testar network segmentation (limitação de acesso)

**Testes Avançados:**
- [ ] Testar bypass de validação de URL (encoding, redirecionamento)
- [ ] Validar validação de schema (http://, https://, file://, gopher://)
- [ ] Verificar timeout e limites de requisições
- [ ] Testar diferentes protocolos (HTTP, HTTPS, FTP, etc.)

**Ferramentas Recomendadas:**
- Burp Suite (para interceptar e modificar requisições)
- SSRFmap (ferramenta específica para testes SSRF)
- OWASP ZAP (scanner automático)

**Criticidade por Setor:**
- **Financeiro**: Alta (SSRF pode acessar sistemas internos)
- **Educacional**: Média (SSRF pode acessar dados internos)
- **Ecommerce**: Média (SSRF pode acessar sistemas internos)

**Validação Técnica:**
- ✅ Checklist cobre principais cenários de SSRF
- ✅ Inclui validação de URLs e protocolos
- ✅ Ferramentas especializadas recomendadas

---

### Parte 2: Adaptar por Contexto

**Solução Esperada - Checklist Financeiro:**

```markdown
## Checklist Financeiro - OWASP Top 10

### Prioridade Crítica
1. **Broken Access Control** (acesso a contas bancárias)
2. **Cryptographic Failures** (dados de cartão - PCI-DSS)
3. **Injection** (acesso a dados bancários)

### Testes Específicos Financeiro

#### Broken Access Control
- [ ] Validar isolamento absoluto de contas entre clientes
- [ ] Testar que usuário não acessa extrato de outras contas
- [ ] Verificar que transações só podem ser iniciadas pelo dono da conta

#### Cryptographic Failures
- [ ] Verificar criptografia de dados de cartão (PCI-DSS)
- [ ] Validar que dados de cartão nunca são armazenados em texto plano
- [ ] Testar uso de tokenização para dados de pagamento

#### Injection
- [ ] Testar SQL Injection em endpoints de consulta de extratos
- [ ] Validar que queries de transações usam prepared statements
- [ ] Verificar que dados bancários não são expostos via injection

#### Security Misconfiguration
- [ ] Verificar headers de segurança (CSP, HSTS)
- [ ] Validar configuração de TLS (TLS 1.2+, ciphers seguros)
- [ ] Testar exposição de informações sensíveis em logs

#### Authentication Failures
- [ ] Validar MFA obrigatório para operações sensíveis (transferências)
- [ ] Testar rate limiting em login (prevenir força bruta)
- [ ] Verificar política de senhas forte (mínimo 12 caracteres)

### Compliance
- [ ] Validar requisitos PCI-DSS
- [ ] Verificar logs de auditoria (todas as transações)
- [ ] Testar retenção de logs (compliance)
```

**Validação Técnica:**
- ✅ Prioriza vulnerabilidades críticas para financeiro
- ✅ Inclui testes específicos de PCI-DSS
- ✅ Considera compliance e auditoria
- ✅ Foca em dados de cartão e transações

---

**Solução Esperada - Checklist Educacional:**

```markdown
## Checklist Educacional - OWASP Top 10

### Prioridade Crítica
1. **Broken Access Control** (dados de menores - LGPD)
2. **Cryptographic Failures** (proteção de dados pessoais)
3. **Injection** (acesso a dados de alunos)

### Testes Específicos Educacional

#### Broken Access Control
- [ ] Validar isolamento de dados de alunos entre turmas
- [ ] Testar que alunos não acessam dados de outros alunos
- [ ] Verificar que professores só acessam dados de suas turmas

#### Cryptographic Failures
- [ ] Verificar criptografia de dados pessoais (LGPD)
- [ ] Validar que dados de menores são especialmente protegidos
- [ ] Testar uso de hash para dados sensíveis

#### Injection
- [ ] Testar SQL Injection em endpoints de consulta de notas
- [ ] Validar que dados de alunos não são expostos via injection

#### Authentication Failures
- [ ] Validar autenticação forte para acesso de pais/responsáveis
- [ ] Testar rate limiting em login
- [ ] Verificar política de senhas adequada

### Compliance
- [ ] Validar requisitos LGPD (especialmente dados de menores)
- [ ] Verificar logs de acesso (auditoria de acesso a dados sensíveis)
- [ ] Testar consentimento para uso de dados
```

**Validação Técnica:**
- ✅ Prioriza vulnerabilidades críticas para educacional
- ✅ Inclui testes específicos de LGPD
- ✅ Considera dados de menores
- ✅ Foca em privacidade e isolamento

---

### Parte 3: Template de Documentação

**Solução Esperada:**

```markdown
# Relatório de Testes de Segurança - OWASP Top 10

## Informações Gerais
- **Aplicação**: [Nome da aplicação]
- **Data**: [Data do teste]
- **Testador**: [Nome do testador]
- **Contexto**: [Financeiro/Educacional/Ecommerce]
- **Escopo**: [URLs/Endpoints testados]

## Resumo Executivo

### Total de Vulnerabilidades Encontradas
- **Críticas**: [X]
- **Altas**: [X]
- **Médias**: [X]
- **Baixas**: [X]
- **Total**: [X]

### Status Geral
- [ ] Aplicação segura para produção
- [ ] Vulnerabilidades críticas precisam ser corrigidas
- [ ] Vulnerabilidades médias/baixas podem ser corrigidas em próximas releases

## Vulnerabilidades Encontradas

### [Vulnerabilidade #1]: [Nome]

**Tipo**: [OWASP Top 10 #] - [Nome]
**Severidade**: [Crítica/Alta/Média/Baixa]
**CVSS Score**: [X.X] (se aplicável)

**Descrição**:
[Descrição detalhada da vulnerabilidade]

**Evidência**:
- **Endpoint**: `[URL/Endpoint]`
- **Payload**: `[Payload usado]`
- **Screenshot**: [Link para screenshot]
- **Log**: [Log relevante]

**Impacto**:
- [Descrição do impacto]
- **Dados Afetados**: [Quais dados são afetados]
- **Usuários Afetados**: [Quantos usuários podem ser afetados]

**Recomendação**:
[Como corrigir a vulnerabilidade]
- [ ] Correção 1
- [ ] Correção 2
- [ ] Correção 3

**Prioridade**: [P1/P2/P3/P4]
**Prazo Sugerido**: [Prazo para correção]

---

## Detalhamento por OWASP Top 10

### 1. Broken Access Control
- **Total de Vulnerabilidades**: [X]
- **Críticas**: [X]
- **Status**: [✅ Passou / ⚠️ Falhou / ❌ Crítico]

### 2. Cryptographic Failures
[Similar para cada categoria]

---

## Recomendações Prioritárias

1. **Prioridade P1 (Crítica - Corrigir Imediatamente)**
   - [Vulnerabilidade #1]: [Descrição]
   - [Vulnerabilidade #2]: [Descrição]

2. **Prioridade P2 (Alta - Corrigir Este Sprint)**
   - [Vulnerabilidade #3]: [Descrição]

3. **Prioridade P3 (Média - Corrigir Próximo Sprint)**
   - [Vulnerabilidade #4]: [Descrição]

4. **Prioridade P4 (Baixa - Corrigir Quando Possível)**
   - [Vulnerabilidade #5]: [Descrição]

---

## Próximos Passos

1. [ ] Revisar vulnerabilidades críticas com time de desenvolvimento
2. [ ] Criar issues para correções
3. [ ] Retestar após correções
4. [ ] Atualizar checklist com novas descobertas

---

**Assinatura**:
- Testador: ________________
- Data: ________________
- Revisão: ________________
```

**Validação Técnica:**
- ✅ Template estruturado e completo
- ✅ Inclui evidências (screenshots, logs)
- ✅ Sistema de priorização claro
- ✅ Próximos passos definidos

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Checklist Base:**
- [ ] Checklist criado para todas as 10 vulnerabilidades OWASP Top 10
- [ ] Cada vulnerabilidade tem pelo menos 3-4 testes básicos
- [ ] Ferramentas recomendadas incluídas
- [ ] Criticidade por setor considerada

**Adaptação por Contexto:**
- [ ] Checklist adaptado para pelo menos 1 contexto (Financeiro/Educacional/Ecommerce)
- [ ] Prioridades ajustadas para contexto específico
- [ ] Testes específicos do contexto incluídos

**Template de Documentação:**
- [ ] Template criado para documentar resultados
- [ ] Template inclui seções essenciais (informações gerais, resumo, detalhamento)
- [ ] Sistema de priorização incluído

### ⭐ Importantes (Recomendados para Resposta Completa)

**Checklist Base:**
- [ ] Testes avançados incluídos para maioria das vulnerabilidades
- [ ] Ferramentas especializadas recomendadas
- [ ] Exemplos de payloads ou testes incluídos

**Adaptação por Contexto:**
- [ ] Checklist adaptado para 2-3 contextos diferentes
- [ ] Compliance específico considerado (PCI-DSS, LGPD)
- [ ] Testes específicos bem detalhados

**Template de Documentação:**
- [ ] Template completo com todas as seções
- [ ] Exemplos de preenchimento incluídos
- [ ] Formato profissional e claro

**Aplicação:**
- [ ] Checklist aplicado em aplicação real ou de exemplo
- [ ] Resultados documentados usando template
- [ ] Vulnerabilidades priorizadas

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Checklist:**
- [ ] Checklist customizado para projeto específico
- [ ] Integração com ferramentas de segurança (SAST, DAST)
- [ ] Processo de atualização do checklist documentado

**Template:**
- [ ] Template integrado com ferramentas (Jira, GitHub Issues)
- [ ] Métricas de segurança incluídas (tempo de correção, taxa de retest)
- [ ] Dashboard de vulnerabilidades criado

**Aplicação:**
- [ ] Processo completo de triagem documentado
- [ ] Recomendações de correção bem detalhadas
- [ ] Análise de tendências de vulnerabilidades

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Criação de Checklist**: Aluno consegue criar checklist completo e prático?
2. **Adaptação por Contexto**: Aluno adapta checklist para diferentes contextos?
3. **Documentação**: Aluno documenta resultados de forma estruturada?
4. **Priorização**: Aluno prioriza vulnerabilidades adequadamente?

### Erros Comuns

1. **Erro: Checklist muito genérico**
   - **Situação**: Aluno cria checklist vago ("testar segurança")
   - **Feedback**: "Boa ideia criar checklist! Para torná-lo mais útil, seja específico: em vez de 'testar segurança', liste testes concretos como 'testar IDOR em todos os endpoints que recebem ID de recurso'. Isso torna checklist acionável."

2. **Erro: Não adaptar por contexto**
   - **Situação**: Aluno usa mesmo checklist para financeiro e educacional
   - **Feedback**: "Checklist criado! Lembre-se que diferentes contextos têm prioridades diferentes. Em financeiro, priorize PCI-DSS e proteção de dados de cartão. Em educacional, priorize LGPD e proteção de dados de menores. Adapte checklist para contexto."

3. **Erro: Template incompleto**
   - **Situação**: Aluno cria template sem seções de evidência ou priorização
   - **Feedback**: "Template criado! Para torná-lo mais completo, inclua: seção de evidências (screenshots, logs), sistema de priorização (P1/P2/P3), e próximos passos. Isso facilita correção e follow-up."

### Dicas para Feedback

- ✅ **Reconheça**: Checklist completo, adaptação por contexto, template bem estruturado
- ❌ **Corrija**: Checklist genérico, falta de adaptação, template incompleto
- 💡 **Incentive**: Checklist customizado, integração com ferramentas, processo de atualização

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Prática Real**: QA de segurança precisa de checklist sistemático para garantir cobertura
2. **Adaptação**: Ensina a adaptar testes para diferentes contextos e necessidades
3. **Documentação**: Desenvolve capacidade de documentar resultados de forma estruturada
4. **Reutilização**: Checklist criado pode ser usado em projetos reais

**Conexão com o Curso:**
- Aula 1.2: OWASP Top 10 (teoria) → Este exercício (prática sistemática)
- Pré-requisito para: Módulo 2 (ferramentas SAST complementam checklist manual)
- Base para: Processo contínuo de testes de segurança

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Checklist OWASP Top 10:**
"Checklist completo criado para todas as 10 vulnerabilidades, com 5-7 testes básicos e 3-4 testes avançados para cada. Inclui ferramentas recomendadas (Burp Suite, OWASP ZAP, SQLMap) e criticidade por setor (Financeiro: Crítica para Injection, Educacional: Alta para Broken Access Control)."

**Adaptação:**
"Checklist financeiro prioriza Broken Access Control (crítica), Cryptographic Failures (crítica - PCI-DSS), e Injection (crítica). Inclui testes específicos como 'validar isolamento absoluto de contas' e 'verificar criptografia de dados de cartão (PCI-DSS)'. Checklist educacional prioriza LGPD e proteção de dados de menores."

**Template:**
"Template completo com seções: Informações Gerais, Resumo Executivo (total por severidade), Detalhamento (descrição, evidência, impacto, recomendação, prioridade), e Próximos Passos. Inclui sistema de priorização P1-P4 e campos para screenshots/logs."

**Aplicação:**
"Aplicado em OWASP Juice Shop: encontradas 8 vulnerabilidades (3 críticas, 2 altas, 3 médias). Documentado usando template, priorizadas, e issues criadas. Checklist será usado em próximas releases."

**Características da Resposta:**
- ✅ Checklist completo e detalhado
- ✅ Adaptação bem feita para múltiplos contextos
- ✅ Template profissional e completo
- ✅ Aplicação prática documentada

---

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
