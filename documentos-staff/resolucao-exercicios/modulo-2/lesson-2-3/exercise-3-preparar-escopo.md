---
exercise_id: lesson-2-3-exercise-3-preparar-escopo
title: "Exercício 2.3.3: Preparar Escopo de Pentest"
lesson_id: lesson-2-3
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.3.3: Preparar Escopo de Pentest

## 📋 Enunciado Completo

Empresa contratou pentest externo. Como QA, você deve preparar escopo e ambiente de teste.

### Tarefa
1. Definir escopo (endpoints, funcionalidades, exclusões)
2. Preparar ambiente de teste (staging isolado)
3. Criar credenciais de teste (diferentes níveis de acesso)
4. Documentar regras de engajamento
5. Preparar time interno

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Documento de escopo completo e profissional:**

```markdown
## 🎯 Escopo de Pentest - Q1 2026

**Cliente**: Empresa XYZ Ltda.  
**Pentester**: Security Consultoria S.A.  
**Data**: 01-05 de Fevereiro de 2026 (5 dias úteis)  
**Tipo**: Gray Box (credenciais fornecidas)  
**Metodologia**: OWASP Testing Guide v4 + PTES

---

### 📍 In-Scope (O que DEVE ser testado)

**Aplicações Web:**
- URL: https://app.exemplo.com
- URL: https://admin.exemplo.com
- URL API: https://api.exemplo.com/v1/*

**Funcionalidades Críticas:**
1. **Autenticação e Autorização**
   - Login/Logout
   - Recuperação de senha
   - MFA (2FA)
   - Controles de acesso (RBAC)

2. **Área do Cliente**
   - Dashboard
   - Perfil de usuário
   - Histórico de transações
   - Upload de documentos

3. **Checkout e Pagamentos**
   - Carrinho de compras
   - Processamento de pagamento
   - Integração com gateway (sandbox)

4. **Painel Administrativo**
   - Gestão de usuários
   - Relatórios financeiros
   - Configurações do sistema

**APIs REST:**
- Todos os endpoints `/api/v1/*`
- Autenticação via JWT
- Rate limiting

**Tecnologias:**
- Frontend: React 18
- Backend: Node.js 18 + Express
- Database: PostgreSQL 14
- Cache: Redis 7

---

### ⛔ Out-of-Scope (O que NÃO deve ser testado)

**Infraestrutura:**
- ❌ Servidores AWS (EC2, RDS, S3)
- ❌ Network layer (switches, routers)
- ❌ Firewall configurations
- ❌ DNS configurations

**Ataques Destrutivos:**
- ❌ DoS/DDoS attacks
- ❌ Resource exhaustion
- ❌ Disk filling attacks
- ❌ Data deletion/corruption

**Engenharia Social:**
- ❌ Phishing campaigns
- ❌ Vishing (phone calls)
- ❌ Physical security testing
- ❌ Social media profiling

**Ambiente de Produção:**
- ❌ https://app.exemplo.com (produção)
- ✅ https://staging.exemplo.com (teste)
- ⚠️ APENAS ambiente staging deve ser testado

**Terceiros:**
- ❌ Stripe API (payment gateway)
- ❌ SendGrid API (email)
- ❌ AWS services (use mocks)

---

### 🔐 Credenciais de Teste

**User Regular (Basic):**
- Email: `test_user@exemplo.com`
- Senha: `TestUser123!@#`
- Role: `user`
- Permissões: Leitura próprios dados

**User Premium (Authenticated):**
- Email: `test_premium@exemplo.com`
- Senha: `TestPremium456!@#`
- Role: `premium_user`
- Permissões: Leitura/escrita próprios dados + features premium

**Admin (Privileged):**
- Email: `test_admin@exemplo.com`
- Senha: `TestAdmin789!@#`
- Role: `admin`
- Permissões: Gestão completa (usuários, config, relatórios)

**Super Admin (Full Access):**
- Email: `test_superadmin@exemplo.com`
- Senha: `TestSuperAdmin000!@#`
- Role: `super_admin`
- Permissões: Acesso irrestrito (incluindo sistema)

**API Keys:**
- Dev API Key: `sk_test_REDACTED`
- Admin API Key: `sk_test_REDACTED_ADMIN`

**Notas:**
- Todas as senhas são descartáveis (serão resetadas após pentest)
- Credenciais NÃO devem ser compartilhadas fora do pentest
- API keys são válidas APENAS em staging

---

### 📜 Regras de Engajamento

**Horário de Testes:**
- Segunda a Sexta: 09:00 - 18:00 (horário comercial)
- ❌ Fim de semana: Não autorizado
- ❌ Feriados: Não autorizado
- ⚠️ Urgências: Contatar security@exemplo.com

**Comunicação:**
- **Contato Primário**: João Silva (Security Lead)
  - Email: joao.silva@exemplo.com
  - Slack: @joao.silva
  - Celular: +55 11 98765-4321 (emergências)

- **Contato Secundário**: Maria Santos (QA Lead)
  - Email: maria.santos@exemplo.com
  - Slack: @maria.santos

**Notificação Obrigatória ANTES de:**
1. Port scanning agressivo (> 1000 ports)
2. Exploits que possam causar instabilidade
3. Brute force attacks (> 100 tentativas)
4. SQL injection com comandos destrutivos (DROP, DELETE)
5. File upload de malware (mesmo em sandbox)

**Em Caso de Emergência:**
- Sistema offline/instável: Parar testes IMEDIATAMENTE
- Ligar: +55 11 98765-4321 (João Silva)
- Email: security-emergency@exemplo.com
- Slack: #security-incidents

**Evidências:**
- Screenshots de todas as vulnerabilidades
- Payloads completos (para reprodução)
- Logs de requisições (timestamps)
- Vídeo de exploração (vulnerabilidades críticas)

**Confidencialidade:**
- NDA assinado (anexo)
- Dados de teste NÃO são dados reais
- Relatório confidencial (não compartilhar)
- Credenciais devem ser deletadas após pentest

---

### 🏗️ Preparação do Ambiente

**Ambiente Staging Isolado:**
```yaml
URL: https://staging.exemplo.com
Database: staging_db (dados sintéticos)
Redis: staging_redis_cache
Logs: CloudWatch Logs (staging-pentest)

Diferenças de Produção:
  - Dados: Sintéticos (50K usuários fake)
  - Pagamentos: Sandbox (Stripe Test Mode)
  - Emails: Mailtrap (não envia emails reais)
  - Rate Limiting: Desabilitado (para permitir testes)
```

**Dados Sintéticos:**
- 50.000 usuários fake
- 100.000 transações fake
- 10.000 produtos fake
- Nenhum dado real de clientes

**Monitoramento:**
- Logs centralizados: CloudWatch
- Alertas: Slack #security-pentest
- Dashboard: Grafana (staging metrics)

**Backup:**
- Snapshot do staging antes do pentest
- Rollback disponível (se necessário)
- Dados preservados para auditoria

---

### 📋 Checklist de Preparação

**1 Semana Antes:**
- [x] Documento de escopo aprovado
- [x] NDA assinado por pentester
- [x] Ambiente staging isolado preparado
- [x] Dados sintéticos carregados
- [x] Credenciais de teste criadas

**3 Dias Antes:**
- [x] Kickoff meeting agendado
- [x] Time interno notificado
- [x] Monitoramento configurado
- [x] Backup do staging realizado

**1 Dia Antes:**
- [x] Credenciais testadas (login funciona)
- [x] Ambiente validado (aplicação online)
- [x] Contatos de emergência confirmados
- [x] Slack #security-pentest criado

**Dia do Pentest:**
- [x] Kickoff call (09:00)
- [ ] Pentester iniciou testes
- [ ] Monitoramento ativo (war room)

---

### 👥 Preparação do Time Interno

**Kickoff Meeting (1h):**
- Agenda:
  1. Apresentação do pentester
  2. Revisão do escopo
  3. Demonstração do ambiente staging
  4. Q&A

**Time Interno Envolvido:**
- Security Lead (full-time)
- QA Lead (part-time)
- DevOps Engineer (on-call)
- Backend Lead (on-call)

**Comunicação:**
- Slack: #security-pentest (privado)
- Daily updates: 17:00 (resumo do dia)
- Incidentes críticos: Notificação imediata

**Expectativas:**
- Pentester encontrará vulnerabilidades (esperado)
- Não culpar devs (foco em processo)
- Aprender com findings (não defensivo)

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Escopo claro (in-scope vs out-of-scope)
- [ ] Credenciais de teste criadas (múltiplos níveis)
- [ ] Regras de engajamento definidas
- [ ] Ambiente staging preparado

### ⭐ Importantes
- [ ] Ambiente isolado (não afeta produção)
- [ ] Dados sintéticos (não usa dados reais)
- [ ] Contatos de emergência definidos
- [ ] Kickoff meeting planejado

### 💡 Diferencial
- [ ] NDA e contratos revisados
- [ ] Monitoramento em tempo real configurado
- [ ] Baseline de segurança documentado
- [ ] Processo de follow-up planejado

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Definição de Escopo**: Consegue definir limites claros (in/out-of-scope)?
2. **Segurança Operacional**: Isola ambiente de teste (não afeta produção)?
3. **Preparação de Credenciais**: Cria múltiplos níveis de acesso?
4. **Gestão de Stakeholders**: Prepara time interno e define comunicação?

### Erros Comuns

**Erro 1: "Escopo muito amplo (tudo é in-scope)"**
- **Problema**: Pentest sem limites = custo alto + risco de afetar produção
- **Feedback**: "Escopo deve ser FOCADO. Priorize áreas críticas: autenticação, checkout, APIs principais. Out-of-scope deve incluir: infraestrutura, ataques destrutivos, produção, terceiros. Escopo claro protege ambos (empresa e pentester). Redefina com foco nas funcionalidades de negócio críticas."

**Erro 2: "Usou ambiente de produção"**
- **Problema**: Pentest em produção = risco de downtime, exposição de dados reais
- **Feedback**: "⚠️ CRÍTICO: Pentest NUNCA deve ser em produção. Use staging isolado com: 1) Dados sintéticos (não reais), 2) Configurações similares, 3) Monitoramento. Se staging não existe, CRIE antes de contratar pentest. Produção = risco inaceitável."

**Erro 3: "Credenciais de um único nível"**
- **Problema**: Apenas user admin = não testa controles de acesso adequadamente
- **Feedback**: "Teste de autorização exige MÚLTIPLOS níveis: user básico, premium, admin, super admin. Pentester testa se user básico consegue acessar recursos admin (privilege escalation). Crie ao menos 3 níveis de credenciais com permissões diferentes."

**Erro 4: "Não definiu regras de engajamento"**
- **Problema**: Sem regras = pentester pode fazer port scan agressivo → derruba staging
- **Feedback**: "Regras de engajamento protegem AMBOS. Defina: 1) Horário permitido, 2) Notificação antes de ataques agressivos, 3) Contatos de emergência, 4) O que fazer se sistema cair. Isso evita mal-entendidos e incidentes."

**Erro 5: "Não preparou time interno"**
- **Problema**: Devs descobrem pentest durante execução → pânico, defensividade
- **Feedback**: "Comunicação prévia é essencial. Notifique time: 1) Pentest está acontecendo (quando), 2) Não é auditoria de pessoas (blameless), 3) Objetivo é APRENDER, 4) Como reportar se observarem comportamento suspeito. Time preparado colabora; surpresa gera resistência."

**Erro 6: "Dados reais em ambiente de teste"**
- **Problema**: Staging com dados de produção = risco de exposição via pentest
- **Feedback**: "⚠️ LGPD: Ambiente de teste NUNCA deve ter dados reais. Use dados sintéticos (faker, mockaroo) ou anonimizados (PII removido). Se pentester achar vulnerabilidade e expor dados, você violou LGPD Art. 46 (testes com dados reais sem proteção adequada). Substitua por dados fake."

### Dicas para Feedback Construtivo

**Para preparação profissional:**
> "Excelente preparação de escopo! Você demonstrou maturidade ao: 1) Definir limites claros (in/out-of-scope), 2) Isolar ambiente staging com dados sintéticos, 3) Criar credenciais multi-nível, 4) Estabelecer regras de engajamento, 5) Preparar time interno. Essa é a preparação de empresas maduras em segurança. Seu pentest será produtivo e seguro. Próximo nível: após pentest, documente lições aprendidas para melhorar processo."

**Para preparação básica:**
> "Boa preparação inicial! Você definiu escopo e credenciais. Para melhorar: 1) Adicione regras de engajamento (horário, notificações, emergências), 2) Valide que ambiente staging NÃO tem dados reais (LGPD), 3) Prepare time interno (kickoff meeting, comunicação), 4) Configure monitoramento (logs, alertas). Sua base está correta, agora completude e segurança operacional."

**Para dificuldades:**
> "Preparação de pentest é complexa na primeira vez. Vamos simplificar: 1) Use template de escopo (OWASP, PTES), 2) Copie configuração de staging de produção (mas com dados fake), 3) Crie credenciais básicas (user, admin), 4) Agende call de 1h com pentester (esclarecer dúvidas). Após primeiro pentest, fica mais fácil. Peça suporte de security team se disponível."

### Contexto Pedagógico

**Por que este exercício é fundamental:**

1. **Coordenação de Pentest**: QA frequentemente prepara escopo (não executa, mas coordena)
2. **Segurança Operacional**: Ensina a isolar testes (não afetar produção/dados reais)
3. **Gestão de Stakeholders**: Preparar time interno é crítico para sucesso
4. **Compliance LGPD**: Dados sintéticos em teste = obrigação legal
5. **Eficácia do Pentest**: Escopo bem definido = pentest focado e eficaz

**Conexão com o Curso:**
- **Pré-requisito**: Aula 2.3 (Pentest Básico), Exercício 2.3.1 (Interpretar Relatório)
- **Aplica conceitos**: Escopo, Metodologias (OWASP, PTES), Regras de Engajamento
- **Prepara para**: Exercício 2.3.2 (Validar Correções), Carreira em Security Operations
- **Integra com**: Aula 2.4 (Automação) - staging isolado é essencial para CI/CD security

**Habilidades desenvolvidas:**
- Definição de escopo (técnico + negócio)
- Segurança operacional (isolamento de ambientes)
- Gestão de stakeholders (preparação de time)
- Compliance (LGPD em testes)

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
