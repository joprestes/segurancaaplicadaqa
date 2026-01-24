---
exercise_id: lesson-2-2-exercise-3-dast-cicd
title: "Exercício 2.2.3a: DAST Autenticado (Área Logada)"
lesson_id: lesson-2-2
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.2.3a: DAST Autenticado (Área Logada)

## 📋 Enunciado Completo

Este exercício tem como objetivo **configurar OWASP ZAP para escanear áreas autenticadas** de uma aplicação web (dashboard, painel administrativo, área de perfil).

**Contexto**: Baseline Scan (Exercício 2.2.1) testa apenas páginas públicas. Vulnerabilidades críticas geralmente estão em **áreas logadas** (ex: IDOR no `/profile`, XSS no `/admin/users`). Authenticated Scan garante cobertura completa.

### Tarefa

1. **Criar usuário de teste** (se necessário)
2. **Configurar ZAP Context** com credenciais de autenticação
3. **Mapear fluxo de login** (form-based, JWT, OAuth)
4. **Executar scan autenticado** (ZAP faz login automaticamente)
5. **Validar cobertura** - garantir que área logada foi escaneada
6. **Analisar vulnerabilidades** exclusivas de área autenticada (IDOR, privilege escalation)
7. **Documentar processo** de configuração (replicável)

**Aplicações de Teste Sugeridas**:
- OWASP Juice Shop (https://juice-shop.herokuapp.com) - tem área de perfil/basket
- DVWA (Damn Vulnerable Web Application) - local
- Aplicação própria (staging/dev environment)

---

## ✅ Soluções Detalhadas

### Passo 1: Criar Usuário de Teste

**Recomendações:**

```markdown
## Usuário de Teste para DAST

**Princípios:**
- ✅ Criar usuário dedicado para scans (`dast-scanner@example.com`)
- ✅ Evitar usar usuário real (logs ficam poluídos)
- ✅ Permissões realistas (não admin, mas acesso a features principais)
- ✅ Dados fictícios (não dados sensíveis de produção)
- ⚠️ **NUNCA** escanear produção sem autorização explícita

**Exemplo (Juice Shop):**
```bash
# Registrar usuário via API
curl -X POST https://juice-shop.herokuapp.com/api/Users/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "dast-test@example.com",
    "password": "Test@123456",
    "passwordRepeat": "Test@123456",
    "securityQuestion": {
      "id": 1,
      "question": "Your eldest siblings middle name?",
      "answer": "test"
    }
  }'
```

**Documentar Credenciais (Secure):**
```bash
# Armazenar em .env (NUNCA commitar no git)
echo "DAST_USER_EMAIL=dast-test@example.com" >> .env.dast
echo "DAST_USER_PASSWORD=Test@123456" >> .env.dast

# Adicionar ao .gitignore
echo ".env.dast" >> .gitignore
```

---

### Passo 2: Configurar ZAP Context (Authenticated Scan)

**Opção A: ZAP GUI (Interface Gráfica)**

**Passo 2.1: Criar Context**

1. Abra OWASP ZAP
2. Menu: **Analyse → Include in Context → New Context**
3. Nome: `juice-shop-authenticated`
4. **Include in Context**: `https://juice-shop.herokuapp.com.*`
5. **Exclude from Context**:
   ```regex
   https://juice-shop.herokuapp.com/.*logout.*
   https://juice-shop.herokuapp.com/.*/\.(js|css|png|jpg|gif|svg)$
   https://juice-shop.herokuapp.com/ftp/.*
   ```

**Passo 2.2: Configurar Autenticação**

1. Context → **Authentication**
2. Method: **Form-Based Authentication**
3. **Login Form Target URL**: `https://juice-shop.herokuapp.com/rest/user/login`
4. **Login Request Data** (POST body):
   ```
   email={%username%}&password={%password%}
   ```
5. **Username Parameter**: `email`
6. **Password Parameter**: `password`
7. **Logged In Indicator** (regex na resposta autenticada):
   ```regex
   "authentication":\{"token":"
   ```
8. **Logged Out Indicator** (regex quando NÃO está logado):
   ```regex
   "Invalid email or password"
   ```

**Passo 2.3: Adicionar Usuário**

1. Context → **Users**
2. **Add User**:
   - Username: `dast-test@example.com`
   - Password: `Test@123456`
3. **Enable User**

**Passo 2.4: Configurar Session Management**

1. Context → **Session Management**
2. Method: **Cookie-Based Session Management**
3. (ZAP detecta automaticamente cookie `token` do Juice Shop)

**Passo 2.5: Validar Autenticação**

1. Clique direito no Context → **Flag as Context → juice-shop-authenticated**
2. Menu: **Tools → Force User Mode**
3. Selecione usuário: `dast-test@example.com`
4. **Test**: Navegue manualmente para `https://juice-shop.herokuapp.com/#/profile`
   - Deve aparecer perfil do usuário (não redirect para login)

**Passo 2.6: Executar Scan Autenticado**

1. Menu: **Tools → Active Scan**
2. **Starting Point**: `https://juice-shop.herokuapp.com`
3. **Context**: `juice-shop-authenticated`
4. **User**: `dast-test@example.com`
5. **Recurse**: ✅ Enable
6. **Policy**: Default
7. Clique em **Start Scan**
8. Aguarde (10-15 minutos)

---

**Opção B: ZAP CLI (Automação)**

```bash
# 1. Criar arquivo de configuração do Context
cat > zap-context.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <context>
    <name>juice-shop-authenticated</name>
    <desc>Authenticated scan for Juice Shop</desc>
    <inscope>true</inscope>
    <incregexes>https://juice-shop.herokuapp.com.*</incregexes>
    <excregexes>https://juice-shop.herokuapp.com/.*logout.*</excregexes>
    <authentication>
      <type>1</type> <!-- Form-Based -->
      <loggedinindicator>"authentication":\{"token":</loggedinindicator>
      <loggedoutindicator>"Invalid email or password"</loggedoutindicator>
      <loginurl>https://juice-shop.herokuapp.com/rest/user/login</loginurl>
      <loginrequestdata>email={%username%}&amp;password={%password%}</loginrequestdata>
    </authentication>
    <users>
      <user>
        <name>dast-test@example.com</name>
        <credentials>
          <credential>
            <name>email</name>
            <value>dast-test@example.com</value>
          </credential>
          <credential>
            <name>password</name>
            <value>Test@123456</value>
          </credential>
        </credentials>
      </user>
    </users>
  </context>
</configuration>
EOF

# 2. Executar scan autenticado
docker run -v $(pwd):/zap/wrk:rw owasp/zap2docker-stable \
  zap-full-scan.py \
  -t https://juice-shop.herokuapp.com \
  -n zap-context.xml \
  -U dast-test@example.com \
  -r authenticated_scan_report.html \
  -J authenticated_scan_report.json

# 3. Verificar relatório
ls -lh authenticated_scan_report.html
```

---

**Opção C: ZAP API (Programático)**

```python
# zap_authenticated_scan.py
from zapv2 import ZAPv2
import time

# Configuração
zap = ZAPv2(apikey='your-api-key-here', proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})
target = 'https://juice-shop.herokuapp.com'

# 1. Criar Context
context_name = 'juice-shop-auth'
zap.context.new_context(contextname=context_name)
zap.context.include_in_context(context_name, f'{target}.*')
zap.context.exclude_from_context(context_name, f'{target}/.*logout.*')

# 2. Configurar Autenticação
login_url = f'{target}/rest/user/login'
login_data = 'email={%username%}&password={%password%}'
logged_in_indicator = r'"authentication":\{"token":'
logged_out_indicator = r'"Invalid email or password"'

auth_method_config = {
    'methodname': 'formBasedAuthentication',
    'loginurl': login_url,
    'loginrequestdata': login_data
}
zap.authentication.set_authentication_method(context_name, 'formBasedAuthentication', json.dumps(auth_method_config))
zap.authentication.set_logged_in_indicator(context_name, logged_in_indicator)
zap.authentication.set_logged_out_indicator(context_name, logged_out_indicator)

# 3. Adicionar Usuário
user_name = 'dast-test@example.com'
user_credentials = 'email=dast-test@example.com&password=Test@123456'
user_id = zap.users.new_user(context_name, user_name)
zap.users.set_authentication_credentials(context_name, user_id, user_credentials)
zap.users.set_user_enabled(context_name, user_id, True)

# 4. Spider (com autenticação)
print('[+] Starting authenticated spider...')
scan_id = zap.spider.scan_as_user(context_name, user_id, target, recurse=True)
while int(zap.spider.status(scan_id)) < 100:
    print(f'    Spider progress: {zap.spider.status(scan_id)}%')
    time.sleep(2)
print('[+] Spider completed!')

# 5. Active Scan (com autenticação)
print('[+] Starting authenticated active scan...')
scan_id = zap.ascan.scan_as_user(context_name, user_id, target, recurse=True)
while int(zap.ascan.status(scan_id)) < 100:
    print(f'    Active scan progress: {zap.ascan.status(scan_id)}%')
    time.sleep(5)
print('[+] Active scan completed!')

# 6. Gerar Relatório
print('[+] Generating HTML report...')
with open('authenticated_report.html', 'w') as f:
    f.write(zap.core.htmlreport())
print('[+] Report saved: authenticated_report.html')
```

---

### Passo 3: Validar Cobertura (Área Logada Foi Escaneada?)

**Checklist de Validação:**

```markdown
## Validação de Cobertura

### 1. Verificar URLs Escaneadas
- [ ] URLs de área pública presentes (/, /products, /search)
- [ ] URLs de área logada presentes (/profile, /basket, /order-history)
- [ ] URLs administrativas testadas (se usuário tem acesso)

**Como Verificar (ZAP GUI):**
1. Sites tab → Expandir domínio
2. Verificar se há URLs sob `/profile`, `/basket`, etc.
3. Se ausentes → autenticação falhou

### 2. Verificar Session Management
- [ ] Cookie de sessão capturado (ex: `token`, `Authorization`)
- [ ] Session mantida durante o scan (não expirou)

**Como Verificar (ZAP GUI):**
1. Menu: Tools → Session Properties
2. HTTP Sessions → Deve mostrar token válido

### 3. Verificar Findings de Área Logada
- [ ] Vulnerabilidades em endpoints autenticados encontradas
- [ ] Exemplos: IDOR em `/api/user/:id`, XSS em `/profile/update`

**Teste Manual:**
```bash
# Testar endpoint autenticado manualmente
curl -X GET https://juice-shop.herokuapp.com/rest/basket/1 \
  -H "Authorization: Bearer <token>"
# Deve retornar carrinho (não 401 Unauthorized)
```

### 4. Falhas Comuns

**Sintoma**: ZAP não encontrou nenhum endpoint de área logada
**Causa Provável**:
1. Logged In Indicator incorreto (regex não bate)
2. Session expirou durante scan (timeout curto)
3. Login form mudou (target URL incorreto)

**Debugging**:
```bash
# Verificar logs do ZAP
tail -f ~/.ZAP/zap.log | grep -i "authentication"
# Procurar por: "Authentication successful" ou "Failed to authenticate"
```
```

---

### Passo 4: Análise de Vulnerabilidades de Área Logada

**Tipos Comuns em Área Autenticada:**

#### 1. IDOR (Insecure Direct Object Reference)

```markdown
### Vulnerabilidade: IDOR em /api/user/:id

**Descrição**: Usuário comum pode acessar dados de outros usuários modificando ID na URL.

**POC:**
```bash
# Como usuário ID 5, acessar dados do usuário ID 1
curl -X GET https://juice-shop.herokuapp.com/api/user/1 \
  -H "Authorization: Bearer <token-user-5>"
# ✅ Exploração: Retornou dados do usuário ID 1 (email, endereço, histórico)
```

**Risco**: Exposição de dados PII de todos os usuários.

**Correção:**
```javascript
// ❌ Vulnerável
app.get('/api/user/:id', auth, (req, res) => {
  const user = getUserById(req.params.id);  // Sem verificação
  res.json(user);
});

// ✅ Corrigido: Validar que user só acessa próprios dados
app.get('/api/user/:id', auth, (req, res) => {
  if (req.params.id !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({error: 'Forbidden'});
  }
  const user = getUserById(req.params.id);
  res.json(user);
});
```
```

#### 2. Privilege Escalation

```markdown
### Vulnerabilidade: Admin Panel Accessible via Direct URL

**Descrição**: Painel admin (`/admin`) acessível sem verificação de role.

**POC:**
```bash
# Como usuário comum (não-admin), acessar /admin diretamente
curl -X GET https://juice-shop.herokuapp.com/admin \
  -H "Authorization: Bearer <token-user-comum>"
# ✅ Exploração: Painel admin carregado (deveria retornar 403)
```

**Risco**: Usuário comum pode deletar users, alterar produtos, etc.

**Correção:**
```javascript
// ❌ Vulnerável: Frontend esconde botão, mas não protege rota
app.get('/admin', auth, (req, res) => {
  res.render('admin-panel');
});

// ✅ Corrigido: Verificar role no backend
app.get('/admin', auth, requireAdmin, (req, res) => {
  res.render('admin-panel');
});

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({error: 'Admin access required'});
  }
  next();
}
```
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios)

**Configuração Autenticada:**
- [ ] ZAP Context criado com sucesso
- [ ] Autenticação configurada (form-based, JWT, etc.)
- [ ] Usuário de teste criado e habilitado
- [ ] Scan autenticado executado (não apenas baseline público)

**Validação de Cobertura:**
- [ ] Demonstrou que área logada foi escaneada (screenshots de URLs autenticadas)
- [ ] Session mantida durante scan (não expirou)
- [ ] Relatório inclui vulnerabilidades de área autenticada

**Análise de Vulnerabilidades:**
- [ ] Identificou pelo menos 2 vulnerabilidades de área logada (IDOR, privilege escalation, etc.)
- [ ] Documentou detalhes técnicos (endpoint, payload, impacto)
- [ ] Propôs correções técnicas

### ⭐ Importantes (Qualidade da Resposta)

**Configuração Profissional:**
- [ ] Documentou processo de configuração (replicável por outro QA)
- [ ] Credenciais armazenadas de forma segura (.env, não hardcoded)
- [ ] Exclusões configuradas (logout, assets estáticos)
- [ ] Logged In/Out indicators validados

**Análise Crítica:**
- [ ] Validou manualmente pelo menos 1 IDOR (não confiou apenas no ZAP)
- [ ] Testou privilege escalation (usuário comum acessando admin?)
- [ ] Comparou findings autenticado vs público (quais são exclusivos de área logada?)
- [ ] Priorizou por risco contextual

**Automação:**
- [ ] Script de configuração criado (Python, Bash, etc.)
- [ ] Documentou processo de autenticação (diagrama de fluxo)

### 💡 Diferencial (Conhecimento Avançado)

**Técnicas Avançadas:**
- [ ] Configurou Multi-User Scan (admin vs usuário comum)
- [ ] Testou expiração de sessão (scan com token expirado)
- [ ] Configurou Custom Authentication Script (ZAP Scripting)
- [ ] Integrou com CI/CD (automated authenticated scan)

**Cobertura Completa:**
- [ ] Documentou matriz de permissões (quem acessa o quê)
- [ ] Testou diferentes roles (user, moderator, admin)
- [ ] Criou relatório comparativo (baseline vs authenticated)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Authenticated vs Baseline Scan**: Compreende diferença e importância de áreas logadas?
2. **ZAP Context**: Consegue configurar autenticação corretamente?
3. **Session Management**: Entende cookies, tokens, expiração?
4. **IDOR**: Identifica falhas de autorização (acesso a recursos de outros users)?
5. **Privilege Escalation**: Testa se usuário comum acessa funcionalidades admin?

### Erros Comuns

**Erro 1: "Authenticated scan não encontrou nada diferente do baseline"**
- **Causa**: Autenticação não funcionou (ZAP não conseguiu logar)
- **Feedback**: "Se scan autenticado retornou mesmos resultados que baseline, autenticação falhou. VALIDAÇÕES: 1) Verifique Logged In Indicator (regex correto?), 2) Teste login manual copiando request do ZAP, 3) Verifique logs (Menu → View → Show the ZAP log), 4) Confirme que URLs de área logada aparecem no Sites tree (ex: /profile, /basket). Se não aparecerem = ZAP não entrou. Refaça configuração seguindo passo a passo."

**Erro 2: "Session expirou no meio do scan"**
- **Causa**: Token tem TTL curto (ex: 5 minutos) e scan demora mais
- **Feedback**: "Session expirando é comum em aplicações modernas (JWT de curta duração). SOLUÇÕES: 1) Aumente TTL do token no backend (apenas ambiente de teste), 2) Configure Re-authentication no ZAP (Menu → Tools → Options → Authentication → Enable re-authentication), 3) Use ZAP Script para refresh de token (advanced), 4) Reduza escopo do scan (menos URLs = mais rápido). Meta: scan completa antes de token expirar."

**Erro 3: "Não consegui configurar Logged In Indicator"**
- **Causa**: Não sabe como identificar regex de autenticação
- **Feedback**: "Logged In Indicator é regex que aparece APENAS quando LOGADO. COMO ENCONTRAR: 1) Faça login manual na aplicação, 2) No ZAP History, encontre response do login, 3) Procure por texto único (ex: 'Welcome, user@example.com', 'Logout', token no JSON), 4) Use esse texto como regex. TESTE: Navegue logado → regex deve aparecer. Navegue deslogado → regex NÃO deve aparecer. Sem validação = falsos positivos/negativos."

**Erro 4: "Configurei autenticação mas ZAP não faz login automaticamente"**
- **Causa**: Force User Mode não habilitado OU usuário não habilitado
- **Feedback**: "Após configurar Context + User, você PRECISA: 1) Clicar direito no Context → Flag as Context, 2) Menu → Tools → Force User Mode → Enable, 3) Selecionar usuário correto. VALIDAÇÃO: Navegue para área logada manualmente no ZAP browser → deve estar logado. Sem Force User Mode = ZAP não usa autenticação automaticamente."

**Erro 5: "Identificou XSS mas não testou IDOR/privilege escalation"**
- **Causa**: Focou apenas em vulnerabilidades que ZAP detecta automaticamente
- **Feedback**: "ZAP detecta bem XSS/SQLi, mas IDOR e privilege escalation exigem TESTE MANUAL. EXERCÍCIO: 1) Como usuário ID 5, tente acessar `/api/user/1` (deveria dar 403, dá?), 2) Como usuário comum, tente acessar `/admin` (deveria dar 403, dá?), 3) Modifique `/api/order/123` para `/api/order/124` (acessa pedido de outro user?). Documente POCs. Vulnerabilidades de autorização são as MAIS CRÍTICAS em aplicações modernas."

**Erro 6: "Expôs credenciais no relatório público (GitHub)"**
- **Causa**: Commitou relatório com senha em plaintext
- **Feedback**: "⚠️ SEGURANÇA! Você expôs credenciais no relatório. NUNCA: 1) Commite senhas (mesmo de teste), 2) Inclua tokens em screenshots, 3) Compartilhe relatórios com dados sensíveis. USE: 1) .env para credenciais, 2) .gitignore para relatórios ZAP, 3) Sanitize screenshots (redact senhas/tokens). AÇÃO IMEDIATA: 1) Remova commit do histórico (git filter-branch), 2) Troque senha do usuário de teste."

### Dicas para Feedback Construtivo

**Para alunos com domínio completo:**
> "Excelente trabalho! Você demonstrou: 1) Configuração completa de authenticated scan (Context, Users, Session Management), 2) Validação de cobertura (confirmou que área logada foi escaneada), 3) Identificação de vulnerabilidades de autorização (IDOR, privilege escalation), 4) Validação manual (POCs funcionais). Seu conhecimento está no nível de Security Tester sênior. Próximo desafio: configure Multi-User Scan (admin vs user comum) e automatize com ZAP API (Exercício 2.2.4 - CI/CD integration)."

**Para alunos com dificuldades intermediárias:**
> "Boa configuração! Você conseguiu configurar Context e executar scan. Para elevar o nível: 1) VALIDE cobertura (verifique se URLs de área logada aparecem no Sites tree), 2) TESTE manualmente IDOR (modifique IDs na URL, consegue acessar dados de outros users?), 3) DOCUMENTE processo (outro QA consegue replicar seguindo sua documentação?), 4) COMPARE findings autenticado vs baseline (quais vulnerabilidades são exclusivas de área logada?). Revise seção 'Authenticated Scanning' da Aula 2.2."

**Para alunos que travaram:**
> "Authenticated scan é desafiador. Vamos simplificar: 1) Use ZAP GUI (não CLI, mais fácil visualizar), 2) Siga tutorial oficial: https://www.zaproxy.org/docs/desktop/start/features/authentication/, 3) Use Juice Shop (autenticação simples, bem documentada), 4) VALIDE em cada etapa: 4.1) Consegue logar manualmente? 4.2) Logged In Indicator correto? (teste com regex tester), 4.3) Force User Mode habilitado?, 4.4) URLs de área logada aparecem no Sites tree?. Após conseguir scan básico, agende monitoria para avançar."

### Contexto Pedagógico

**Por que este exercício é crítico:**

1. **Cobertura Completa**: 70% das vulnerabilidades críticas estão em áreas logadas (OWASP, 2023)
2. **Falhas de Autorização**: IDOR, privilege escalation são Top 1 em aplicações modernas (OWASP A01:2021)
3. **Realismo**: Aplicações reais têm autenticação; scan sem autenticação é incompleto
4. **Habilidade Profissional**: Configurar authenticated scan diferencia QA júnior de pleno/sênior
5. **Compliance**: PCI-DSS 11.3.2 exige testes de autenticação/autorização

**Conexão com o Curso:**
- **Pré-requisito**: Exercício 2.2.1 (Baseline Scan), conhecimento de autenticação (JWT, cookies, sessions)
- **Aplica conceitos**: Authenticated DAST, IDOR, Privilege Escalation, Session Management
- **Prepara para**: Exercício 2.2.3b (False Positives), Exercício 2.2.4 (DAST Report Analysis), Aula 2.3 (Pentest)
- **Integra com**: Aula 2.1 (SAST não detecta IDOR/authorization), Módulo 3 (Secure Development - autorização correta)

**Habilidades desenvolvidas:**
- Configuração avançada de DAST (Context, Authentication, Session Management)
- Identificação de falhas de autorização (IDOR, privilege escalation)
- Validação manual de exploits (POC)
- Debugging de autenticação (logs, indicators, session tokens)
- Documentação técnica de processos de segurança
- Pensamento de atacante (como bypassar controles de acesso)

**Estatísticas da Indústria:**
- 81% das aplicações web têm área autenticada (Forrester, 2024)
- 65% das vulnerabilidades High/Critical estão em área logada (Veracode, 2025)
- IDOR é #1 em bug bounty programs (HackerOne, 2025)
- Authenticated scan aumenta cobertura em 3-5x (ZAP Benchmark, 2024)

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
