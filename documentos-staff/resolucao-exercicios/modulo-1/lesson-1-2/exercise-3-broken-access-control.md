---
exercise_id: lesson-1-2-exercise-3-broken-access-control
title: "Exercício 1.2.3: Broken Access Control - Testes e Correções"
lesson_id: lesson-1-2
module: module-1
difficulty: "Intermediário"
last_updated: 2026-01-14
---

# Exercício 1.2.3: Broken Access Control - Testes e Correções

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **testes de Broken Access Control** através da **identificação de vulnerabilidades de acesso** e **implementação de controles adequados**.

### Tarefa Principal

1. Identificar vulnerabilidades de Broken Access Control em API
2. Testar controles de acesso (IDOR, privilege escalation)
3. Implementar validação de propriedade e autorização
4. Criar testes automatizados para validar controles

---

## ✅ Soluções Detalhadas

### Parte 1: Identificar Vulnerabilidades

#### Endpoint 1: IDOR (Insecure Direct Object Reference)

**Código Vulnerável:**
```python
@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # ❌ VULNERÁVEL - Não valida se usuário logado é dono do recurso
    user = db.get_user(user_id)
    return jsonify(user)
```

**Solução Esperada:**

**Vulnerabilidade Identificada**: IDOR (Insecure Direct Object Reference)

**Onde está**: Endpoint `/api/users/<user_id>` não valida propriedade do recurso

**Por que é vulnerável**:
- Permite que qualquer usuário autenticado acesse dados de outros
- Não verifica se `user_id` corresponde ao usuário logado
- Atacante pode enumerar IDs e acessar dados sensíveis

**Exemplo de Ataque:**
```bash
# Usuário 1 logado tenta acessar dados do usuário 2
GET /api/users/2
Headers: Authorization: Bearer <token_usuario_1>

# Resposta: Retorna dados do usuário 2 (vulnerabilidade!)
```

**Impacto por Contexto:**
- **Financeiro**: Acesso a dados bancários de outras pessoas → Violação PCI-DSS, LGPD
- **Educacional**: Acesso a dados de alunos → Violação LGPD (dados de menores)
- **Ecommerce**: Acesso a pedidos de outros clientes → Vazamento de dados pessoais

**Validação Técnica:**
- ✅ Identifica IDOR corretamente
- ✅ Explica impacto em diferentes contextos
- ✅ Demonstra como atacante exploraria

---

#### Endpoint 2: Privilege Escalation

**Código Vulnerável:**
```python
@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    # ❌ VULNERÁVEL - Confia em parâmetro do cliente
    is_admin = request.json.get('is_admin', False)
    
    if is_admin:
        return jsonify(db.get_all_users())
    return {'error': 'Forbidden'}, 403
```

**Solução Esperada:**

**Vulnerabilidade Identificada**: Privilege Escalation (Vertical Access Control)

**Onde está**: Endpoint `/api/admin/users` confia em parâmetro do cliente para verificar role

**Por que é vulnerável**:
- Validação de role feita no cliente (parâmetro `is_admin`)
- Atacante pode enviar `is_admin: true` e escalar privilégios
- Nunca deve confiar em validações do cliente

**Exemplo de Ataque:**
```bash
# Usuário comum tenta acessar endpoint admin
POST /api/admin/users
Headers: Authorization: Bearer <token_usuario_comum>
Body: {"is_admin": true}

# Resposta: Retorna todos os usuários (escalação de privilégio!)
```

**Impacto:**
- Acesso não autorizado a recursos administrativos
- Potencial acesso a dados de todos os usuários
- Bypass de controles de segurança críticos

**Validação Técnica:**
- ✅ Identifica privilege escalation corretamente
- ✅ Explica que não deve confiar em parâmetros do cliente
- ✅ Reconhece necessidade de validação no servidor

---

#### Endpoint 3: Horizontal Access Control

**Código Vulnerável:**
```python
@app.route('/api/accounts/<account_id>/balance', methods=['GET'])
def get_balance(account_id):
    # ❌ VULNERÁVEL - Não valida se conta pertence ao usuário
    account = db.get_account(account_id)
    return jsonify({'balance': account.balance})
```

**Solução Esperada:**

**Vulnerabilidade Identificada**: Horizontal Access Control (falta validação de relacionamento)

**Onde está**: Endpoint `/api/accounts/<account_id>/balance` não valida relacionamento conta-usuário

**Por que é vulnerável**:
- Não verifica se conta pertence ao usuário autenticado
- Atacante pode acessar saldo de outras contas
- Similar ao IDOR, mas envolve relacionamento entre entidades

**Diferença Horizontal vs Vertical:**
- **Horizontal**: Acesso a recursos do mesmo nível (outra conta de usuário comum)
- **Vertical**: Acesso a recursos de nível superior (recursos administrativos)

**Validação Técnica:**
- ✅ Identifica tipo correto de vulnerabilidade
- ✅ Diferencia horizontal vs vertical
- ✅ Explica necessidade de validar relacionamento

---

### Parte 2: Implementar Correções

#### Correção 1: Validação de Propriedade

**Solução Esperada:**

```python
@app.route('/api/users/<user_id>', methods=['GET'])
@require_auth  # Decorator que valida autenticação
def get_user(user_id):
    # Obter usuário autenticado da sessão/token
    current_user_id = session['user_id']
    
    # ✅ SEGURO - Valida propriedade
    if int(user_id) != current_user_id:
        return jsonify({'error': 'Forbidden'}), 403
    
    user = db.get_user(user_id)
    return jsonify(user)
```

**Validação Técnica:**
- ✅ Valida que `user_id` corresponde ao usuário autenticado
- ✅ Retorna 403 Forbidden quando não autorizado
- ✅ Validação feita no servidor (não no cliente)
- ✅ Usa decorator para autenticação consistente

**Variações Aceitáveis:**
- Usar JWT token em vez de sessão
- Validar UUID em vez de int
- Usar ORM para validar propriedade

---

#### Correção 2: Role-Based Access Control (RBAC)

**Solução Esperada:**

```python
from functools import wraps

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Obter usuário autenticado
        current_user = db.get_user(session['user_id'])
        
        # ✅ SEGURO - Valida role no servidor
        if not current_user or not current_user.is_admin:
            return jsonify({'error': 'Forbidden'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/admin/users', methods=['GET'])
@require_auth
@require_admin  # Decorator que valida role admin
def admin_users():
    return jsonify(db.get_all_users())
```

**Validação Técnica:**
- ✅ Role validada no servidor (nunca no cliente)
- ✅ Decorator reutilizável para endpoints admin
- ✅ Retorna 403 quando não autorizado
- ✅ Usa verificação de propriedade do banco de dados

**Variações Aceitáveis:**
- Usar biblioteca de autorização (Flask-Principal, Flask-User)
- Implementar RBAC mais complexo (múltiplas roles)
- Validar permissões específicas em vez de apenas role

---

#### Correção 3: Validação de Relacionamento

**Solução Esperada:**

```python
@app.route('/api/accounts/<account_id>/balance', methods=['GET'])
@require_auth
def get_balance(account_id):
    current_user_id = session['user_id']
    
    # ✅ SEGURO - Valida relacionamento através de join
    account = db.query(
        "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
        (account_id, current_user_id)
    ).first()
    
    if not account:
        return jsonify({'error': 'Forbidden'}), 403
    
    return jsonify({'balance': account.balance})
```

**Validação Técnica:**
- ✅ Valida relacionamento conta-usuário no SQL
- ✅ Query inclui validação de propriedade (WHERE user_id = ?)
- ✅ Retorna 403 se conta não existe ou não pertence ao usuário
- ✅ Usa prepared statements (seguro contra SQL Injection)

**Variações Aceitáveis:**
- Usar ORM para validar relacionamento: `Account.query.filter_by(id=account_id, user_id=current_user_id).first()`
- Validar em múltiplas camadas (middleware + endpoint)
- Implementar cache para melhor performance

---

### Parte 3: Criar Testes de Segurança

**Solução Esperada:**

```python
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_idor_prevention(client):
    """Testa que IDOR é prevenido"""
    
    # Login como usuário 1
    response = client.post('/api/login', json={
        'username': 'user1@example.com',
        'password': 'pass123'
    })
    token1 = response.json['token']
    
    # Tentar acessar dados do usuário 2
    response = client.get(
        '/api/users/2',
        headers={'Authorization': f'Bearer {token1}'}
    )
    
    # Deve retornar 403 Forbidden
    assert response.status_code == 403
    assert 'Forbidden' in response.json['error']
    assert 'user' not in response.json

def test_privilege_escalation_prevention(client):
    """Testa que privilege escalation é prevenido"""
    
    # Login como usuário comum
    response = client.post('/api/login', json={
        'username': 'user@example.com',
        'password': 'pass123'
    })
    token = response.json['token']
    
    # Tentar acessar endpoint admin
    response = client.get(
        '/api/admin/users',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    # Deve retornar 403 Forbidden
    assert response.status_code == 403
    assert 'Forbidden' in response.json['error']

def test_horizontal_access_control(client):
    """Testa que horizontal access control é prevenido"""
    
    # Login como usuário 1
    response = client.post('/api/login', json={
        'username': 'user1@example.com',
        'password': 'pass123'
    })
    token1 = response.json['token']
    
    # Tentar acessar conta do usuário 2
    response = client.get(
        '/api/accounts/2/balance',
        headers={'Authorization': f'Bearer {token1}'}
    )
    
    # Deve retornar 403 Forbidden
    assert response.status_code == 403
    assert 'Forbidden' in response.json['error']

def test_valid_access_still_works(client):
    """Testa que acesso válido ainda funciona"""
    
    # Login como usuário 1
    response = client.post('/api/login', json={
        'username': 'user1@example.com',
        'password': 'pass123'
    })
    token1 = response.json['token']
    
    # Acessar próprio perfil (deve funcionar)
    response = client.get(
        '/api/users/1',
        headers={'Authorization': f'Bearer {token1}'}
    )
    
    # Deve retornar 200 OK
    assert response.status_code == 200
    assert 'user' in response.json
```

**Validação Técnica:**
- ✅ Testa que IDOR é prevenido (403 para recursos de outros)
- ✅ Testa que privilege escalation é prevenido (403 para endpoints admin)
- ✅ Testa que horizontal access control é prevenido (403 para recursos relacionados)
- ✅ Testa que acesso válido ainda funciona (200 para recursos próprios)
- ✅ Testes isolados e independentes

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Identificação:**
- [ ] Identifica pelo menos 2 das 3 vulnerabilidades (IDOR, Privilege Escalation, Horizontal)
- [ ] Explica por que cada vulnerabilidade é um problema
- [ ] Demonstra como atacante exploraria

**Correção:**
- [ ] Implementa validação de propriedade para IDOR
- [ ] Implementa validação de role no servidor para Privilege Escalation
- [ ] Implementa validação de relacionamento para Horizontal Access Control

**Testes:**
- [ ] Cria testes que validam correções funcionam
- [ ] Testa que acesso não autorizado retorna 403
- [ ] Testa que acesso válido ainda funciona

### ⭐ Importantes (Recomendados para Resposta Completa)

**Identificação:**
- [ ] Identifica todas as 3 vulnerabilidades
- [ ] Diferencia horizontal vs vertical access control
- [ ] Considera impacto em diferentes contextos (financeiro, educacional, ecommerce)

**Correção:**
- [ ] Usa decorators para reutilização de validação
- [ ] Implementa validação em múltiplas camadas
- [ ] Código bem estruturado e comentado

**Testes:**
- [ ] Testes automatizados (pytest, unittest)
- [ ] Cobre múltiplos cenários (IDOR, privilege escalation, horizontal)
- [ ] Testes são claros e manuteníveis

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Correção:**
- [ ] Implementa RBAC completo (múltiplas roles, permissões granulares)
- [ ] Usa bibliotecas de autorização (Flask-Principal, Django Permissions)
- [ ] Implementa logging de tentativas de acesso não autorizado

**Testes:**
- [ ] Testes de integração completos
- [ ] Testa diferentes tipos de IDs (numérico, UUID, string)
- [ ] Valida comportamento após mudança de role

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Identificação de Broken Access Control**: Aluno consegue identificar diferentes tipos (IDOR, Privilege Escalation, Horizontal)?
2. **Compreensão de Impacto**: Aluno entende impacto em diferentes contextos?
3. **Implementação de Correções**: Aluno implementa validações adequadas?
4. **Criação de Testes**: Aluno cria testes que validam correções?

### Erros Comuns

1. **Erro: Confundir tipos de acesso**
   - **Situação**: Aluno identifica IDOR mas chama de "broken authentication"
   - **Feedback**: "Excelente identificação da vulnerabilidade! Isso é Broken Access Control - especificamente IDOR (Insecure Direct Object Reference). Broken Authentication seria problema com login/credenciais. Ambos são OWASP Top 10, mas tipos diferentes."

2. **Erro: Validação apenas no cliente**
   - **Situação**: Aluno propõe validar no frontend apenas
   - **Feedback**: "Boa ideia validar no frontend, mas isso não é suficiente! Validação deve sempre ser feita no servidor também, porque atacante pode bypassar frontend. Frontend é UX, backend é segurança."

3. **Erro: Testes não validam correção**
   - **Situação**: Aluno cria testes mas não valida que vulnerabilidade foi corrigida
   - **Feedback**: "Testes criados! Para validar que correção funciona, garanta que: 1) Tentativas de acesso não autorizado retornam 403, 2) Acesso válido ainda retorna 200. Isso confirma que correção bloqueou Broken Access Control sem quebrar funcionalidade."

### Dicas para Feedback

- ✅ **Reconheça**: Identificação correta de vulnerabilidades, uso de validação no servidor, testes criados
- ❌ **Corrija**: Validação apenas no cliente, falta de validação de relacionamento, testes incompletos
- 💡 **Incentive**: Usar decorators, implementar RBAC completo, testes de integração

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **OWASP Top 10 #1**: Broken Access Control é a vulnerabilidade #1 do OWASP Top 10 2021
2. **Habilidade Essencial**: QA de segurança precisa saber testar controles de acesso
3. **Prevenção**: Ensina best practices (validação no servidor, RBAC) que previnem vulnerabilidade
4. **Validação**: Desenvolve capacidade de criar testes de segurança

**Conexão com o Curso:**
- Aula 1.2: OWASP Top 10 - Broken Access Control (teoria) → Este exercício (prática)
- Pré-requisito para: Módulo 2 (SAST pode detectar alguns padrões, mas testes manuais são essenciais)
- Base para: Exercícios avançados de segurança (multi-layered defense, compliance)

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Identificação:**
"Endpoint 1 tem IDOR porque não valida se usuário logado é dono do recurso. Atacante pode modificar `user_id` na URL e acessar dados de outros. Endpoint 2 tem Privilege Escalation porque confia em parâmetro `is_admin` do cliente. Endpoint 3 tem Horizontal Access Control porque não valida relacionamento conta-usuário."

**Correção:**
```python
# Validação de propriedade
if int(user_id) != current_user_id:
    return jsonify({'error': 'Forbidden'}), 403

# Validação de role no servidor
if not current_user.is_admin:
    return jsonify({'error': 'Forbidden'}), 403

# Validação de relacionamento
account = db.query("SELECT * FROM accounts WHERE id = ? AND user_id = ?", ...)
```

**Testes:**
"Testei que usuário 1 não acessa dados do usuário 2 (403), usuário comum não acessa admin (403), e acesso válido ainda funciona (200). Testes automatizados validam todas as correções."

**Características da Resposta:**
- ✅ Identifica todas as 3 vulnerabilidades corretamente
- ✅ Diferencia tipos de acesso
- ✅ Implementa correções técnicas adequadas
- ✅ Testes completos e funcionais

---

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
