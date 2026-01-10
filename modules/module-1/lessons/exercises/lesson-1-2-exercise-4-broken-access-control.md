---
layout: exercise
title: "Exercício 1.2.4: Broken Access Control - Testes e Correções"
slug: "broken-access-control"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Intermediário"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-2-exercise-4-broken-access-control/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/owasp-top-10/
---

## Objetivo

Este exercício tem como objetivo praticar **testes de Broken Access Control** através da **identificação de vulnerabilidades de acesso** e **implementação de controles adequados**.

Ao completar este exercício, você será capaz de:

- Identificar vulnerabilidades de Broken Access Control
- Testar controles de acesso (IDOR, privilege escalation)
- Implementar validação de propriedade e autorização
- Criar testes automatizados para validar controles

---

## Descrição

Você precisa identificar e corrigir vulnerabilidades de Broken Access Control em uma API de exemplo.

### Contexto

Broken Access Control é a vulnerabilidade #1 do OWASP Top 10 2021. Como QA de segurança, você precisa saber testar controles de acesso e garantir que usuários só acessem recursos autorizados.

---

## Requisitos

### Parte 1: Identificar Vulnerabilidades

Analise os seguintes endpoints e identifique vulnerabilidades:

#### Endpoint 1: IDOR (Insecure Direct Object Reference)

```python
@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # ❌ VULNERÁVEL - Não valida se usuário logado é dono do recurso
    user = db.get_user(user_id)
    return jsonify(user)
```

**Tarefas**:
- [ ] Identificar a vulnerabilidade (IDOR)
- [ ] Criar teste que explora a vulnerabilidade
- [ ] Explicar o impacto em diferentes contextos
- [ ] Propor correção

#### Endpoint 2: Privilege Escalation

```python
@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    # ❌ VULNERÁVEL - Confia em parâmetro do cliente
    is_admin = request.json.get('is_admin', False)
    
    if is_admin:
        return jsonify(db.get_all_users())
    return {'error': 'Forbidden'}, 403
```

**Tarefas**:
- [ ] Identificar a vulnerabilidade (privilege escalation)
- [ ] Criar teste que explora a vulnerabilidade
- [ ] Explicar o risco
- [ ] Propor correção

#### Endpoint 3: Horizontal Access Control

```python
@app.route('/api/accounts/<account_id>/balance', methods=['GET'])
def get_balance(account_id):
    # ❌ VULNERÁVEL - Não valida se conta pertence ao usuário
    account = db.get_account(account_id)
    return jsonify({'balance': account.balance})
```

**Tarefas**:
- [ ] Identificar tipo de vulnerabilidade
- [ ] Diferenciar horizontal vs vertical access control
- [ ] Criar teste de exploração
- [ ] Propor correção

---

### Parte 2: Implementar Correções

Implemente controles de acesso adequados:

#### Correção 1: Validação de Propriedade

**Tarefas**:
- [ ] Implementar validação de propriedade
- [ ] Verificar se usuário logado é dono do recurso
- [ ] Retornar 403 Forbidden quando não autorizado
- [ ] Testar que correção funciona

**Código de Referência**:
```python
@app.route('/api/users/<user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    current_user_id = session['user_id']
    
    # ✅ SEGURO - Valida propriedade
    if int(user_id) != current_user_id:
        return jsonify({'error': 'Forbidden'}), 403
    
    user = db.get_user(user_id)
    return jsonify(user)
```

#### Correção 2: Role-Based Access Control (RBAC)

**Tarefas**:
- [ ] Implementar verificação de roles
- [ ] Validar role no servidor (nunca confiar no cliente)
- [ ] Criar decorator para verificar admin
- [ ] Testar que apenas admins acessam

**Código de Referência**:
```python
from functools import wraps

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = db.get_user(session['user_id'])
        
        # ✅ SEGURO - Valida role no servidor
        if not current_user or not current_user.is_admin:
            return jsonify({'error': 'Forbidden'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/admin/users', methods=['GET'])
@require_auth
@require_admin
def admin_users():
    return jsonify(db.get_all_users())
```

#### Correção 3: Validação de Relacionamento

**Tarefas**:
- [ ] Implementar validação de relacionamento
- [ ] Verificar se recurso pertence ao usuário através de relacionamento
- [ ] Usar joins para validar propriedade
- [ ] Testar diferentes cenários

**Código de Referência**:
```python
@app.route('/api/accounts/<account_id>/balance', methods=['GET'])
@require_auth
def get_balance(account_id):
    current_user_id = session['user_id']
    
    # ✅ SEGURO - Valida relacionamento
    account = db.get_account_with_user(account_id)
    
    if not account or account.user_id != current_user_id:
        return jsonify({'error': 'Forbidden'}), 403
    
    return jsonify({'balance': account.balance})
```

---

### Parte 3: Criar Testes de Segurança

Crie testes automatizados para validar controles de acesso:

**Tarefas**:
- [ ] Criar testes para IDOR
- [ ] Testar privilege escalation
- [ ] Validar que usuários não acessam recursos de outros
- [ ] Testar diferentes roles e permissões

**Exemplo de Teste**:
```python
import pytest

def test_idor_prevention():
    """Testa que IDOR é prevenido"""
    
    # Login como usuário 1
    token1 = login_user('user1@example.com', 'pass123')
    
    # Tentar acessar dados do usuário 2
    response = client.get(
        '/api/users/2',
        headers={'Authorization': f'Bearer {token1}'}
    )
    
    # Deve retornar 403 Forbidden
    assert response.status_code == 403
    assert 'Forbidden' in response.json['error']

def test_privilege_escalation_prevention():
    """Testa que privilege escalation é prevenido"""
    
    # Login como usuário comum
    token = login_user('user@example.com', 'pass123')
    
    # Tentar acessar endpoint admin
    response = client.get(
        '/api/admin/users',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    # Deve retornar 403 Forbidden
    assert response.status_code == 403
```

---

## Contexto CWI

> **Nota**: O exemplo abaixo é um cenário hipotético criado para fins educacionais.

### Exemplo Hipotético: Projeto Financeiro

Em um projeto financeiro hipotético, poderíamos identificar Broken Access Control em endpoints de consulta de extratos. Usuários conseguiriam acessar extratos de outras contas modificando o ID da conta na URL.

**Impacto**:
- Potencial acesso a dados bancários de outras pessoas
- Violação de PCI-DSS
- Risco de fraude e vazamento de dados

**Correção Implementada**:
- Validação de propriedade em todos os endpoints sensíveis
- Verificação de relacionamento conta-usuário
- Testes automatizados de segurança
- Auditoria de acesso

**Lição Aprendida**:
- Sempre validar propriedade no servidor
- Nunca confiar em validações apenas no cliente
- Testes de acesso devem ser parte do processo
- Logging de tentativas de acesso não autorizado

---

## Checklist de Testes

Use este checklist para testar controles de acesso:

### Testes Básicos
- [ ] Usuário não acessa recursos de outros usuários (IDOR)
- [ ] Usuário comum não acessa recursos administrativos
- [ ] Usuário não modifica recursos de outros
- [ ] Usuário não deleta recursos de outros

### Testes Avançados
- [ ] Validação funciona com diferentes tipos de IDs (numérico, UUID, string)
- [ ] Controles funcionam após mudança de role
- [ ] Sessões invalidadas não permitem acesso
- [ ] Rate limiting não permite bypass de controles

### Testes por Contexto
- [ ] **Financeiro**: Contas isoladas entre usuários
- [ ] **Educacional**: Dados de alunos isolados entre turmas
- [ ] **Ecommerce**: Pedidos isolados entre clientes

---

## Dicas

1. **Pense como atacante**: Como você exploraria esses endpoints?
2. **Teste diferentes IDs**: Numéricos, UUIDs, strings
3. **Valide relacionamentos**: Não apenas propriedade direta
4. **Use ferramentas**: Burp Suite, OWASP ZAP ajudam nos testes
5. **Documente testes**: Crie casos de teste reutilizáveis

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.2.5: OWASP Checklist Completo
- Aplicar conhecimento em testes reais de aplicações
- Criar testes automatizados de segurança

---


{% include exercise-submission-form.html %}

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Exercício 1.2.3 (XSS Prevenção)
