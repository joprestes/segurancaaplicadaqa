---
layout: exercise
title: "Exercício 1.2.1: Identificar Vulnerabilidades OWASP Top 10"
slug: "identificar-vulnerabilidades"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Básico"
permalink: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-2-exercise-1-identificar-vulnerabilidades/
lesson_url: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/owasp-top-10/
---

## Objetivo

Este exercício tem como objetivo praticar **identificação de vulnerabilidades** do OWASP Top 10 através da **análise de código vulnerável**.

Ao completar este exercício, você será capaz de:

- Identificar vulnerabilidades do OWASP Top 10 em código
- Reconhecer padrões de código inseguro
- Entender como vulnerabilidades se manifestam no código
- Aplicar conhecimento teórico em análise prática

---

## Descrição

Você precisa analisar trechos de código e identificar quais vulnerabilidades do OWASP Top 10 estão presentes em cada um.

### Contexto

Como QA de segurança, uma das habilidades mais importantes é identificar vulnerabilidades em código. Este exercício desenvolve essa capacidade através da análise de exemplos práticos.

### Tarefa

Para cada trecho de código abaixo, identifique:
1. Qual vulnerabilidade do OWASP Top 10 está presente
2. Por que o código é vulnerável
3. Como um atacante poderia explorar essa vulnerabilidade

---

## Requisitos

### Código 1: Autenticação

```python
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = db.execute(query)
    
    if user:
        return {'token': 'abc123'}
    return {'error': 'Invalid credentials'}, 401
```

**Tarefas**:
- [ ] Identificar a vulnerabilidade presente
- [ ] Explicar como um atacante poderia explorar
- [ ] Propor uma correção segura

---

### Código 2: Acesso a Recursos

```python
@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    user = db.get_user(user_id)
    return jsonify(user)
```

**Tarefas**:
- [ ] Identificar a vulnerabilidade presente
- [ ] Explicar o risco em diferentes contextos (financeiro, educacional)
- [ ] Propor uma correção segura

---

### Código 3: Upload de Arquivo

```python
@app.route('/api/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    filename = file.filename
    
    # Salva arquivo sem validação
    file.save(f'/uploads/{filename}')
    
    return {'success': True, 'file': filename}
```

**Tarefas**:
- [ ] Identificar possíveis vulnerabilidades
- [ ] Explicar os riscos de segurança
- [ ] Propor validações de segurança

---

### Código 4: Consulta de Dados

```python
@app.route('/api/search', methods=['POST'])
def search():
    query = request.json['query']
    
    # Busca em MongoDB sem validação
    results = db.users.find({
        'name': query,
        'email': query
    })
    
    return jsonify(list(results))
```

**Tarefas**:
- [ ] Identificar a vulnerabilidade presente
- [ ] Explicar como funciona o ataque
- [ ] Propor uma correção segura

---

### Código 5: Mensagens de Erro

```python
@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = db.get_user(user_id)
        return jsonify(user)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500
```

**Tarefas**:
- [ ] Identificar a vulnerabilidade presente
- [ ] Explicar quais informações são expostas
- [ ] Propor uma correção segura

---

## Soluções Esperadas

### Código 1: SQL Injection
- **Vulnerabilidade**: Injection (SQL Injection)
- **Exploração**: `username = "admin' OR '1'='1' --"`
- **Correção**: Usar prepared statements

### Código 2: Broken Access Control
- **Vulnerabilidade**: Broken Access Control (IDOR)
- **Exploração**: Acessar dados de outros usuários modificando user_id
- **Correção**: Validar propriedade do recurso

### Código 3: Múltiplas Vulnerabilidades
- **Vulnerabilidades**: Path Traversal, Upload inseguro
- **Exploração**: `filename = "../../etc/passwd"`
- **Correção**: Validar e sanitizar nome de arquivo

### Código 4: NoSQL Injection
- **Vulnerabilidade**: Injection (NoSQL Injection)
- **Exploração**: `query = {"$ne": null}`
- **Correção**: Validar e sanitizar entrada

### Código 5: Security Misconfiguration
- **Vulnerabilidade**: Security Misconfiguration
- **Exploração**: Stack trace expõe estrutura interna
- **Correção**: Mensagens genéricas em produção

---

## Dicas

1. **Analise linha por linha**: Cada linha pode conter uma vulnerabilidade
2. **Pense como atacante**: Como você exploraria esse código?
3. **Contexto importa**: Considere o contexto da aplicação (financeiro, educacional, etc.)
4. **Múltiplas vulnerabilidades**: Um código pode ter várias vulnerabilidades

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.2.2: SQL Injection na Prática
- Exercício 1.2.3: Prevenção de XSS
- Aplicar conhecimento em testes reais de segurança

---

**Duração Estimada**: 30-45 minutos  
**Nível**: Básico  
**Pré-requisitos**: Aula 1.2 (OWASP Top 10)
