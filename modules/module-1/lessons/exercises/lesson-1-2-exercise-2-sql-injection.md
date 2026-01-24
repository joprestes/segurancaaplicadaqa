---
layout: exercise
title: "Exercício 1.2.2: SQL Injection - Exploração e Prevenção"
slug: "sql-injection"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Intermediário"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-2-exercise-2-sql-injection/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/owasp-top-10/
---

## Objetivo

Este exercício tem como objetivo praticar **SQL Injection** através da **exploração de vulnerabilidades** e **implementação de correções**.

Ao completar este exercício, você será capaz de:

- Identificar vulnerabilidades de SQL Injection
- Explorar SQL Injection em ambiente controlado
- Implementar correções usando prepared statements
- Criar testes para validar correções

---

## Descrição

Você precisa explorar uma vulnerabilidade de SQL Injection em uma aplicação de exemplo e depois implementar a correção.

### Contexto

SQL Injection é uma das vulnerabilidades mais comuns e críticas. Como QA de segurança, você precisa saber identificá-la, explorá-la (em ambientes controlados) e validar correções.

### Ambiente de Teste

Use uma das seguintes opções:
- **OWASP WebGoat**: Módulo "SQL Injection (Intro)"
- **DVWA**: Nível "Low" de SQL Injection
- **Aplicação própria**: Crie uma API simples com vulnerabilidade

---

## Requisitos

### Parte 1: Identificar Vulnerabilidade

Analise o seguinte código:

```python
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('users.db')
    return conn

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    
    conn = get_db()
    cursor = conn.cursor()
    
    # ❌ VULNERÁVEL - Concatenação de strings
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({'success': True, 'user': user[1]})
    return jsonify({'error': 'Invalid credentials'}), 401
```

**Tarefas**:
- [ ] Identificar onde está a vulnerabilidade
- [ ] Explicar por que é vulnerável
- [ ] Documentar como um atacante exploraria

---

### Parte 2: Explorar Vulnerabilidade

**Tarefas**:
- [ ] Criar payloads de SQL Injection para bypass de autenticação
- [ ] Testar diferentes técnicas:
  - Bypass com `OR '1'='1'`
  - Comentários SQL (`--`, `#`)
  - Union-based injection
- [ ] Documentar payloads que funcionaram
- [ ] Capturar requisições usando Burp Suite ou OWASP ZAP

**Exemplo de Payloads para Testar**:
```json
{"username": "admin' OR '1'='1' --", "password": "qualquer"}
{"username": "admin' OR '1'='1' #", "password": "qualquer"}
{"username": "admin' UNION SELECT * FROM users --", "password": "qualquer"}
```

---

### Parte 3: Implementar Correção

Implemente a correção usando prepared statements:

**Tarefas**:
- [ ] Reescrever função de login usando prepared statements
- [ ] Validar entrada antes de usar na query
- [ ] Implementar tratamento de erros adequado
- [ ] Testar que payloads maliciosos não funcionam mais

**Código de Referência**:
```python
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    
    # Validação de entrada
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # ✅ SEGURO - Prepared statement
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({'success': True, 'user': user[1]})
    return jsonify({'error': 'Invalid credentials'}), 401
```

---

### Parte 4: Criar Testes de Segurança

Crie testes automatizados para validar a correção:

**Tarefas**:
- [ ] Criar testes que tentam SQL Injection
- [ ] Validar que vulnerabilidade foi corrigida
- [ ] Testar casos válidos ainda funcionam
- [ ] Documentar resultados

**Exemplo de Teste**:
```python
import pytest

def test_sql_injection_prevention():
    """Testa que SQL Injection não funciona após correção"""
    
    # Payloads maliciosos
    malicious_payloads = [
        "admin' OR '1'='1' --",
        "admin' OR '1'='1' #",
        "admin' UNION SELECT * FROM users --",
        "'; DROP TABLE users; --"
    ]
    
    for payload in malicious_payloads:
        response = client.post('/api/login', json={
            'username': payload,
            'password': 'qualquer'
        })
        
        # Deve retornar erro, não sucesso
        assert response.status_code == 401
        assert 'success' not in response.json
```

---

## Contexto CWI

> **Nota**: O exemplo abaixo é um cenário hipotético criado para fins educacionais.

### Exemplo Hipotético: Projeto Financeiro

Em um projeto financeiro hipotético, poderíamos identificar SQL Injection em endpoint de consulta de extratos. O endpoint construiria queries SQL concatenando strings com dados do usuário.

**Impacto**:
- Potencial acesso a dados bancários de 500k+ usuários
- Violação de PCI-DSS
- Risco de fraude

**Correção Implementada**:
- Migração para prepared statements em todos os endpoints
- Validação rigorosa de entrada
- Testes automatizados de segurança

**Lição Aprendida**:
- Nunca confiar em entrada do usuário
- Sempre usar prepared statements
- Testes de segurança devem ser parte do processo

---

## Checklist de Validação

- [ ] Vulnerabilidade identificada corretamente
- [ ] Payloads de ataque documentados
- [ ] Correção implementada com prepared statements
- [ ] Testes de segurança criados e passando
- [ ] Casos válidos ainda funcionam
- [ ] Documentação completa

---

## Dicas

1. **Use ambiente isolado**: Nunca teste em produção ou dados reais
2. **Documente tudo**: Payloads, resultados, correções
3. **Teste casos válidos**: Garanta que correção não quebra funcionalidade
4. **Use ferramentas**: Burp Suite, OWASP ZAP ajudam na exploração

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.2.3: Broken Access Control
- Exercício 1.2.4: Checklist OWASP Top 10
- Aplicar conhecimento em testes reais de aplicações

---


{% include exercise-submission-form.html %}

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Exercício 1.2.1 (Identificar Vulnerabilidades)
