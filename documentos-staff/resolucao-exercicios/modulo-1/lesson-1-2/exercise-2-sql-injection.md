---
exercise_id: lesson-1-2-exercise-2-sql-injection
title: "Exercício 1.2.2: SQL Injection - Exploração e Prevenção"
lesson_id: lesson-1-2
module: module-1
difficulty: "Intermediário"
last_updated: 2025-01-15
---

# Exercício 1.2.2: SQL Injection - Exploração e Prevenção

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **SQL Injection** através da **exploração de vulnerabilidades** e **implementação de correções**.

### Tarefa Principal

1. Identificar vulnerabilidade de SQL Injection em código fornecido
2. Explorar vulnerabilidade em ambiente controlado
3. Implementar correção usando prepared statements
4. Criar testes para validar correções

---

## ✅ Soluções Detalhadas

### Parte 1: Identificar Vulnerabilidade

**Código Vulnerável:**

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

**Solução Esperada:**

**Vulnerabilidade Identificada**: SQL Injection na linha 67

**Onde está**: Na construção da query SQL usando f-string/f-formatting (`f"SELECT * FROM users WHERE username = '{username}'..."`)

**Por que é vulnerável**:
- Concatenação de entrada do usuário diretamente na query SQL
- Permite que atacante injete código SQL malicioso
- Não há validação ou sanitização da entrada

**Validação Técnica:**
- ✅ Identifica linha específica com vulnerabilidade (linha 67)
- ✅ Explica uso de f-string/concatenação
- ✅ Reconhece falta de sanitização

---

### Parte 2: Explorar Vulnerabilidade

**Solução Esperada:**

**Payload 1: Bypass de Autenticação com OR**
```json
{
  "username": "admin' OR '1'='1' --",
  "password": "qualquer"
}
```

**Resultado**: Query se torna:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'qualquer'
```

- `'1'='1'` sempre é verdadeiro → bypass de autenticação
- `--` comenta o resto da query → ignora validação de senha

**Payload 2: Bypass com Comentário Hash**
```json
{
  "username": "admin' OR '1'='1' #",
  "password": "qualquer"
}
```

**Resultado**: Similar ao payload 1, mas usa `#` para comentar (MySQL)

**Payload 3: Union-based Injection (para extrair dados)**
```json
{
  "username": "admin' UNION SELECT username, password FROM users --",
  "password": "qualquer"
}
```

**Resultado**: Combina resultados de múltiplas queries, podendo extrair todos os usuários/senhas

**Validação Técnica:**
- ✅ Pelo menos 2 payloads diferentes documentados
- ✅ Explicação de como cada payload funciona
- ✅ Query SQL resultante mostrada
- ✅ Resultado esperado documentado

**Variações Aceitáveis:**
- `admin' OR 'x'='x' --` (similar ao `'1'='1'`)
- `' OR 1=1 --` (sem username específico)
- `admin'--` (apenas comentando senha)

---

### Parte 3: Implementar Correção

**Solução Esperada:**

```python
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Validação de entrada
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Validação adicional: username deve ser alfanumérico básico
    if not username.isalnum() or len(username) > 50:
        return jsonify({'error': 'Invalid username format'}), 400
    
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

**Validação Técnica:**
- ✅ Usa prepared statement com placeholders (`?`)
- ✅ Passa parâmetros como tupla separada da query
- ✅ Validação de entrada antes de usar na query
- ✅ Tratamento de erros adequado

**Variações Aceitáveis:**

**Opção 1: Usando ORM (SQLAlchemy)**
```python
from models import User

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username, password=password).first()
    
    if user:
        return jsonify({'success': True, 'user': user.username})
    return jsonify({'error': 'Invalid credentials'}), 401
```

**Opção 2: Usando Django ORM**
```python
from django.contrib.auth import authenticate

def login(request):
    username = request.POST['username']
    password = request.POST['password']
    
    user = authenticate(username=username, password=password)
    if user:
        return JsonResponse({'success': True, 'user': user.username})
    return JsonResponse({'error': 'Invalid credentials'}, status=401)
```

**Pontos Adicionais a Observar:**
- ⚠️ Senha ainda está em texto plano (não é foco deste exercício, mas é problema de segurança)
- ⚠️ Falta rate limiting (permite brute force)
- ✅ Prepared statements previnem SQL Injection

---

### Parte 4: Criar Testes de Segurança

**Solução Esperada:**

```python
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_sql_injection_prevention(client):
    """Testa que SQL Injection não funciona após correção"""
    
    # Payloads maliciosos
    malicious_payloads = [
        "admin' OR '1'='1' --",
        "admin' OR '1'='1' #",
        "admin' UNION SELECT * FROM users --",
        "'; DROP TABLE users; --",
        "' OR 'x'='x",
        "admin'--",
        "' OR 1=1--"
    ]
    
    for payload in malicious_payloads:
        response = client.post('/api/login', json={
            'username': payload,
            'password': 'qualquer'
        })
        
        # Deve retornar erro, não sucesso
        assert response.status_code == 401, f"Payload '{payload}' não foi bloqueado"
        assert 'success' not in response.json, f"Payload '{payload' causou bypass"
        assert 'error' in response.json, f"Resposta inválida para payload '{payload}'"

def test_valid_login_still_works(client):
    """Testa que login válido ainda funciona após correção"""
    
    # Assumindo que existe usuário de teste
    response = client.post('/api/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    # Se usuário existe, deve funcionar
    # Se não existe, deve retornar 401 (mas não deve causar erro SQL)
    assert response.status_code in [200, 401]
    if response.status_code == 200:
        assert 'success' in response.json
    else:
        assert 'error' in response.json
```

**Validação Técnica:**
- ✅ Testa múltiplos payloads maliciosos (mínimo 5-7)
- ✅ Valida que vulnerabilidade foi corrigida (401 em vez de 200)
- ✅ Testa casos válidos ainda funcionam
- ✅ Assertions claras e descritivas
- ✅ Teste isolado (não depende de estado anterior)

**Variações Aceitáveis:**
- Usar unittest em vez de pytest
- Testes manuais documentados (se ambiente não permite automação)
- Usar ferramentas (Burp Suite, OWASP ZAP) para testes manuais

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Identificação:**
- [ ] Identifica corretamente onde está a vulnerabilidade (linha/comentário)
- [ ] Explica por que é vulnerável (concatenação, falta de sanitização)

**Exploração:**
- [ ] Cria pelo menos 2 payloads diferentes de SQL Injection
- [ ] Documenta como cada payload funciona
- [ ] Testa payloads e documenta resultados

**Correção:**
- [ ] Implementa correção usando prepared statements
- [ ] Valida entrada antes de usar na query
- [ ] Código corrigido é funcional

**Testes:**
- [ ] Cria testes que tentam SQL Injection
- [ ] Valida que vulnerabilidade foi corrigida (payloads falham)
- [ ] Testa que casos válidos ainda funcionam

### ⭐ Importantes (Recomendados para Resposta Completa)

**Exploração:**
- [ ] Testa múltiplos tipos de payloads (OR bypass, Union, Comment)
- [ ] Captura requisições usando ferramentas (Burp Suite, OWASP ZAP)
- [ ] Documenta query SQL resultante para cada payload

**Correção:**
- [ ] Implementa validação adicional de entrada
- [ ] Tratamento de erros adequado
- [ ] Código bem estruturado e comentado

**Testes:**
- [ ] Testes automatizados (pytest, unittest)
- [ ] Cobre múltiplos cenários (payloads diferentes, casos válidos)
- [ ] Testes são claros e manuteníveis

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Correção:**
- [ ] Usa ORM (SQLAlchemy, Django ORM) em vez de SQL direto
- [ ] Implementa validação robusta (regex, whitelist)
- [ ] Considera outros aspectos de segurança (hash de senha, rate limiting)

**Testes:**
- [ ] Testes de integração completos
- [ ] Usa ferramentas de segurança (Semgrep, Bandit) para validar código
- [ ] Documenta métricas de segurança (tempo de resposta, cobertura)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Identificação de Vulnerabilidade**: Aluno consegue identificar SQL Injection no código?
2. **Compreensão de Exploração**: Aluno entende como criar payloads maliciosos?
3. **Implementação de Correção**: Aluno sabe usar prepared statements corretamente?
4. **Validação de Correção**: Aluno cria testes para validar que correção funciona?

### Erros Comuns

1. **Erro: Usar prepared statement incorretamente**
   - **Situação**: Aluno usa f-string com placeholder: `f"SELECT * FROM users WHERE username = ?"`
   - **Feedback**: "Ótima tentativa! Mas lembre-se: prepared statements só funcionam quando você passa os parâmetros separados da query. Use `cursor.execute(query, (username, password))` em vez de f-string."

2. **Erro: Não validar entrada**
   - **Situação**: Aluno implementa prepared statement mas não valida entrada
   - **Feedback**: "Excelente correção com prepared statements! Para tornar ainda mais seguro, considere validar a entrada antes: verificar se username/password não estão vazios, têm formato válido, tamanho máximo. Isso defende em profundidade."

3. **Erro: Payloads não funcionam em teste**
   - **Situação**: Aluno cria payloads mas não testa ou testa incorretamente
   - **Feedback**: "Bons payloads documentados! Para garantir que funcionam, teste cada um deles: faça requisição POST para `/api/login` com payload JSON. Verifique se antes da correção retorna 200 (bypass) e depois retorna 401 (bloqueado)."

4. **Erro: Testes não validam correção**
   - **Situação**: Aluno cria testes mas não valida que vulnerabilidade foi corrigida
   - **Feedback**: "Testes criados! Para validar que a correção funciona, garanta que: 1) Payloads maliciosos retornam 401 (não 200), 2) Casos válidos ainda funcionam. Isso confirma que correção bloqueou SQL Injection sem quebrar funcionalidade."

### Dicas para Feedback

- ✅ **Reconheça**: Identificação correta da vulnerabilidade, uso de prepared statements, testes criados
- ❌ **Corrija**: Uso incorreto de prepared statements, falta de validação, testes incompletos
- 💡 **Incentive**: Usar ORM, validação robusta, testes de integração, ferramentas de segurança

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Prática Real**: SQL Injection é vulnerabilidade #1 no OWASP Top 10
2. **Habilidade Essencial**: QA de segurança precisa saber identificar, explorar e validar correções
3. **Prevenção**: Ensina best practices (prepared statements) que previnem vulnerabilidade
4. **Validação**: Desenvolve capacidade de criar testes de segurança

**Conexão com o Curso:**
- Aula 1.2: OWASP Top 10 - Injection (teoria) → Este exercício (prática)
- Pré-requisito para: Módulo 2 (SAST detecta SQL Injection automaticamente)
- Base para: Exercícios avançados de segurança (multi-layered defense)

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Identificação:**
"Vulnerabilidade de SQL Injection na linha 67, onde a query é construída usando f-string: `query = f\"SELECT * FROM users WHERE username = '{username}'...\"`. Isso permite que atacante injete código SQL, pois a entrada do usuário é concatenada diretamente na query sem sanitização."

**Exploração:**
"Payload 1: `admin' OR '1'='1' --` - Faz bypass de autenticação porque '1'='1' sempre é verdadeiro e -- comenta o resto. Payload 2: `admin' UNION SELECT * FROM users --` - Extrai todos os usuários combinando resultados de múltiplas queries."

**Correção:**
```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))
```
"Usa prepared statements com placeholders (?) e passa parâmetros separadamente. Isso previne SQL Injection porque o banco trata parâmetros como dados, não código."

**Testes:**
"Testei 7 payloads maliciosos e todos retornaram 401 após correção. Testes automatizados com pytest validam que vulnerabilidade foi corrigida sem quebrar login válido."

**Características da Resposta:**
- ✅ Identifica vulnerabilidade com precisão
- ✅ Múltiplos payloads documentados e testados
- ✅ Correção técnica correta (prepared statements)
- ✅ Testes automatizados criados e funcionando

### Exemplo 2: Resposta Boa (Adequada)

**Identificação:**
"SQL Injection porque concatena strings na query SQL."

**Exploração:**
"Payload: `admin' OR '1'='1' --` funciona para bypass de autenticação."

**Correção:**
"Usar prepared statements com `?` em vez de f-string."

**Testes:**
"Criei testes manuais e confirmei que payloads não funcionam mais."

**Características da Resposta:**
- ✅ Identifica vulnerabilidade corretamente
- ✅ Propõe correção adequada
- ✅ Testa correção
- ⚠️ Poderia ser mais detalhado (mas está correto)

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
