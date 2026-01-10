---
exercise_id: lesson-1-2-exercise-1-identificar-vulnerabilidades
title: "Exercício 1.2.1: Identificar Vulnerabilidades OWASP Top 10"
lesson_id: lesson-1-2
module: module-1
difficulty: "Básico"
last_updated: 2025-01-09
---

# Exercício 1.2.1: Identificar Vulnerabilidades OWASP Top 10

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **identificação de vulnerabilidades** do OWASP Top 10 através da **análise de código vulnerável**.

### Tarefa

Para cada trecho de código abaixo, identifique:
1. Qual vulnerabilidade do OWASP Top 10 está presente
2. Por que o código é vulnerável
3. Como um atacante poderia explorar essa vulnerabilidade

---

## ✅ Soluções Detalhadas

### Código 1: Autenticação

**Vulnerabilidade**: **Injection (SQL Injection)**

**Exploração Detalhada:**
O código utiliza concatenação de strings para construir a query SQL. Um atacante pode inserir código SQL malicioso no campo `username`:

```python
# Payload malicioso:
username = "admin' OR '1'='1' --"
password = "qualquer"

# Query resultante:
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'qualquer'
```

A parte `--` comenta o resto da query, fazendo com que a condição `'1'='1'` seja sempre verdadeira, permitindo login sem senha.

**Correção Segura:**
```python
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    
    # Usar prepared statement com placeholders
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    user = db.execute(query, (username, password))
    
    if user:
        return {'token': 'abc123'}
    return {'error': 'Invalid credentials'}, 401
```

**Variações Aceitáveis:**
- Usar ORM (SQLAlchemy, Django ORM) que já implementam prepared statements
- Usar bibliotecas específicas de validação e sanitização
- Implementar hash de senha (bcrypt, Argon2) - esse código também armazena senha em texto plano

**Pontos Adicionais a Observar:**
- ❌ Senha em texto plano no banco (não é SQL Injection, mas é grave)
- ❌ Token fixo `'abc123'` (problema de segurança adicional)
- ⚠️ Falta de rate limiting (permite brute force)

---

### Código 2: Acesso a Recursos

**Vulnerabilidade**: **Broken Access Control (IDOR - Insecure Direct Object Reference)**

**Exploração Detalhada:**
O código não valida se o usuário autenticado tem permissão para acessar o recurso solicitado. Um atacante pode:

1. Acessar dados de outros usuários modificando o `user_id` na URL
2. Enumerar todos os usuários tentando IDs sequenciais (1, 2, 3, ...)
3. Acessar recursos administrativos se souber IDs de administradores

**Exemplo de Ataque:**
```python
# Requisição legítima
GET /api/users/123  # Acessa próprio perfil

# Ataque IDOR
GET /api/users/456  # Acessa perfil de outro usuário sem permissão
GET /api/users/1    # Tenta acessar conta administrativa
```

**Correção Segura:**
```python
@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # Obter usuário autenticado da sessão/token
    authenticated_user_id = get_current_user_id()
    
    # Validar que o usuário só pode acessar seu próprio perfil
    if str(user_id) != str(authenticated_user_id):
        return {'error': 'Forbidden'}, 403
    
    user = db.get_user(user_id)
    
    # Sanitizar dados sensíveis antes de retornar
    user_sanitized = {
        'id': user['id'],
        'name': user['name'],
        'email': user['email']  # Considerar se email deve ser público
        # Não retornar: senha, tokens, dados sensíveis
    }
    
    return jsonify(user_sanitized)
```

**Contextos de Risco:**
- **Financeiro**: Acesso a dados bancários de outros clientes (violação PCI-DSS)
- **Educacional**: Acesso a notas e informações pessoais de outros alunos (violação LGPD)
- **E-commerce**: Acesso a histórico de compras e dados pessoais de outros clientes

**Variações Aceitáveis:**
- Implementar Role-Based Access Control (RBAC) para recursos compartilhados
- Usar tokens JWT com informações de permissão
- Implementar filtros de acesso baseados em relacionamentos (ex: apenas contatos)

---

### Código 3: Upload de Arquivo

**Vulnerabilidades**: **Múltiplas - Path Traversal e Upload Inseguro**

**Exploração 1 - Path Traversal:**
```python
# Payload malicioso:
filename = "../../../etc/passwd"

# Resultado:
file.save('/uploads/../../../etc/passwd')
# Arquivo salvo em /etc/passwd (fora do diretório de uploads)
```

**Exploração 2 - Upload de Script Executável:**
```python
# Payload malicioso:
filename = "malware.php"
# Conteúdo: <?php system($_GET['cmd']); ?>

# Se uploads estiverem acessíveis via web:
http://site.com/uploads/malware.php?cmd=rm -rf /
```

**Exploração 3 - Sobrescrita de Arquivos Importantes:**
```python
# Payload malicioso:
filename = "../../config/database.py"

# Sobrescreve configuração do banco de dados
```

**Correção Segura:**
```python
import os
import hashlib
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt', 'md'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {'error': 'No file provided'}, 400
    
    file = request.files['file']
    
    # Validar que arquivo foi selecionado
    if file.filename == '':
        return {'error': 'No file selected'}, 400
    
    # Validar tipo de arquivo
    if not allowed_file(file.filename):
        return {'error': 'File type not allowed'}, 400
    
    # Validar tamanho
    if file.content_length > MAX_FILE_SIZE:
        return {'error': 'File too large'}, 400
    
    # Sanitizar nome do arquivo
    original_filename = secure_filename(file.filename)
    
    # Gerar nome único para evitar sobrescrita
    file_hash = hashlib.md5(file.read()).hexdigest()
    file.seek(0)  # Voltar ao início do arquivo
    
    # Extrair extensão
    file_ext = original_filename.rsplit('.', 1)[1].lower()
    
    # Novo nome: hash + extensão (impossível prever)
    safe_filename = f"{file_hash}.{file_ext}"
    
    # Caminho absoluto seguro (dentro de uploads/)
    upload_path = os.path.join('/uploads', safe_filename)
    
    # Garantir que caminho está dentro de uploads/ (prevenir path traversal)
    upload_dir = os.path.abspath('/uploads')
    file_path = os.path.abspath(upload_path)
    
    if not file_path.startswith(upload_dir):
        return {'error': 'Invalid file path'}, 400
    
    # Salvar arquivo
    file.save(file_path)
    
    # Opcional: Escanear arquivo com antivírus
    # scan_file(file_path)
    
    return {'success': True, 'file': safe_filename}
```

**Validações Adicionais Recomendadas:**
- ✅ Validar conteúdo real do arquivo (magic bytes) além da extensão
- ✅ Escanear com antivírus antes de aceitar
- ✅ Armazenar arquivos fora do diretório web acessível
- ✅ Implementar lista de bloqueio de tipos perigosos
- ✅ Limitar tamanho máximo por tipo de arquivo

---

### Código 4: Consulta de Dados

**Vulnerabilidade**: **Injection (NoSQL Injection)**

**Exploração Detalhada:**
O código aceita entrada JSON sem validação e a usa diretamente em uma query MongoDB. Um atacante pode injetar operadores MongoDB:

```python
# Payload malicioso:
query = {"$ne": None}  # $ne = "not equal"

# Query resultante:
db.users.find({
    'name': {"$ne": None},
    'email': {"$ne": None}
})

# Isso retorna TODOS os usuários (name != None E email != None sempre verdadeiro)
```

**Outros Payloads Possíveis:**
```python
# Retornar todos os documentos
query = {"$ne": ""}

# Regex injection (se MongoDB suportar)
query = {"$regex": ".*"}

# Comentários
query = {"$where": "this.name == this.email"}
```

**Correção Segura:**
```python
import re
from bson import ObjectId

@app.route('/api/search', methods=['POST'])
def search():
    query = request.json.get('query', '')
    
    # Validar entrada
    if not query or not isinstance(query, str):
        return {'error': 'Invalid query'}, 400
    
    # Sanitizar entrada (remover caracteres especiais perigosos)
    query_sanitized = re.sub(r'[${}]', '', query)  # Remove $ { }
    
    # Limitar tamanho da query
    if len(query_sanitized) > 100:
        return {'error': 'Query too long'}, 400
    
    # Usar busca segura com validação de tipo
    results = db.users.find({
        'name': {'$regex': query_sanitized, '$options': 'i'},  # Case insensitive
        'active': True  # Adicionar filtros de contexto
    }).limit(50)  # Limitar resultados
    
    # Sanitizar resultados antes de retornar
    results_sanitized = []
    for user in results:
        results_sanitized.append({
            'id': str(user['_id']),
            'name': user.get('name', ''),
            'email': user.get('email', '')  # Considerar privacidade
            # Não retornar: senha, dados sensíveis
        })
    
    return jsonify(results_sanitized)
```

**Alternativas Seguras:**
- Usar bibliotecas de validação (Marshmallow, Pydantic)
- Implementar whitelist de campos permitidos
- Usar índices de busca dedicados (Elasticsearch) em vez de query direta

---

### Código 5: Mensagens de Erro

**Vulnerabilidade**: **Security Misconfiguration (Information Disclosure)**

**Exploração Detalhada:**
O código expõe informações sensíveis em mensagens de erro:

1. **Stack Trace Completo**: Expõe estrutura interna do código, caminhos de arquivos, nomes de funções, variáveis
2. **Mensagens de Erro SQL**: Se houver erro no banco, pode expor estrutura do banco de dados
3. **Informações do Sistema**: Versões de bibliotecas, configurações, caminhos absolutos

**Exemplo de Informação Exposta:**
```json
{
  "error": "connection to database 'prod_db' failed: timeout after 30s",
  "traceback": "File '/app/models/user.py', line 42, in get_user\n  user = db.get_user(user_id)\nFile '/app/db/connection.py', line 15\n  conn = psycopg2.connect(host='10.0.0.5', database='prod_db', user='admin')\n..."
}
```

**Informações Sensíveis Expostas:**
- ✅ Nomes de arquivos e estrutura do código
- ✅ Nomes de banco de dados e hosts
- ✅ Credenciais parciais em strings de conexão
- ✅ Versões de bibliotecas (para identificar vulnerabilidades conhecidas)
- ✅ Caminhos absolutos do servidor

**Correção Segura:**
```python
import logging
from flask import jsonify

# Configurar logging (salvar em arquivo, não expor ao usuário)
logger = logging.getLogger(__name__)

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = db.get_user(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify(user)
    
    except ValueError as e:
        # Erro de validação - mensagem genérica
        logger.warning(f"Invalid user_id: {user_id}")
        return jsonify({'error': 'Invalid request'}), 400
    
    except Exception as e:
        # Erro inesperado - logar detalhes, retornar genérico
        error_id = str(uuid.uuid4())  # ID único para rastreamento
        logger.error(f"Error {error_id}: {str(e)}", exc_info=True)
        
        # Em desenvolvimento: retornar erro detalhado
        if app.config.get('DEBUG'):
            return jsonify({
                'error': 'Internal server error',
                'error_id': error_id,
                'details': str(e)
            }), 500
        
        # Em produção: mensagem genérica
        return jsonify({
            'error': 'An error occurred. Please try again later.',
            'error_id': error_id  # Usuário pode reportar este ID para suporte
        }), 500
```

**Boas Práticas:**
- ✅ Usar logging para registrar erros detalhados (não expor ao usuário)
- ✅ Mensagens genéricas em produção
- ✅ IDs de erro únicos para rastreamento (ajuda suporte sem expor detalhes)
- ✅ Diferentes níveis de detalhe em desenvolvimento vs produção
- ✅ Monitorar erros em sistema de logging centralizado (Sentry, CloudWatch)

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (60 pontos)

**Código 1 (SQL Injection):**
- [ ] Identifica corretamente como SQL Injection (10 pontos)
- [ ] Explica como o ataque funciona (concatenação de strings) (10 pontos)
- [ ] Propõe uso de prepared statements (10 pontos)

**Código 2 (Broken Access Control):**
- [ ] Identifica corretamente como Broken Access Control/IDOR (10 pontos)
- [ ] Explica que falta validação de propriedade/permissão (10 pontos)
- [ ] Propõe validação de usuário autenticado (10 pontos)

**Código 3 (Upload Inseguro):**
- [ ] Identifica pelo menos uma vulnerabilidade (Path Traversal ou Upload inseguro) (10 pontos)
- [ ] Explica o risco (acesso a arquivos do sistema ou execução de código) (10 pontos)
- [ ] Propõe validação de tipo e nome de arquivo (10 pontos)

**Código 4 (NoSQL Injection):**
- [ ] Identifica corretamente como Injection (NoSQL) (10 pontos)
- [ ] Explica como funciona ($ne, $regex, etc.) (10 pontos)
- [ ] Propõe validação/sanitização de entrada (10 pontos)

**Código 5 (Security Misconfiguration):**
- [ ] Identifica exposição de informações sensíveis (10 pontos)
- [ ] Explica quais informações são expostas (stack trace, caminhos, etc.) (10 pontos)
- [ ] Propõe mensagens genéricas em produção (10 pontos)

### ⭐ Importantes (25 pontos)

- [ ] Explicação detalhada e clara (5 pontos)
- [ ] Identifica múltiplas vulnerabilidades no Código 3 (5 pontos)
- [ ] Considera contexto prático (financeiro, educacional) no Código 2 (5 pontos)
- [ ] Propõe correções bem estruturadas com código de exemplo (10 pontos)

### 💡 Bônus (15 pontos)

- [ ] Identifica vulnerabilidades adicionais (senha em texto plano, token fixo) no Código 1 (5 pontos)
- [ ] Propõe validações adicionais (rate limiting, sanitização de saída) (5 pontos)
- [ ] Considera múltiplos contextos e riscos diferentes (5 pontos)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Reconhecimento de Padrões**: Aluno consegue identificar padrões de código vulnerável?
2. **Compreensão de Ataques**: Aluno entende como atacantes exploram vulnerabilidades?
3. **Capacidade de Correção**: Aluno propõe correções seguras e práticas?
4. **Contexto e Riscos**: Aluno considera impacto em diferentes contextos?

### Erros Comuns

1. **Erro: Confundir tipos de Injection**
   - **Situação**: Aluno identifica SQL Injection no Código 4 (que é NoSQL Injection)
   - **Feedback**: "Excelente identificação da vulnerabilidade! O Código 4 é na verdade NoSQL Injection, que funciona de forma similar mas usa operadores MongoDB ($ne, $regex) em vez de SQL. Ambos são tipos de Injection do OWASP Top 10."

2. **Erro: Correção incompleta**
   - **Situação**: Aluno propõe apenas validação de extensão no Código 3
   - **Feedback**: "Boa identificação do problema de upload! Além da validação de extensão, considere também: validação de conteúdo real do arquivo (magic bytes), sanitização do nome do arquivo, e armazenamento fora do diretório web acessível. Isso previne bypass da validação de extensão."

3. **Erro: Não considerar múltiplas vulnerabilidades**
   - **Situação**: Aluno identifica apenas uma vulnerabilidade no Código 3
   - **Feedback**: "Ótimo trabalho identificando o Path Traversal! O Código 3 tem múltiplas vulnerabilidades: além do Path Traversal, há também risco de upload de arquivos executáveis que podem ser acessados via web. Considere sempre verificar múltiplas camadas de segurança."

4. **Erro: Correção que introduz novos problemas**
   - **Situação**: Aluno propõe apenas ocultar erros sem logging
   - **Feedback**: "Boa identificação do problema de exposição de informações! Além de ocultar erros do usuário, é importante implementar logging para que a equipe possa diagnosticar problemas. Isso permite rastrear erros sem expor detalhes sensíveis."

### Dicas para Feedback

- ✅ **Reconheça**: Esforço de análise, identificação correta, explicações claras
- ❌ **Corrija**: Confusões entre tipos de vulnerabilidades, correções incompletas
- 💡 **Incentive**: Considerar múltiplas vulnerabilidades, pensar em contexto, propor validações adicionais

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Base para Tudo**: Identificação de vulnerabilidades é a habilidade mais básica e importante em segurança
2. **OWASP Top 10**: Exercita reconhecimento das vulnerabilidades mais comuns (Top 10)
3. **Pensamento Crítico**: Desenvolve capacidade de analisar código com olhar de segurança
4. **Correção Prática**: Ensina a não apenas identificar, mas também corrigir vulnerabilidades
5. **Contexto Real**: Simula análise real de código que desenvolvedores fazem

**Conexão com o Curso:**
- Aula 1.2: OWASP Top 10 (teoria) → Este exercício (prática)
- Pré-requisito para: Aulas de ferramentas SAST (que identificam essas vulnerabilidades automaticamente)
- Base para: Módulo 2 (Testes de Segurança na Prática)

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (90-100 pontos)

**Código 1 - SQL Injection**
"O código tem vulnerabilidade de SQL Injection porque utiliza concatenação de strings para construir a query SQL. Um atacante pode inserir `admin' OR '1'='1' --` no campo username, fazendo com que a condição seja sempre verdadeira. A correção deve usar prepared statements com placeholders (%s) para evitar execução de código SQL arbitrário."

**Características da Resposta:**
- ✅ Identifica vulnerabilidade corretamente
- ✅ Explica como funciona o ataque
- ✅ Propõe correção técnica específica
- ✅ Considera impacto (bypass de autenticação)

### Exemplo 2: Resposta Boa (80-89 pontos)

**Código 2 - Broken Access Control**
"Este código permite que qualquer usuário acesse dados de outros usuários modificando o user_id na URL. Isso é um problema de Broken Access Control porque não há validação se o usuário tem permissão para acessar aquele recurso. Deve-se validar que o usuário autenticado só pode acessar seu próprio perfil."

**Características da Resposta:**
- ✅ Identifica vulnerabilidade corretamente
- ✅ Explica o problema de controle de acesso
- ✅ Propõe validação (mas poderia ser mais detalhada)
- ⚠️ Não menciona impacto em diferentes contextos (mas isso é bônus)

---

**Última atualização**: 2025-01-09  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
