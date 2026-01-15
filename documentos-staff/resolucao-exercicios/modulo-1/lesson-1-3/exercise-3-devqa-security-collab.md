---
exercise_id: lesson-1-3-exercise-3-devqa-security-collab
title: "Exercício 1.3.3: Colaboração Dev/QA/Security"
lesson_id: lesson-1-3
module: module-1
difficulty: "Intermediário"
last_updated: 2026-01-14
---

# Exercício 1.3.3: Colaboração Dev/QA/Security

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **colaboração entre Dev, QA e Security** através da **simulação de cenários reais** de trabalho conjunto.

### Tarefa Principal

1. Documentar vulnerabilidade de forma clara para Dev
2. Realizar code review focando em segurança
3. Criar processo de colaboração eficaz
4. Criar ferramentas de colaboração

---

## ✅ Soluções Detalhadas

### Parte 1: Cenário - Vulnerabilidade Encontrada

**Situação**: QA encontrou vulnerabilidade de SQL Injection em endpoint de busca.

**Solução Esperada - Template de Bug de Segurança:**

```markdown
# Bug de Segurança: SQL Injection em /api/search

## Severidade
🔴 Crítica

## Descrição
Endpoint /api/search é vulnerável a SQL Injection, permitindo acesso não autorizado a dados.

## Impacto
- Acesso não autorizado a dados do banco
- Possível vazamento de informações sensíveis
- Violação de confidencialidade
- Possível violação de compliance (LGPD, PCI-DSS)

## Steps to Reproduce
1. Acessar endpoint: `GET /api/search?q=teste`
2. Modificar parâmetro: `GET /api/search?q=teste' OR '1'='1' --`
3. Observar que retorna mais resultados do que deveria

## Evidência
- **Payload usado**: `teste' OR '1'='1' --`
- **Resultado**: Retorna todos os registros da tabela
- **Código vulnerável**: Linha 45 de `search.py`:
  ```python
  query = f"SELECT * FROM items WHERE name = '{term}'"
  ```
- **Screenshot**: [anexar screenshot da resposta]

## Correção Proposta
Usar prepared statements ao invés de concatenação de strings:
```python
# Antes (vulnerável)
query = f"SELECT * FROM items WHERE name = '{term}'"

# Depois (seguro)
query = "SELECT * FROM items WHERE name = ?"
cursor.execute(query, (term,))
```

## Teste de Validação
Após correção, executar:
- [ ] Teste com payload malicioso deve retornar erro ou resultado vazio
- [ ] Teste com entrada válida deve funcionar normalmente
- [ ] Teste automatizado deve passar

## Prioridade
P1 - IMEDIATO (Corrigir em 24h)

## Anexos
- [ ] Screenshot da vulnerabilidade
- [ ] Logs de requisição
- [ ] Exemplo de código vulnerável
```

**Validação Técnica:**
- ✅ Descrição clara e específica
- ✅ Steps to reproduce detalhados
- ✅ Evidência documentada (payload, código, screenshot)
- ✅ Correção proposta com código de exemplo
- ✅ Teste de validação documentado
- ✅ Prioridade definida

---

### Parte 2: Cenário - Code Review de Segurança

**Código para Revisar:**

```python
@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    user = db.get_user(user_id)
    return jsonify(user)

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    is_admin = request.json.get('is_admin', False)
    if is_admin:
        return jsonify(db.get_all_users())
    return {'error': 'Forbidden'}, 403
```

**Solução Esperada - Code Review de Segurança:**

```markdown
## Code Review de Segurança

### Vulnerabilidades Encontradas

#### 1. Broken Access Control (IDOR)
**Arquivo**: `app.py`, linha 5-7
**Severidade**: 🔴 Crítica

**Problema**: Endpoint não valida se usuário logado é dono do recurso. Usuário pode acessar dados de outros modificando `user_id` na URL.

**Exemplo de Exploração:**
```bash
# Usuário 1 logado tenta acessar dados do usuário 2
GET /api/users/2
Headers: Authorization: Bearer <token_usuario_1>
# Retorna dados do usuário 2 (vulnerabilidade!)
```

**Correção:**
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

#### 2. Privilege Escalation
**Arquivo**: `app.py`, linha 10-15
**Severidade**: 🔴 Crítica

**Problema**: Confia em parâmetro do cliente para verificar admin. Atacante pode enviar `is_admin: true` e escalar privilégios.

**Exemplo de Exploração:**
```bash
# Usuário comum tenta acessar endpoint admin
POST /api/admin/users
Body: {"is_admin": true}
# Retorna todos os usuários (escalação de privilégio!)
```

**Correção:**
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

### Resumo
- **Vulnerabilidades encontradas**: 2 críticas
- **Recomendação**: Não fazer merge até correções serem implementadas
- **Prioridade**: P1 - IMEDIATO
```

**Validação Técnica:**
- ✅ Vulnerabilidades identificadas corretamente
- ✅ Problemas explicados claramente
- ✅ Exemplos de exploração documentados
- ✅ Correções propostas com código de exemplo
- ✅ Severidade e prioridade definidas

---

### Parte 3: Cenário - Processo de Colaboração

**Solução Esperada - Processo de Colaboração:**

```markdown
# Processo de Colaboração Dev/QA/Security

## Fluxo de Vulnerabilidade Encontrada

### 1. QA encontra vulnerabilidade
- **Ação**: Documenta usando template de bug padronizado
- **Ferramenta**: GitHub Issues / Jira
- **Priorização**: Define severidade (Crítica/Alta/Média/Baixa)
- **Atribuição**: Atribui para Dev responsável pelo código

**Template**: Usar template de bug de segurança padronizado

### 2. Dev recebe e analisa
- **Ação**: Analisa vulnerabilidade, propõe correção técnica
- **Prazo**: Responder em até 4h (crítica) ou 1 dia (alta/média)
- **Comunicação**: Comenta no issue com análise e proposta

**Checklist Dev:**
- [ ] Vulnerabilidade compreendida
- [ ] Correção proposta (código de exemplo)
- [ ] Impacto da correção avaliado
- [ ] Correção implementada

### 3. QA valida correção
- **Ação**: Executa testes de segurança, valida que vulnerabilidade foi corrigida
- **Prazo**: Validar em até 4h após correção implementada
- **Comunicação**: Comenta no issue com resultados dos testes

**Checklist QA:**
- [ ] Teste de vulnerabilidade (deve falhar após correção)
- [ ] Teste de funcionalidade (deve funcionar normalmente)
- [ ] Testes automatizados passando
- [ ] Issue fechado se tudo ok

### 4. Security revisa (se crítico)
- **Ação**: Revisa correção, valida que atende políticas de segurança
- **Prazo**: Revisar em até 1 dia após correção
- **Comunicação**: Aprova ou solicita ajustes

**Checklist Security:**
- [ ] Correção técnica adequada
- [ ] Atende políticas de segurança
- [ ] Não introduz novas vulnerabilidades
- [ ] Aprovação ou feedback fornecido

## SLA (Service Level Agreement)
- **Crítica**: Correção em 24h, validação em 4h
- **Alta**: Correção em 3 dias, validação em 1 dia
- **Média**: Correção em 1 semana, validação em 2 dias
- **Baixa**: Correção em 2 semanas, validação em 3 dias

## Ferramentas
- **Issue Tracking**: GitHub Issues / Jira
- **Code Review**: GitHub Pull Requests / GitLab Merge Requests
- **Comunicação**: Slack / Teams / Email
- **Documentação**: Confluence / Wiki
```

**Validação Técnica:**
- ✅ Fluxo claro e bem definido
- ✅ Responsabilidades definidas para cada papel
- ✅ SLA definido (prazos realistas)
- ✅ Ferramentas recomendadas
- ✅ Checklists para cada etapa

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Documentação de Vulnerabilidade:**
- [ ] Bug documentado usando template padronizado
- [ ] Descrição clara e específica
- [ ] Steps to reproduce documentados
- [ ] Evidência incluída (payload, código, screenshot)
- [ ] Correção proposta com código de exemplo

**Code Review:**
- [ ] Pelo menos 1 vulnerabilidade identificada corretamente
- [ ] Problema explicado claramente
- [ ] Correção proposta

**Processo:**
- [ ] Processo de colaboração criado (fluxo básico)
- [ ] Responsabilidades definidas

### ⭐ Importantes (Recomendados para Resposta Completa)

**Documentação:**
- [ ] Bug bem documentado (todas as seções preenchidas)
- [ ] Teste de validação documentado
- [ ] Prioridade e SLA definidos

**Code Review:**
- [ ] Múltiplas vulnerabilidades identificadas (2+)
- [ ] Exemplos de exploração documentados
- [ ] Correções propostas com código completo

**Processo:**
- [ ] Processo completo e detalhado
- [ ] SLA definido (prazos realistas)
- [ ] Checklists para cada etapa
- [ ] Ferramentas recomendadas

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Processo:**
- [ ] Processo integrado com ferramentas (GitHub, Jira)
- [ ] Métricas de colaboração definidas (tempo de correção, taxa de retest)
- [ ] Processo de melhoria contínua documentado

**Ferramentas:**
- [ ] Templates customizados criados
- [ ] Scripts de automação (se aplicável)
- [ ] Dashboard de vulnerabilidades

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Documentação**: Aluno documenta vulnerabilidades de forma clara?
2. **Code Review**: Aluno identifica vulnerabilidades em código?
3. **Colaboração**: Aluno cria processos eficazes de colaboração?

### Erros Comuns

1. **Erro: Documentação incompleta**
   - **Situação**: Aluno documenta vulnerabilidade sem steps to reproduce
   - **Feedback**: "Boa identificação da vulnerabilidade! Para facilitar correção, inclua steps to reproduce detalhados: '1. Acessar endpoint X, 2. Modificar parâmetro Y, 3. Observar resultado Z'. Isso ajuda Dev a reproduzir e corrigir rapidamente."

2. **Erro: Correção proposta sem código**
   - **Situação**: Aluno propõe "usar prepared statements" sem mostrar código
   - **Feedback**: "Boa proposta de correção! Para tornar mais útil, inclua código de exemplo: 'Antes (vulnerável): ... Depois (seguro): ...'. Isso facilita implementação."

### Dicas para Feedback

- ✅ **Reconheça**: Documentação clara, identificação correta de vulnerabilidades, processo bem estruturado
- ❌ **Corrija**: Documentação incompleta, correções sem código, processo vago
- 💡 **Incentive**: Templates customizados, automação, métricas

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Colaboração Essencial**: Shift-Left Security requer colaboração efetiva
2. **Habilidade Essencial**: QA precisa saber comunicar vulnerabilidades
3. **Prevenção**: Processos claros previnem mal-entendidos e atrasos
4. **Eficiência**: Documentação clara acelera correção

**Conexão com o Curso:**
- Aula 1.3: Shift-Left Security (teoria) → Este exercício (prática de colaboração)
- Pré-requisito para: Processos reais de segurança
- Base para: Toda colaboração Dev/QA/Security

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Bug Documentado:**
"Bug de SQL Injection em /api/search. Severidade: Crítica. Steps to reproduce: 1. GET /api/search?q=teste, 2. GET /api/search?q=teste' OR '1'='1' --, 3. Retorna todos os registros. Evidência: payload documentado, código vulnerável linha 45, screenshot anexado. Correção: usar prepared statements. Teste: payload malicioso deve retornar erro. Prioridade: P1 - IMEDIATO."

**Code Review:**
"Identificadas 2 vulnerabilidades críticas: 1) IDOR em /api/users/<id> - não valida propriedade, 2) Privilege Escalation em /api/admin/users - confia em parâmetro do cliente. Correções propostas com código completo. Recomendação: não fazer merge até correções."

**Processo:**
"Processo criado: QA documenta bug → Dev analisa e corrige → QA valida → Security revisa (crítico). SLA: Crítica 24h, Alta 3 dias. Checklists para cada etapa. Ferramentas: GitHub Issues, PRs."

**Características da Resposta:**
- ✅ Documentação completa e clara
- ✅ Code review detalhado com correções
- ✅ Processo completo e prático
- ✅ SLA e checklists definidos

---

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
