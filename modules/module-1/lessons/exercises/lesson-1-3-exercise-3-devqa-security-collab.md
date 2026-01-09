---
layout: exercise
title: "Exercício 1.3.3: Colaboração Dev/QA/Security"
slug: "devqa-security-collab"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Intermediário"
permalink: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-3-exercise-3-devqa-security-collab/
lesson_url: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/shift-left-security/
---

## Objetivo

Este exercício tem como objetivo praticar **colaboração entre Dev, QA e Security** através da **simulação de cenários reais** de trabalho conjunto.

Ao completar este exercício, você será capaz de:

- Facilitar comunicação entre Dev, QA e Security
- Traduzir vulnerabilidades técnicas para ações práticas
- Criar processos de colaboração eficazes
- Documentar vulnerabilidades de forma clara

---

## Descrição

Você precisa simular cenários de colaboração entre Dev, QA e Security, criando processos e documentação que facilitem o trabalho conjunto.

### Contexto

Colaboração efetiva entre Dev, QA e Security é essencial para Shift-Left Security. Como QA, você está na posição única de facilitar essa colaboração.

---

## Requisitos

### Parte 1: Cenário - Vulnerabilidade Encontrada

**Situação**:
QA encontrou vulnerabilidade de SQL Injection em endpoint de busca durante testes.

**Informações**:
- Endpoint: `/api/search?q=termo`
- Vulnerabilidade: SQL Injection possível
- Payload de teste: `termo' OR '1'='1' --`
- Impacto: Acesso não autorizado a dados

**Tarefas**:
- [ ] Documentar vulnerabilidade de forma clara para Dev
- [ ] Incluir: descrição, impacto, evidência, steps to reproduce
- [ ] Propor correção técnica
- [ ] Criar teste para validar correção

**Template de Bug de Segurança**:
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

## Steps to Reproduce
1. Acessar endpoint: GET /api/search?q=teste
2. Modificar parâmetro: GET /api/search?q=teste' OR '1'='1' --
3. Observar que retorna mais resultados do que deveria

## Evidência
- Payload usado: `teste' OR '1'='1' --`
- Resultado: Retorna todos os registros da tabela
- Screenshot: [anexar]

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
- Teste com payload malicioso deve retornar erro ou resultado vazio
- Teste com entrada válida deve funcionar normalmente
```

---

### Parte 2: Cenário - Code Review de Segurança

**Situação**:
Dev submeteu PR com nova funcionalidade. QA precisa fazer code review focando em segurança.

**Código para Revisar**:
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

**Tarefas**:
- [ ] Identificar vulnerabilidades de segurança
- [ ] Documentar vulnerabilidades encontradas
- [ ] Propor correções
- [ ] Criar comentários de code review construtivos

**Template de Code Review**:
```markdown
## Code Review de Segurança

### Vulnerabilidades Encontradas

#### 1. Broken Access Control (IDOR)
**Arquivo**: `app.py`, linha 5
**Severidade**: 🔴 Crítica

**Problema**: Endpoint não valida se usuário logado é dono do recurso.

**Correção**:
```python
@app.route('/api/users/<user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    current_user_id = session['user_id']
    if int(user_id) != current_user_id:
        return jsonify({'error': 'Forbidden'}), 403
    user = db.get_user(user_id)
    return jsonify(user)
```

#### 2. Privilege Escalation
**Arquivo**: `app.py`, linha 10
**Severidade**: 🔴 Crítica

**Problema**: Confia em parâmetro do cliente para verificar admin.

**Correção**: Validar role no servidor.
```

---

### Parte 3: Cenário - Processo de Colaboração

Crie um processo de colaboração para vulnerabilidades encontradas:

**Tarefas**:
- [ ] Definir fluxo de comunicação
- [ ] Criar templates de documentação
- [ ] Definir SLA (tempo de resposta)
- [ ] Criar processo de validação de correções

**Template de Processo**:
```markdown
# Processo de Colaboração Dev/QA/Security

## Fluxo de Vulnerabilidade Encontrada

1. **QA encontra vulnerabilidade**
   - Documenta usando template de bug
   - Prioriza por severidade
   - Atribui para Dev responsável

2. **Dev recebe e analisa**
   - Analisa vulnerabilidade
   - Propõe correção técnica
   - Implementa correção

3. **QA valida correção**
   - Executa testes de segurança
   - Valida que vulnerabilidade foi corrigida
   - Valida que funcionalidade ainda funciona

4. **Security revisa (se crítico)**
   - Revisa correção
   - Valida que atende políticas
   - Aprova ou solicita ajustes

## SLA (Service Level Agreement)
- Crítica: Correção em 24h
- Alta: Correção em 3 dias
- Média: Correção em 1 semana
- Baixa: Correção em 2 semanas
```

---

### Parte 4: Criar Ferramentas de Colaboração

Crie ferramentas que facilitem colaboração:

**Tarefas**:
- [ ] Criar template de bug de segurança
- [ ] Criar template de code review
- [ ] Criar checklist de validação
- [ ] Criar guia de comunicação

---

## Contexto CWI

### Caso Real: Processo de Colaboração em Projeto

Em um projeto da CWI, criamos processo de colaboração Dev/QA/Security:

**Processo Criado**:
1. QA documenta vulnerabilidade em template padronizado
2. Dev recebe notificação e analisa
3. Dev propõe correção e implementa
4. QA valida correção com testes automatizados
5. Security revisa se vulnerabilidade é crítica

**Ferramentas Criadas**:
- Template de bug de segurança
- Checklist de code review
- Testes automatizados de validação
- Dashboard de vulnerabilidades

**Resultado**:
- Comunicação mais eficiente
- Tempo de correção reduzido em 50%
- Zero vulnerabilidades críticas em produção

---

## Dicas

1. **Seja claro e específico**: Documentação clara facilita correção
2. **Seja construtivo**: Code reviews devem ajudar, não criticar
3. **Comunique proativamente**: Informe vulnerabilidades rapidamente
4. **Valide correções**: Sempre teste que correção funciona
5. **Documente processos**: Processos claros facilitam colaboração

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.3.4: Shift-Left Checklist
- Aplicar processos de colaboração em projetos reais
- Facilitar comunicação entre times

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Exercício 1.3.2 (Threat Modeling Early)
