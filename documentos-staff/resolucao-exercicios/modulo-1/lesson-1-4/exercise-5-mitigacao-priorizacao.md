---
exercise_id: lesson-1-4-exercise-5-mitigacao-priorizacao
title: "Exercício 1.4.5: Mitigação e Priorização de Ameaças"
lesson_id: lesson-1-4
module: module-1
difficulty: "Avançado"
last_updated: 2025-01-15
---

# Exercício 1.4.5: Mitigação e Priorização de Ameaças

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **mitigação e priorização** de ameaças através da **criação de planos de ação** e **alocação de recursos**.

### Tarefa Principal

1. Criar mitigações efetivas para ameaças
2. Priorizar mitigações por risco e esforço
3. Criar planos de implementação
4. Validar que mitigações são efetivas

---

## ✅ Soluções Detalhadas

### Parte 1: Criar Mitigações - SQL Injection em Busca

**Solução Esperada:**

#### Mitigação para: SQL Injection em Busca

**Ameaça**: Endpoint de busca vulnerável a SQL Injection (DREAD: 9.6 - Crítico)

**Mitigação Proposta**: Usar prepared statements ao invés de concatenação de strings

**Tipo de Controle**: Preventivo (evita ameaça)

**Esforço de Implementação**: Baixo (< 1 dia)
- Reescrever query usando prepared statements
- Validar entrada antes de usar na query
- Testar que vulnerabilidade foi corrigida

**Efetividade Esperada**: Alta (mitiga completamente)
- Prepared statements previnem SQL Injection completamente
- Validação de entrada adiciona camada adicional de segurança

**Validação**:
- Teste de SQL Injection com payloads maliciosos (deve retornar erro)
- Teste de entrada válida (deve funcionar normalmente)
- Code review validando uso de prepared statements

**Código de Exemplo:**
```python
# Antes (vulnerável)
query = f"SELECT * FROM products WHERE name = '{term}'"
cursor.execute(query)

# Depois (seguro)
query = "SELECT * FROM products WHERE name = ?"
cursor.execute(query, (term,))
```

**Validação Técnica:**
- ✅ Mitigação específica e implementável
- ✅ Tipo de controle definido (Preventivo)
- ✅ Esforço estimado adequadamente
- ✅ Efetividade justificada
- ✅ Validação documentada

---

### Parte 1: Criar Mitigações - Broken Access Control em Pedidos

**Solução Esperada:**

#### Mitigação para: Broken Access Control em Pedidos

**Ameaça**: Clientes podem acessar pedidos de outros (DREAD: 9.0 - Crítico)

**Mitigação Proposta**: Validação de propriedade no servidor

**Tipo de Controle**: Preventivo (evita ameaça)

**Esforço de Implementação**: Médio (1-2 dias)
- Implementar validação de propriedade em endpoint
- Validar que cliente logado é dono do pedido
- Testar que vulnerabilidade foi corrigida

**Efetividade Esperada**: Alta (mitiga completamente)
- Validação no servidor previne IDOR completamente
- Não há como bypassar validação no servidor

**Validação**:
- Teste de IDOR (cliente tenta acessar pedido de outro → deve retornar 403)
- Teste de acesso válido (cliente acessa próprio pedido → deve funcionar)
- Code review validando validação de propriedade

**Código de Exemplo:**
```python
# Antes (vulnerável)
@app.route('/api/orders/<order_id>', methods=['GET'])
def get_order(order_id):
    order = db.get_order(order_id)
    return jsonify(order)

# Depois (seguro)
@app.route('/api/orders/<order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    current_user_id = session['user_id']
    order = db.get_order_with_user(order_id)
    
    if not order or order.user_id != current_user_id:
        return jsonify({'error': 'Forbidden'}), 403
    
    return jsonify(order)
```

**Validação Técnica:**
- ✅ Mitigação específica e implementável
- ✅ Esforço estimado adequadamente (Médio para implementar validação)
- ✅ Efetividade justificada
- ✅ Código de exemplo fornecido

---

### Parte 2: Priorizar Mitigações

**Solução Esperada - Matriz de Priorização:**

| Ameaça | Risco (DREAD) | Esforço | Prioridade | Ação |
|--------|---------------|---------|------------|------|
| SQL Injection | 9.6 (Crítico) | Baixo | P1 - IMEDIATO | Implementar agora (< 1 dia) |
| Broken Access Control | 9.0 (Crítico) | Médio | P1 - IMEDIATO | Implementar agora (1-2 dias) |
| Vazamento de Cartão | 9.8 (Crítico) | Alto | P1 - IMEDIATO | Planejar (3-5 dias) |
| Senha Fraca | 8.2 (Alto) | Baixo | P2 - Este Sprint | Implementar em seguida (< 1 dia) |
| Cache Poisoning | 7.0 (Alto) | Médio | P2 - Este Sprint | Implementar depois (1-2 dias) |

**Matriz Visual - Risco vs Esforço:**

```
                Esforço Baixo    Esforço Médio   Esforço Alto
Risco Crítico   [FAZER PRIMEIRO] [FAZER PRIMEIRO] [PLANEJAR]
                SQL Injection    Broken Access    Vazamento
                                 Control          Cartão

Risco Alto      [FAZER AGORA]   [FAZER DEPOIS]  [CONSIDERAR]
                Senha Fraca     Cache Poisoning

Risco Médio     [FAZER QUANDO]  [OPCIONAL]      [IGNORAR]
```

**Estratégia de Priorização:**
1. **Críticas de Baixo Esforço**: Implementar imediatamente (SQL Injection)
2. **Críticas de Médio Esforço**: Implementar imediatamente (Broken Access Control)
3. **Críticas de Alto Esforço**: Planejar implementação (Vazamento de Cartão)
4. **Altas de Baixo Esforço**: Implementar em seguida (Senha Fraca)
5. **Altas de Médio Esforço**: Implementar depois (Cache Poisoning)

**Validação Técnica:**
- ✅ Matriz de priorização criada
- ✅ Risco e esforço considerados
- ✅ Prioridades definidas (P1/P2/P3)
- ✅ Estratégia de priorização justificada

---

### Parte 3: Criar Plano de Implementação

**Solução Esperada:**

```markdown
# Plano de Implementação de Mitigações

## Fase 1: Mitigações Críticas (Semana 1)

### Semana 1 - Dia 1: SQL Injection
- **Mitigação**: Prepared statements em /api/products?q=
- **Responsável**: Dev Backend
- **Prazo**: 4 horas
- **Validação**: Teste de SQL Injection deve falhar
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

### Semana 1 - Dias 2-3: Broken Access Control
- **Mitigação**: Validação de propriedade em /api/orders/<id>
- **Responsável**: Dev Backend
- **Prazo**: 2 dias
- **Validação**: Teste de IDOR deve retornar 403
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

### Semana 1 - Dias 4-5: Vazamento de Cartão (Planejamento)
- **Mitigação**: Tokenização de dados de cartão
- **Responsável**: Dev Backend + Security
- **Prazo**: Planejamento (implementação em Semana 2)
- **Validação**: Verificação de tokenização implementada
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

## Fase 2: Mitigações Altas (Semana 2)

### Semana 2 - Dia 1: Senha Fraca
- **Mitigação**: Política de senhas forte (12+ caracteres, complexidade)
- **Responsável**: Dev Backend
- **Prazo**: 1 dia
- **Validação**: Teste de política de senhas deve falhar para senhas fracas
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

### Semana 2 - Dias 2-3: Cache Poisoning
- **Mitigação**: Validação de dados antes de cachear, TTL apropriado
- **Responsável**: Dev Backend
- **Prazo**: 2 dias
- **Validação**: Teste de cache poisoning deve falhar
- **Status**: [ ] Pendente / [ ] Em andamento / [ ] Concluído

## Validação Geral
- [ ] Todos os testes de segurança passando após mitigações
- [ ] Code review realizado para todas as mitigações
- [ ] Vulnerabilidades críticas corrigidas (0 críticas restantes)
- [ ] Vulnerabilidades altas reduzidas (> 50% corrigidas)
- [ ] Documentação atualizada com mitigações implementadas
```

**Validação Técnica:**
- ✅ Plano de implementação criado
- ✅ Prazos realistas definidos
- ✅ Responsáveis definidos
- ✅ Validação documentada para cada mitigação
- ✅ Métricas de sucesso definidas

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Criação de Mitigações:**
- [ ] Mitigações criadas para pelo menos 2 ameaças críticas/altas
- [ ] Mitigações são específicas e implementáveis
- [ ] Tipo de controle definido (Preventivo/Detectivo/Corretivo)
- [ ] Esforço estimado para cada mitigação

**Priorização:**
- [ ] Matriz de priorização criada (risco vs esforço)
- [ ] Prioridades definidas (P1/P2/P3)
- [ ] Estratégia de priorização justificada

**Plano de Implementação:**
- [ ] Plano básico criado com prazos

### ⭐ Importantes (Recomendados para Resposta Completa)

**Criação de Mitigações:**
- [ ] Mitigações criadas para 3+ ameaças
- [ ] Esforço estimado adequadamente (Baixo/Médio/Alto)
- [ ] Efetividade esperada definida e justificada
- [ ] Validação documentada para cada mitigação
- [ ] Código de exemplo fornecido quando aplicável

**Priorização:**
- [ ] Matriz visual criada (risco vs esforço)
- [ ] Priorização considerando risco e esforço
- [ ] Estratégia de priorização bem detalhada

**Plano de Implementação:**
- [ ] Plano completo com prazos realistas
- [ ] Responsáveis definidos
- [ ] Validação documentada para cada mitigação
- [ ] Métricas de sucesso definidas

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Mitigações:**
- [ ] Múltiplas mitigações por ameaça (defense in depth)
- [ ] Mitigações considerando múltiplas camadas (preventivo + detectivo)
- [ ] Análise de custo-benefício (esforço vs efetividade)

**Plano:**
- [ ] Plano detalhado com dependências
- [ ] Cronograma com marcos (milestones)
- [ ] Processo de revisão documentado
- [ ] Integração com processo de desenvolvimento

**Aplicação:**
- [ ] Plano aplicado em projeto real
- [ ] Mitigações implementadas e validadas
- [ ] Resultados documentados

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Criação de Mitigações**: Aluno consegue criar mitigações efetivas?
2. **Priorização**: Aluno prioriza mitigações considerando risco e esforço?
3. **Plano de Implementação**: Aluno cria plano de implementação prático?

### Erros Comuns

1. **Erro: Mitigações vagas**
   - **Situação**: Aluno propõe "usar prepared statements" sem detalhar como implementar
   - **Feedback**: "Boa proposta de mitigação! Para torná-la mais útil, detalhe: 'usar prepared statements' pode incluir 'reescrever query usando placeholders (?)', 'validar entrada antes de usar na query', 'testar que vulnerabilidade foi corrigida'. Isso torna mitigação implementável."

2. **Erro: Não considerar esforço**
   - **Situação**: Aluno prioriza todas as mitigações como P1 sem considerar esforço
   - **Feedback**: "Boa priorização por risco! Lembre-se de considerar esforço: mitigações críticas de baixo esforço devem ser implementadas primeiro (quick wins). Mitigações críticas de alto esforço podem ser planejadas mas implementadas depois. Isso aloca recursos eficientemente."

### Dicas para Feedback

- ✅ **Reconheça**: Mitigações específicas, priorização considerando risco e esforço, plano completo
- ❌ **Corrija**: Mitigações vagas, priorização sem considerar esforço, plano incompleto
- 💡 **Incentive**: Múltiplas mitigações, análise de custo-benefício, plano detalhado

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Prática Real**: Identificar ameaças é apenas primeiro passo; mitigar e priorizar é essencial
2. **Habilidade Essencial**: QA precisa saber priorizar mitigações efetivamente
3. **Eficiência**: Priorização adequada aloca recursos eficientemente
4. **Prevenção**: Mitigações corretas previnem vulnerabilidades

**Conexão com o Curso:**
- Aula 1.4: Threat Modeling (teoria) → Este exercício (prática de mitigação e priorização)
- Integra todos os exercícios anteriores de threat modeling
- Base para: Implementação de segurança em projetos reais

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Mitigações Criadas:**
"SQL Injection: Mitigação - prepared statements. Tipo: Preventivo. Esforço: Baixo (< 1 dia). Efetividade: Alta (mitiga completamente). Validação: Teste de SQL Injection deve falhar. Código: [exemplo fornecido]."

**Priorização:**
"Matriz criada: SQL Injection (Crítico, Baixo Esforço) → P1 - IMEDIATO. Broken Access Control (Crítico, Médio Esforço) → P1 - IMEDIATO. Vazamento de Cartão (Crítico, Alto Esforço) → P1 - Planejar. Estratégia: Quick wins primeiro (críticas de baixo esforço), depois críticas de médio esforço, depois críticas de alto esforço planejadas."

**Plano:**
"Plano criado: Semana 1 - Dia 1: SQL Injection (4h, Dev Backend). Semana 1 - Dias 2-3: Broken Access Control (2 dias, Dev Backend). Semana 2: Vazamento de Cartão (planejamento + implementação). Validação: Todos os testes passando, code review realizado, 0 críticas restantes."

**Características da Resposta:**
- ✅ Mitigações específicas e implementáveis
- ✅ Priorização considerando risco e esforço
- ✅ Plano completo com prazos realistas
- ✅ Validação documentada
- ✅ Métricas de sucesso definidas

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
