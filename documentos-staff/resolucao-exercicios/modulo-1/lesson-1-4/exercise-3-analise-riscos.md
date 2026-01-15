---
exercise_id: lesson-1-4-exercise-3-analise-riscos
title: "Exercício 1.4.3: Análise de Riscos com DREAD"
lesson_id: lesson-1-4
module: module-1
difficulty: "Intermediário"
last_updated: 2025-01-15
---

# Exercício 1.4.3: Análise de Riscos com DREAD

## 📋 Enunciado Completo

Este exercício tem como objetivo praticar **análise de riscos** usando **DREAD** para priorizar ameaças identificadas.

### Tarefa Principal

1. Calcular riscos com DREAD
2. Priorizar ameaças por risco calculado
3. Justificar priorização de ameaças
4. Criar matriz de riscos

---

## ✅ Soluções Detalhadas

### Parte 1: Calcular Riscos com DREAD - SQL Injection em Busca

**Solução Esperada:**

#### DREAD Analysis

**D - Damage (Dano)**: 9/10
**Justificativa**: SQL Injection pode permitir acesso completo ao banco de dados, vazamento de informações sensíveis (senhas, dados pessoais, dados financeiros), e potencial modificação ou exclusão de dados. Em contexto financeiro ou com dados de cartão, pode violar PCI-DSS.

**R - Reproducibility (Reprodutibilidade)**: 10/10
**Justificativa**: Vulnerabilidade é 100% reprodutível. Qualquer atacante pode executar o payload `teste' OR '1'='1' --` repetidamente com o mesmo resultado. Não há aleatoriedade ou condições especiais necessárias.

**E - Exploitability (Explorabilidade)**: 9/10
**Justificativa**: Muito fácil de explorar. Não requer conhecimento técnico avançado, ferramentas especiais, ou acesso privilegiado. Basta conhecer SQL básico e ter acesso ao endpoint. Payloads são amplamente documentados online.

**A - Affected Users (Usuários Afetados)**: 10/10
**Justificativa**: Todos os usuários do sistema podem ser afetados. Se atacante conseguir acesso ao banco, pode acessar dados de todos os usuários. Em sistemas com muitos usuários, impacto é massivo.

**D - Discoverability (Descobribilidade)**: 10/10
**Justificativa**: Muito fácil de descobrir. Vulnerabilidade pode ser encontrada através de testes manuais simples, scanners automáticos (OWASP ZAP, Burp Suite), ou análise de código. Padrão vulnerável (concatenação de strings em SQL) é comum e amplamente conhecido.

**Risco Total**: (9 + 10 + 9 + 10 + 10) / 5 = 9.6/10

**Classificação**: Crítico

**Validação Técnica:**
- ✅ Todos os fatores DREAD calculados com justificativa
- ✅ Pontuações adequadas para SQL Injection
- ✅ Risco total calculado corretamente
- ✅ Classificação apropriada (Crítico)

---

### Parte 1: Calcular Riscos com DREAD - Broken Access Control em Perfil

**Solução Esperada:**

#### DREAD Analysis

**D - Damage**: 8/10
**Justificativa**: Permite acesso a dados pessoais de outros usuários. Em contexto financeiro, pode expor dados bancários. Em contexto educacional, pode expor dados de menores (violação LGPD). Impacto alto, mas não permite acesso completo ao banco.

**R - Reproducibility**: 10/10
**Justificativa**: 100% reprodutível. Qualquer usuário autenticado pode modificar `user_id` na URL e acessar dados de outros. Não há aleatoriedade ou condições especiais.

**E - Exploitability**: 9/10
**Justificativa**: Muito fácil de explorar. Não requer conhecimento técnico avançado. Basta estar autenticado e modificar ID na URL. Pode ser feito manualmente ou com scripts simples.

**A - Affected Users**: 9/10
**Justificativa**: Todos os usuários do sistema podem ser afetados (seus dados podem ser acessados por outros). Atacante pode enumerar IDs e acessar dados de múltiplos usuários.

**D - Discoverability**: 9/10
**Justificativa**: Fácil de descobrir. Vulnerabilidade pode ser encontrada através de testes manuais (modificar ID na URL), scanners automáticos, ou análise de código. Padrão vulnerável (falta de validação de propriedade) é comum.

**Risco Total**: (8 + 10 + 9 + 9 + 9) / 5 = 9.0/10

**Classificação**: Crítico

**Validação Técnica:**
- ✅ Todos os fatores DREAD calculados
- ✅ Pontuações adequadas para Broken Access Control
- ✅ Risco total calculado corretamente
- ✅ Classificação apropriada (Crítico)

---

### Parte 1: Calcular Riscos com DREAD - Senha Fraca Permitida

**Solução Esperada:**

#### DREAD Analysis

**D - Damage**: 6/10
**Justificativa**: Senhas fracas aumentam probabilidade de comprometimento de contas, mas não garantem acesso não autorizado. Atacante ainda precisa descobrir senha através de força bruta ou vazamentos. Impacto médio-alto.

**R - Reproducibility**: 10/10
**Justificativa**: 100% reprodutível. Sistema aceita senhas fracas consistentemente. Não há aleatoriedade.

**E - Exploitability**: 7/10
**Justificativa**: Explorável, mas requer mais esforço que SQL Injection ou IDOR. Atacante precisa descobrir senha através de força bruta (que pode ser bloqueada por rate limiting) ou vazamentos. Mais difícil que exploits diretos.

**A - Affected Users**: 8/10
**Justificativa**: Todos os usuários que criam senhas fracas são afetados. Usuários que criam senhas fortes não são diretamente afetados, mas sistema vulnerável em geral.

**D - Discoverability**: 10/10
**Justificativa**: Muito fácil de descobrir. Basta tentar criar conta com senha fraca. Pode ser descoberta através de testes manuais ou análise de política de senhas.

**Risco Total**: (6 + 10 + 7 + 8 + 10) / 5 = 8.2/10

**Classificação**: Alto

**Validação Técnica:**
- ✅ Todos os fatores DREAD calculados
- ✅ Pontuações adequadas para senha fraca (menos crítico que SQL Injection/IDOR)
- ✅ Risco total calculado corretamente
- ✅ Classificação apropriada (Alto, não Crítico)

---

### Parte 2: Criar Matriz de Riscos

**Solução Esperada:**

| Ameaça | DREAD Score | Classificação | Prioridade | Ação |
|--------|-------------|---------------|------------|------|
| SQL Injection em Busca | 9.6 | Crítico | P1 - IMEDIATO | Corrigir imediatamente (24h) |
| Broken Access Control em Perfil | 9.0 | Crítico | P1 - IMEDIATO | Corrigir imediatamente (24h) |
| Senha Fraca Permitida | 8.2 | Alto | P2 - Este Sprint | Corrigir em 3 dias |

**Matriz Visual:**

```
Risco vs Prioridade:
┌─────────────────────────────────────────┐
│ DREAD Score  │ Classificação │ Ação    │
├─────────────────────────────────────────┤
│ 9.0 - 10.0   │ Crítico       │ 24h     │
│ 7.0 - 8.9    │ Alto          │ 3 dias  │
│ 5.0 - 6.9    │ Médio         │ 1 semana│
│ 3.0 - 4.9    │ Baixo         │ 2 semanas│
└─────────────────────────────────────────┘
```

**Validação Técnica:**
- ✅ Matriz criada com todas as ameaças
- ✅ Ordenação por risco (maior para menor)
- ✅ Classificação e prioridade definidas
- ✅ Ações específicas definidas

---

### Parte 3: Justificar Priorização

**Solução Esperada:**

**Justificativa para Priorização:**

**P1 - IMEDIATO (SQL Injection, Broken Access Control):**
- **Risco Crítico**: DREAD score > 9.0
- **Impacto Imediato**: Podem ser explorados facilmente e causar danos críticos
- **Conformidade**: Violação de compliance (LGPD, PCI-DSS) se não corrigido rapidamente
- **Exposição**: Ameaças facilmente descobertas e exploráveis

**P2 - Este Sprint (Senha Fraca):**
- **Risco Alto**: DREAD score 8.2
- **Impacto Significativo**: Aumenta probabilidade de comprometimento de contas
- **Esforço**: Geralmente mais fácil de corrigir (implementar política de senhas forte)
- **Prevenção**: Previne comprometimento futuro de contas

**Consideração por Contexto:**

**Financeiro:**
- SQL Injection: Prioridade máxima (acesso a dados bancários, violação PCI-DSS)
- Broken Access Control: Prioridade máxima (acesso a contas bancárias de outros)
- Senha Fraca: Prioridade alta (acesso a contas bancárias)

**Educacional:**
- SQL Injection: Prioridade máxima (acesso a dados de menores, violação LGPD)
- Broken Access Control: Prioridade máxima (acesso a dados de menores)
- Senha Fraca: Prioridade alta (acesso a dados de menores)

**Ecommerce:**
- SQL Injection: Prioridade máxima (acesso a dados de clientes e pagamentos)
- Broken Access Control: Prioridade máxima (acesso a pedidos de outros)
- Senha Fraca: Prioridade alta (acesso a contas e pedidos)

**Validação Técnica:**
- ✅ Priorização justificada com base em risco
- ✅ Contexto considerado (Financeiro, Educacional, Ecommerce)
- ✅ Ações específicas definidas (prazos, responsáveis)

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Cálculo DREAD:**
- [ ] DREAD aplicado para pelo menos 2 ameaças
- [ ] Todos os 5 fatores (D, R, E, A, D) calculados para cada ameaça
- [ ] Pontuações justificadas (não apenas números)
- [ ] Risco total calculado corretamente

**Priorização:**
- [ ] Ameaças ordenadas por risco (maior para menor)
- [ ] Classificação definida (Crítico/Alto/Médio/Baixo)
- [ ] Prioridade definida (P1/P2/P3)

**Matriz:**
- [ ] Matriz de riscos criada
- [ ] Todas as ameaças incluídas na matriz

### ⭐ Importantes (Recomendados para Resposta Completa)

**Cálculo DREAD:**
- [ ] DREAD aplicado para 3+ ameaças
- [ ] Justificativas detalhadas para cada pontuação
- [ ] Comparação entre ameaças (por que uma é mais crítica que outra)

**Priorização:**
- [ ] Priorização justificada (por que cada prioridade)
- [ ] Contexto considerado (Financeiro, Educacional, Ecommerce)
- [ ] Ações específicas definidas (prazos, responsáveis)

**Matriz:**
- [ ] Matriz visual criada
- [ ] Classificações e prioridades bem definidas

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Análise de Risco:**
- [ ] Análise de risco detalhada (probabilidade, impacto)
- [ ] Considera múltiplos fatores (técnico, negócio, compliance)
- [ ] Análise de tendências (ameaças similares)

**Aplicação:**
- [ ] Matriz aplicada em projeto real
- [ ] Priorização validada com time
- [ ] Processo de revisão documentado

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Aplicação DREAD**: Aluno consegue aplicar DREAD sistematicamente?
2. **Cálculo de Risco**: Aluno calcula riscos corretamente?
3. **Priorização**: Aluno prioriza ameaças adequadamente?

### Erros Comuns

1. **Erro: Pontuações sem justificativa**
   - **Situação**: Aluno atribui pontuações DREAD sem explicar por quê
   - **Feedback**: "Boa aplicação de DREAD! Para tornar análise mais útil, justifique cada pontuação: por que Damage é 9/10 e não 10/10? Por que Exploitability é 9/10? Justificativas ajudam a validar cálculo de risco."

2. **Erro: Não considerar contexto**
   - **Situação**: Aluno prioriza ameaças sem considerar contexto (Financeiro vs Educacional)
   - **Feedback**: "Boa priorização! Lembre-se de considerar contexto: em Financeiro, SQL Injection pode violar PCI-DSS (prioridade máxima). Em Educacional, acesso a dados de menores viola LGPD (prioridade máxima). Adapte priorização ao contexto."

### Dicas para Feedback

- ✅ **Reconheça**: Aplicação sistemática de DREAD, justificativas claras, priorização adequada
- ❌ **Corrija**: Pontuações sem justificativa, cálculo incorreto, priorização sem contexto
- 💡 **Incentive**: Análise de risco detalhada, consideração de múltiplos fatores, aplicação prática

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Priorização Objetiva**: DREAD fornece metodologia quantitativa para priorizar
2. **Habilidade Essencial**: QA precisa saber priorizar riscos de segurança
3. **Eficiência**: Priorização correta aloca recursos adequadamente
4. **Compliance**: Priorização considerando compliance é essencial

**Conexão com o Curso:**
- Aula 1.4: Threat Modeling (teoria) → Este exercício (prática de priorização)
- Pré-requisito para: Exercícios avançados de threat modeling (1.4.4-1.4.5)
- Base para: Priorização de vulnerabilidades em projetos reais

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**DREAD para SQL Injection:**
"D-Damage: 9/10 - Acesso completo ao banco, vazamento de dados sensíveis, violação PCI-DSS. R-Reproducibility: 10/10 - 100% reprodutível, qualquer payload funciona sempre. E-Exploitability: 9/10 - Muito fácil, não requer conhecimento avançado. A-Affected Users: 10/10 - Todos os usuários afetados. D-Discoverability: 10/10 - Muito fácil de descobrir. Risco Total: 9.6/10 - Crítico. Prioridade: P1 - IMEDIATO (24h)."

**Matriz:**
"SQL Injection (9.6) - Crítico - P1 - Corrigir 24h. Broken Access Control (9.0) - Crítico - P1 - Corrigir 24h. Senha Fraca (8.2) - Alto - P2 - Corrigir 3 dias. Justificativa: SQL Injection e IDOR são críticos pois permitem acesso imediato. Senha fraca é alto mas requer mais esforço para explorar."

**Características da Resposta:**
- ✅ DREAD aplicado completamente com justificativas
- ✅ Risco total calculado corretamente
- ✅ Priorização justificada
- ✅ Contexto considerado

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
