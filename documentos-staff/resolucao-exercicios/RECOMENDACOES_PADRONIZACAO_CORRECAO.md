# 📋 Recomendações para Padronizar a Correção entre Monitores

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano

---

## 🎯 Objetivo

Este documento fornece recomendações práticas para garantir que diferentes monitores apliquem critérios de avaliação de forma consistente e uniforme ao corrigir exercícios.

---

## 📊 Sistema de Avaliação Qualitativa

### Critérios Estabelecidos

Todos os gabaritos seguem o mesmo padrão de critérios **qualitativos** (sem pontuação numérica):

#### ✅ Essenciais (Obrigatórios para Aprovação)
- **O que são**: Critérios fundamentais que devem estar presentes na resposta para aprovação
- **Como aplicar**: Se faltar algum critério essencial, a resposta não está completa
- **Flexibilidade**: Reconheça quando aluno tenta responder mas não consegue - dê feedback construtivo

#### ⭐ Importantes (Recomendados para Resposta Completa)
- **O que são**: Critérios que elevam a qualidade da resposta e demonstram compreensão aprofundada
- **Como aplicar**: Considerar quando aluno demonstra conhecimento além do básico
- **Flexibilidade**: Reconheça esforço mesmo quando não está perfeito - valorize progresso

#### 💡 Diferencial (Demonstram Conhecimento Avançado)
- **O que são**: Critérios que mostram conhecimento avançado e aplicação prática
- **Como aplicar**: Reconhecer quando aluno vai além do esperado
- **Flexibilidade**: Incentive mas não penalize se não estiver presente - é diferencial, não obrigatório

---

## 🆕 Atualizações Recentes (Módulo 2)

Ao corrigir exercícios do Módulo 2, valide os itens específicos abaixo quando aplicável:

- **2.4.1 (SAST no GitHub Actions)**: evidência de **regra de proteção de branch** exigindo check do SAST
- **2.4.2 (DAST no CI/CD)**: relatório como **artefato** e execução **após deploy em staging**
- **2.4.3 (Quality Gates)**: bloqueio em **Critical/High**, aprovação manual para **Medium** e **notificações**
- **2.5.1 (Snyk)**: **integração com GitHub**, scan inicial e **alertas configurados**
- **2.5.3 (SBOM)**: incluir **dependências transitivas** e geração **automatizada no CI**

Use esses itens como referência nos critérios **Essenciais**.

---

## 📖 Processo de Correção Padronizado

### Passo 1: Preparação (Antes de Corrigir)

1. **Leia o Gabarito Correspondente**
   - Abra o gabarito do exercício específico
   - Leia o enunciado completo para contexto
   - Revise a seção "Soluções Detalhadas"

2. **Entenda os Critérios**
   - Identifique critérios Essenciais (obrigatórios)
   - Identifique critérios Importantes (recomendados)
   - Identifique critérios Diferencial (avançado)

3. **Familiarize-se com a Seção "Pontos Importantes para Monitores"**
   - Revise erros comuns documentados
   - Revise exemplos de boas respostas
   - Entenda o contexto pedagógico

### Passo 2: Correção (Durante)

1. **Leia a Resposta do Aluno Completa**
   - Leia toda a resposta antes de avaliar
   - Não julgue apenas pelo início ou por uma parte
   - Entenda o contexto e intenção do aluno

2. **Avalie Critérios Essenciais Primeiro**
   - Verifique se critérios essenciais estão presentes
   - Use checklist: [ ] Presente / [ ] Ausente / [ ] Parcialmente presente
   - **Regra de Ouro**: Se maioria dos critérios essenciais está presente, considere aprovação

3. **Avalie Critérios Importantes**
   - Verifique qualidade da resposta (além do essencial)
   - Reconheça quando aluno demonstra compreensão aprofundada
   - **Regra de Ouro**: Reconheça esforço e progresso, mesmo que não perfeito

4. **Reconheça Critérios Diferencial (Se Presentes)**
   - Identifique quando aluno vai além do esperado
   - Reconheça conhecimento avançado ou aplicação prática
   - **Regra de Ouro**: Valorize mas não penalize ausência

5. **Valide Múltiplas Abordagens**
   - Consulte seção "Variações Aceitáveis" no gabarito
   - Reconheça quando aluno usa abordagem diferente mas válida
   - **Regra de Ouro**: Avalie conteúdo, não apenas formato

### Passo 3: Feedback (Após Correção)

1. **Use a Seção "Pontos Importantes para Monitores"**
   - Consulte "Erros Comuns" se resposta estiver incorreta
   - Use feedback sugerido como referência
   - Adapte feedback para contexto específico do aluno

2. **Dê Feedback Construtivo**
   - ✅ **Reconheça**: O que está correto e bem feito
   - ❌ **Corrija**: O que está incorreto de forma educativa
   - 💡 **Incentive**: Melhorias e próximos passos

3. **Seja Específico e Acionável**
   - Em vez de "melhore sua resposta"
   - Diga "inclua validação de entrada antes de usar na query SQL"
   - **Regra de Ouro**: Feedback específico ajuda aluno a melhorar

4. **Considere Múltiplas Respostas Válidas**
   - Consulte seção "Variações Aceitáveis" no gabarito
   - Reconheça quando resposta é válida mesmo que diferente do modelo
   - **Regra de Ouro**: Avalie qualidade técnica, não apenas correspondência exata

---

## ✅ Checklist para Monitores

Use este checklist antes de finalizar correção:

### Avaliação de Critérios
- [ ] Critérios Essenciais verificados (maioria presente = aprovação)
- [ ] Critérios Importantes considerados (qualidade da resposta)
- [ ] Critérios Diferencial reconhecidos (se presentes)
- [ ] Múltiplas abordagens validadas (se aplicável)

### Validação Técnica
- [ ] Solução técnica correta (se aplicável)
- [ ] Melhores práticas consideradas
- [ ] Compliance considerado (se aplicável)

### Feedback
- [ ] Feedback específico e acionável fornecido
- [ ] Erros corrigidos de forma educativa
- [ ] Melhorias sugeridas
- [ ] Progresso reconhecido

### Consistência
- [ ] Mesmo padrão aplicado para respostas similares
- [ ] Critérios aplicados uniformemente
- [ ] Feedback alinhado com seção "Pontos Importantes"

---

## 🎓 Guia Rápido: Quando Aprovar/Reprovar

### ✅ APROVAR quando:
- **Maioria dos critérios essenciais está presente** (ex: 4 de 5, ou 3 de 4)
- Solução técnica está correta (mesmo que não seja idêntica ao modelo)
- Aluno demonstra compreensão do conceito principal
- Resposta é válida mesmo que use abordagem diferente

### ⚠️ APROVAR COM OBSERVAÇÕES quando:
- **Todos os critérios essenciais estão presentes** mas resposta está incompleta
- Solução técnica está correta mas falta detalhamento
- Aluno demonstra compreensão mas pode melhorar
- **Ação**: Aprovar mas fornecer feedback detalhado para melhorias

### ❌ REPROVAR quando:
- **Maioria dos critérios essenciais está ausente** (ex: apenas 1 de 5, ou 1 de 4)
- Solução técnica está incorreta e não demonstra compreensão
- Resposta não demonstra conhecimento do conceito principal
- **Ação**: Reprovar mas fornecer feedback construtivo indicando o que falta

---

## 💡 Flexibilidade e Múltiplas Respostas Válidas

### Reconhecer Múltiplas Abordagens

**Exemplo 1: SQL Injection - Correção**
- **Modelo**: Prepared statements com placeholders (`?`)
- **Variações Aceitáveis**:
  - ORM (SQLAlchemy, Django ORM) que já implementam prepared statements
  - Bibliotecas específicas de validação e sanitização
  - Validação adicional de entrada (whitelist, regex)

**Como Avaliar**: Se solução previne SQL Injection de forma técnica correta, aceite mesmo que diferente do modelo.

---

### Reconhecer Compreensão vs. Execução Perfeita

**Exemplo 2: Threat Modeling - STRIDE**
- **Ideal**: Aluno aplica todas as 6 categorias (S, T, R, I, D, E) perfeitamente
- **Aceitável**: Aluno aplica 4-5 categorias e demonstra compreensão do conceito
- **Como Avaliar**: Se aluno demonstra compreensão do conceito e aplica maioria das categorias, reconheça progresso mesmo que não completo.

---

## 🔍 Validação Técnica: O que Verificar

### Código de Correção
- ✅ **Correto**: Previne vulnerabilidade de forma técnica adequada
- ⚠️ **Parcialmente Correto**: Previne vulnerabilidade mas falta alguma camada (ex: validação de entrada)
- ❌ **Incorreto**: Não previne vulnerabilidade ou introduz novos problemas

### Documentação
- ✅ **Completa**: Documentação clara e específica
- ⚠️ **Parcialmente Completa**: Documentação presente mas pode melhorar clareza
- ❌ **Incompleta**: Documentação ausente ou vaga

### Testes
- ✅ **Funcionais**: Testes executam e validam correção
- ⚠️ **Parcialmente Funcionais**: Testes existem mas podem melhorar cobertura
- ❌ **Não Funcionais**: Testes ausentes ou não validam correção

---

## 📝 Template de Feedback Padronizado

Use este template para dar feedback consistente:

```markdown
## Feedback - [Nome do Exercício]

### ✅ O que está correto:
- [Listar o que está correto e bem feito]
- [Reconhecer esforço e progresso]

### ❌ O que precisa melhorar:
- [Listar o que está incorreto ou incompleto]
- [Sugerir melhorias específicas]

### 💡 Próximos passos:
- [Sugerir como melhorar]
- [Indicar recursos ou próximas lições relevantes]

### 📊 Avaliação:
- **Essenciais**: [X] de [Y] presentes
- **Status**: [Aprovado / Aprovado com Observações / Reprovado]
- **Justificativa**: [Breve explicação]
```

---

## 🎯 Casos Especiais: Como Avaliar

### Caso 1: Resposta Parcialmente Correta

**Situação**: Aluno identifica vulnerabilidade corretamente mas correção está incompleta.

**Como Avaliar**:
- ✅ **Aprovar** se conceito principal está correto (identificação de vulnerabilidade)
- ⚠️ **Feedback**: "Boa identificação da vulnerabilidade! Sua correção está no caminho certo, mas considere também: [detalhar o que falta]"
- 💡 **Incentive**: "Com essa adição, sua correção ficará completa"

---

### Caso 2: Múltiplas Abordagens Válidas

**Situação**: Aluno usa abordagem diferente do modelo mas tecnicamente válida.

**Como Avaliar**:
- ✅ **Aprovar** se abordagem é tecnicamente válida
- ✅ **Reconhecer**: "Sua abordagem usando [ferramenta/método] é válida e também previne a vulnerabilidade"
- 💡 **Incentive**: "Existem múltiplas formas válidas de resolver isso. Sua abordagem é uma delas"

---

### Caso 3: Resposta Criativa mas Válida

**Situação**: Aluno propõe solução criativa que não está no modelo mas é válida.

**Como Avaliar**:
- ✅ **Aprovar** se solução é tecnicamente válida
- ✅ **Reconhecer**: "Sua abordagem criativa é válida e demonstra compreensão profunda"
- 💡 **Diferencial**: Considere como critério diferencial (conhecimento avançado)

---

### Caso 4: Erro Conceitual

**Situação**: Aluno confunde conceitos (ex: SQL Injection vs NoSQL Injection).

**Como Avaliar**:
- ⚠️ **Corrigir** mas reconhecer o que está certo: "Excelente identificação da vulnerabilidade! O código realmente tem injection, mas é NoSQL Injection (usa operadores MongoDB) em vez de SQL Injection. Ambos são tipos de Injection do OWASP Top 10."
- ✅ **Valorizar**: Identificação de vulnerabilidade está correta
- ❌ **Corrigir**: Tipo específico de injection precisa correção

---

## 📊 Matriz de Decisão Rápida

Use esta matriz para decisões rápidas e consistentes:

| Critérios Essenciais | Critérios Importantes | Critérios Diferencial | Decisão |
|---------------------|----------------------|----------------------|---------|
| Maioria presente (≥70%) | Presentes | Presentes | ✅ **Aprovar - Excelente** |
| Maioria presente (≥70%) | Presentes | Ausentes | ✅ **Aprovar - Completo** |
| Maioria presente (≥70%) | Parcialmente presentes | Qualquer | ✅ **Aprovar - Adequado** |
| Todos presentes | Ausentes | Qualquer | ✅ **Aprovar com Observações** |
| Menos de 50% presentes | Qualquer | Qualquer | ❌ **Reprovar - Incompleto** |

**Nota**: Sempre considere contexto e intenção do aluno. Se aluno demonstra compreensão mas execução está incompleta, considere aprovação com feedback detalhado.

---

## 🔄 Revisão e Calibração

### Quando em Dúvida:
1. **Consulte o gabarito**: Leia seção "Pontos Importantes para Monitores"
2. **Consulte exemplos**: Revise "Exemplos de Boas Respostas"
3. **Consulte colegas**: Discuta casos duvidosos com outros monitores
4. **Documente decisões**: Documente casos especiais para referência futura

### Calibração entre Monitores:
- **Revisar casos juntos**: Revisar amostra de respostas entre monitores
- **Alinhar critérios**: Garantir que todos aplicam critérios da mesma forma
- **Documentar decisões**: Documentar casos especiais para referência
- **Atualizar gabaritos**: Se padrões novos surgem, atualizar gabaritos

---

## ✅ Checklist Final antes de Finalizar Correção

- [ ] Gabarito correspondente lido e revisado
- [ ] Critérios Essenciais verificados (maioria presente = aprovação)
- [ ] Critérios Importantes considerados (qualidade da resposta)
- [ ] Critérios Diferencial reconhecidos (se presentes)
- [ ] Múltiplas abordagens validadas (se aplicável)
- [ ] Feedback específico e acionável fornecido
- [ ] Erros corrigidos de forma educativa
- [ ] Progresso reconhecido
- [ ] Decisão (Aprovar/Reprovar) justificada

---

## 📚 Referências

### Para Mais Informações:
- **Gabaritos Completos**: `documentos-staff/resolucao-exercicios/modulo-1/`
- **Estrutura Padrão**: Ver `documentos-staff/resolucao-exercicios/README.md`
- **Exemplos**: Consulte seção "Exemplos de Boas Respostas" em cada gabarito

---

## 🎯 Princípios Fundamentais

1. **Consistência**: Aplique mesmos critérios para respostas similares
2. **Flexibilidade**: Reconheça múltiplas abordagens válidas
3. **Construtividade**: Feedback deve ajudar aluno a melhorar
4. **Reconhecimento**: Valorize progresso e esforço, mesmo que não perfeito
5. **Transparência**: Seja claro sobre critérios e expectativas

---

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisão**: Anual (próxima revisão: 2026-01-15)
