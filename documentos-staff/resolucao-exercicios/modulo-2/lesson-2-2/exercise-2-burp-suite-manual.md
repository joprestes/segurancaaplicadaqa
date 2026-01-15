---
exercise_id: lesson-2-2-exercise-2-burp-suite-manual
title: "Exercício 2.2.2: Testes Manuais com Burp Suite"
lesson_id: lesson-2-2
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-14
---

# Exercício 2.2.2: Testes Manuais com Burp Suite

## 📋 Enunciado Completo

Este exercício tem como objetivo **aprender a usar Burp Suite para testes manuais de segurança**, interceptando e modificando requisições HTTP para encontrar vulnerabilidades.

### Tarefa Principal

1. Instalar Burp Suite Community Edition
2. Configurar proxy no navegador
3. Interceptar e modificar requisições HTTP
4. Usar Burp Suite Repeater para testes repetidos
5. Usar Burp Suite Intruder para testes automatizados
6. Executar scan automatizado
7. Documentar vulnerabilidades encontradas

---

## ✅ Soluções Detalhadas

### Passo 1: Instalar Burp Suite

**Solução Esperada:**
- Burp Suite Community Edition instalado
- Burp Suite inicia corretamente
- Interface principal acessível

**Verificações Comuns:**
- Burp Suite instalado e inicia sem erros
- Proxy padrão configurado em 127.0.0.1:8080

**Problemas Comuns:**
- Burp Suite não inicia → Verificar Java instalado (Burp requer Java)
- Porta 8080 ocupada → Mudar porta do proxy no Burp Suite

### Passo 2: Configurar Proxy no Navegador

**Solução Esperada:**

**2.1. Instalar Certificado CA**
1. Burp Suite → Proxy → Options → Import / Export CA Certificate
2. Exportar certificado em formato DER
3. Instalar certificado no navegador (processo varia por SO)

**2.2. Configurar Proxy**
- Proxy: 127.0.0.1:8080
- Porta: 8080

**Verificações:**
- Certificado instalado corretamente (sem erros SSL)
- Navegação funciona através do proxy
- Requisições aparecem no Burp Suite

**Problemas Comuns:**
- Erro SSL → Certificado CA não instalado corretamente
- Navegação não funciona → Proxy não configurado no navegador

### Passo 3: Interceptar e Modificar Requisições

**Solução Esperada:**

**3.1. Interceptar Requisição**
1. Ativar interceptação: Proxy → Intercept → "Intercept is on"
2. Navegar para aplicação
3. Requisição aparece no Burp Suite

**3.2. Modificar Requisição**
- Modificar parâmetros (ex: `id=1' OR '1'='1`)
- Clicar em "Forward" para enviar
- Observar resposta no navegador

**Validação:**
- ✅ Aluno consegue interceptar requisições
- ✅ Aluno consegue modificar requisições
- ✅ Aluno observa impacto das modificações

### Passo 4: Usar Repeater

**Solução Esperada:**

**4.1. Enviar para Repeater**
1. Clicar com botão direito na requisição
2. Selecionar "Send to Repeater"
3. Ir para aba "Repeater"

**4.2. Modificar e Reenviar**
- Modificar parâmetros
- Clicar em "Send"
- Analisar resposta
- Repetir com diferentes payloads

**Validação:**
- ✅ Aluno usa Repeater para testes repetidos
- ✅ Aluno testa múltiplos payloads
- ✅ Aluno analisa respostas

### Passo 5: Usar Intruder

**Solução Esperada:**

**5.1. Configurar Intruder**
1. Enviar requisição para Intruder
2. Marcar posição (parâmetro a ser testado)
3. Selecionar attack type (ex: "Sniper")
4. Adicionar payloads

**5.2. Executar Ataque**
- Clicar em "Start attack"
- Observar resultados em tabela
- Analisar respostas diferentes

**Validação:**
- ✅ Aluno configura Intruder corretamente
- ✅ Aluno executa ataque automatizado
- ✅ Aluno identifica respostas diferentes (possíveis vulnerabilidades)

### Passo 6: Executar Scan Automatizado

**Solução Esperada:**

**6.1. Enviar para Scanner**
1. Clicar com botão direito na requisição
2. Selecionar "Scan"
3. Ou ir em "Scanner" → "New scan"

**6.2. Analisar Resultados**
- Ver lista de vulnerabilidades
- Clicar em cada vulnerabilidade para ver detalhes
- Analisar evidência e recomendações

**Validação:**
- ✅ Aluno executa scan automatizado
- ✅ Aluno analisa resultados do scan
- ✅ Aluno entende diferença entre scan manual e automatizado

### Passo 7: Documentar Vulnerabilidades

**Solução Esperada - Estrutura do Relatório:**

```markdown
## Vulnerabilidade: SQL Injection em /api/users

### Detalhes
- **Severidade**: High
- **URL**: `http://app.com/api/users`
- **Método**: GET
- **Parâmetro**: `id`
- **CWE**: CWE-89

### Como Encontrei
1. Interceptei requisição GET no Burp Suite
2. Modifiquei parâmetro `id` para `1' OR '1'='1`
3. Enviei requisição modificada
4. Observado: Resposta retornou dados de múltiplos usuários

### Evidência
[Requisição e resposta HTTP]

### Impacto
[Qual o impacto se explorado?]

### Correção
[Como corrigir?]
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Configuração Técnica:**
- [ ] Burp Suite instalado e funcionando
- [ ] Proxy configurado no navegador
- [ ] Certificado CA instalado
- [ ] Requisições sendo interceptadas

**Uso de Ferramentas:**
- [ ] Requisições modificadas e testadas
- [ ] Repeater usado para testes repetidos
- [ ] Intruder usado para testes automatizados
- [ ] Scan automatizado executado

**Documentação:**
- [ ] Pelo menos 3 vulnerabilidades encontradas e documentadas

### ⭐ Importantes (Recomendados para Resposta Completa)

**Análise de Vulnerabilidades:**
- [ ] Cada vulnerabilidade documentada com:
  - Como foi encontrada (passos)
  - Evidência (requisição/resposta)
  - Impacto
  - Correção sugerida

**Uso Avançado:**
- [ ] Múltiplos payloads testados no Intruder
- [ ] Análise de respostas diferentes
- [ ] Comparação entre scan manual e automatizado

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Análise Profunda:**
- [ ] Vulnerabilidades complexas encontradas (não apenas básicas)
- [ ] Uso criativo de payloads
- [ ] Análise de contexto e impacto detalhada

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Capacidade Técnica**: Aluno consegue usar Burp Suite para testes manuais?
2. **Exploração Manual**: Aluno consegue explorar vulnerabilidades manualmente?
3. **Análise de Resultados**: Aluno entende o que encontrou?

### Erros Comuns

1. **Erro: Não Instalar Certificado CA**
   - **Feedback**: "Boa configuração do proxy! Para testar HTTPS, instale o certificado CA do Burp Suite no navegador. Isso permite interceptar requisições HTTPS sem erros SSL."

2. **Erro: Não Analisar Respostas**
   - **Feedback**: "Ótimo uso do Intruder! Lembre-se de analisar as respostas. Respostas diferentes (tamanho, status code, conteúdo) podem indicar vulnerabilidades."

---

---

## 📝 CRÉDITOS

═══════════════════════════════════════════════════════
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Baseado em**: Aula 2.2: DAST: Dynamic Application Security Testing  
**Referência**: Módulo 2 - Testes de Segurança na Prática  
**Data de revisão**: Janeiro/2026
═══════════════════════════════════════════════════════
