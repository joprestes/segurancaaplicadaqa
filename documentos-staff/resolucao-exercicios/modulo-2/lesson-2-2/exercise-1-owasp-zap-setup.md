---
exercise_id: lesson-2-2-exercise-1-owasp-zap-setup
title: "Exercício 2.2.1: Configurar OWASP ZAP em Aplicação Web"
lesson_id: lesson-2-2
module: module-2
difficulty: "Básico"
last_updated: 2026-01-14
---

# Exercício 2.2.1: Configurar OWASP ZAP em Aplicação Web

## 📋 Enunciado Completo

Este exercício tem como objetivo **configurar OWASP ZAP do zero** e executar sua primeira análise DAST em uma aplicação web.

### Tarefa Principal

1. Instalar OWASP ZAP usando Docker
2. Preparar aplicação web para testar
3. Executar primeiro scan (passivo e ativo)
4. Analisar resultados e identificar top 5 vulnerabilidades
5. Configurar autenticação (opcional)
6. Criar relatório com análise dos findings

---

## ✅ Soluções Detalhadas

### Passo 1: Preparar Ambiente

**Solução Esperada:**
- Docker instalado e funcionando (`docker --version`)
- Aplicação web escolhida para teste (própria ou vulnerável de exemplo)
- Ambiente preparado para análise

**Verificações Comuns:**
- Docker instalado e funcionando (`docker --version`)
- Docker daemon rodando (Colima no macOS, systemd no Linux)
- Aplicação web acessível (testar com `curl http://localhost:3000`)

**Problemas Comuns:**
- Docker não instalado → Instalar Docker via CLI (Colima no macOS, docker.io no Linux)
- Docker daemon não rodando → `colima start` (macOS) ou `sudo systemctl start docker` (Linux)
- Porta 8080 ocupada → Mudar porta ou liberar porta
- Aplicação não acessível → Verificar se aplicação está rodando, verificar firewall

### Passo 2: Instalar e Configurar OWASP ZAP

**Solução Esperada:**

**2.1. Executar OWASP ZAP via Docker**
```bash
docker run -d --name zap \
  -p 8080:8080 \
  -p 8090:8090 \
  -v $(pwd)/zap-reports:/zap/wrk/:rw \
  owasp/zap2docker-stable zap-webswing.sh
```

**Verificações:**
- Container rodando: `docker ps | grep zap`
- Logs sem erros: `docker logs zap`
- Acessível: `curl http://localhost:8080/zap/` (retorna HTML)

**2.2. Primeira Acesso**
- URL: `http://localhost:8080/zap/`
- Interface web do ZAP será carregada
- Aguardar 30-60 segundos para inicialização completa

**Problemas Comuns:**
- ZAP não inicia → Verificar logs (`docker logs zap`), verificar memória disponível
- Interface não carrega → Aguardar mais tempo (pode levar até 2 minutos na primeira vez)
- Porta ocupada → Mudar porta (`-p 8081:8080`)

### Passo 3: Executar Primeiro Scan Passivo

**Solução Esperada:**

**3.1. Scan Passivo Básico**
```bash
docker exec zap zap-baseline.py -t http://localhost:3000
```

**Saída Esperada:**
```
PASS: Baseline Scan
Total of 12 URLs
PASS: No High risk vulnerabilities
WARN: 3 Medium risk vulnerabilities
INFO: 5 Low risk vulnerabilities
```

**Validação Técnica:**
- ✅ Scan completa sem erros
- ✅ Relatório mostra número de URLs testadas
- ✅ Vulnerabilidades categorizadas por severidade
- ⚠️ "PASS" significa que não há High/Critical, mas pode haver Medium/Low

**Tempo de Execução (Referência):**
- Scan passivo: 1-5 minutos (depende do tamanho da aplicação)

### Passo 4: Executar Scan Ativo Completo

**Solução Esperada:**

**4.1. Scan Ativo**
```bash
docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -J zap-report.json \
  -r zap-report.html
```

**Saída Esperada:**
```
PASS: Full Scan
Total of 127 URLs
PASS: No High risk vulnerabilities
WARN: 8 Medium risk vulnerabilities
INFO: 17 Low risk vulnerabilities
```

**Validação Técnica:**
- ✅ Scan completa sem erros
- ✅ Relatórios JSON e HTML gerados
- ✅ Mais vulnerabilidades encontradas que scan passivo (esperado)
- ⚠️ Scan ativo é mais lento (10-30 minutos)

**Tempo de Execução (Referência):**
- Scan ativo: 10-30 minutos (depende do tamanho da aplicação)

**Problemas Comuns:**
- Scan muito lento → Normal para scan ativo, pode otimizar (ver exercício 2.2.7)
- Scan falha → Verificar se aplicação está acessível, verificar logs do ZAP

### Passo 5: Analisar Resultados

**Solução Esperada:**

**5.1. Abrir Relatório HTML**
```bash
open zap-reports/zap-report.html  # macOS
xdg-open zap-reports/zap-report.html  # Linux
start zap-reports/zap-report.html  # Windows
```

**5.2. Explorar Findings**

No relatório HTML, aluno deve ver:
- Resumo geral (total de alertas, por severidade)
- Lista de alertas por tipo
- Detalhes de cada alerta (URL, parâmetro, payload, evidência)

**Interpretação dos Resultados:**

**High/Critical (Alto/Crítico):**
- SQL Injection, XSS, Command Injection, etc.
- Corrigir urgentemente (especialmente se em produção)

**Medium (Médio):**
- Missing Security Headers, Information Disclosure, etc.
- Corrigir quando possível (considerar contexto)

**Low/Informational (Baixo/Informativo):**
- Version disclosure, informações técnicas expostas
- Endereçar gradualmente

**Validação Técnica:**
- ✅ Aluno entende diferença entre severidades
- ✅ Aluno consegue identificar tipo de vulnerabilidade
- ⚠️ Aluno deve validar manualmente cada High/Critical (não confiar cegamente)

### Passo 6: Top 5 Vulnerabilidades

**Solução Esperada - Estrutura do Relatório:**

```markdown
## Top 5 Vulnerabilidades Identificadas

### Vulnerabilidade #1: SQL Injection em /api/users
- **Severidade DAST**: High 🔴
- **CWE**: CWE-89 (SQL Injection)
- **OWASP Top 10**: A03:2021 – Injection
- **URL**: `http://app.com/api/users?id=1`
- **Parâmetro**: `id`

**Evidência:**
```http
GET /api/users?id=1' OR '1'='1 HTTP/1.1

Response: 200 OK
[
  {"id": 1, "name": "User 1"},
  {"id": 2, "name": "User 2"},
  {"id": 3, "name": "User 3"}
]
```

**Payload Usado**: `1' OR '1'='1`

**Risco:**
- Exploitability: ALTA - Pode ser explorado facilmente via API
- Impacto: ALTO - Pode expor dados de todos os usuários
- Contexto: Endpoint em produção, dados sensíveis

**Correção Sugerida:**
```javascript
// ✅ Usar prepared statements
app.get('/api/users', (req, res) => {
  const userId = parseInt(req.query.id);
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    res.json(results);
  });
});
```

**Priorização:** P1 - Corrigir IMEDIATAMENTE
- High + Em produção + Dados sensíveis + Fácil explorar
```

**Critérios para Seleção do Top 5:**
1. Severidade (High/Critical primeiro)
2. Aplicação em produção
3. Dados sensíveis afetados
4. Exploitability alta
5. Compliance violado (PCI-DSS, LGPD)

### Passo 7: Configurar Autenticação (Opcional)

**Solução Esperada:**

**7.1. Criar Arquivo de Configuração**
{% raw %}
```xml
<!-- zap-auth.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<ZAP>
  <authentication>
    <method>form</method>
    <loginUrl>http://localhost:3000/login</loginUrl>
    <loginRequestData>email={%username%}&password={%password%}</loginRequestData>
    <loggedInIndicator>Dashboard</loggedInIndicator>
  </authentication>
  <users>
    <user>
      <username>test@example.com</username>
      <password>TestPass123!</password>
    </user>
  </users>
</ZAP>
```
{% endraw %}

**7.2. Executar Scan com Autenticação**
```bash
docker cp zap-auth.xml zap:/zap/wrk/zap-auth.xml

docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -c /zap/wrk/zap-auth.xml \
  -J zap-report-auth.json \
  -r zap-report-auth.html
```

**Validação:**
- ✅ Scan testa áreas protegidas (mais vulnerabilidades encontradas)
- ✅ Comparação entre scan sem e com autenticação

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Configuração Técnica:**
- [ ] OWASP ZAP instalado e rodando corretamente
- [ ] Aplicação web acessível e testada
- [ ] Scan passivo executado com sucesso
- [ ] Scan ativo executado com sucesso
- [ ] Relatórios HTML e JSON gerados

**Análise de Resultados:**
- [ ] Relatório HTML acessado e explorado
- [ ] Top 5 vulnerabilidades identificadas e documentadas

### ⭐ Importantes (Recomendados para Resposta Completa)

**Relatório de Análise:**
- [ ] Relatório criado com estrutura clara e organizada
- [ ] Cada vulnerabilidade documentada com:
  - Severidade, CWE, OWASP Top 10
  - Evidência (requisição/resposta)
  - Payload usado
  - Análise de risco (exploitability, impacto, contexto)
  - Correção sugerida

**Priorização:**
- [ ] Priorização realizada considerando:
  - Severidade DAST vs Risco Real
  - Contexto (produção vs staging)
  - Dados sensíveis afetados
  - Compliance aplicável (LGPD, PCI-DSS, etc.)

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Autenticação:**
- [ ] Autenticação configurada e testada
- [ ] Comparação entre scan sem e com autenticação

**Análise Avançada:**
- [ ] Identifica false positives e documenta razão claramente
- [ ] Considera contexto de negócio específico (financeiro, educacional, etc.)
- [ ] Propõe estratégia de correção com prazos

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Capacidade Técnica**: Aluno consegue configurar OWASP ZAP do zero?
2. **Interpretação de Resultados**: Aluno entende os findings?
3. **Priorização**: Aluno prioriza por risco real ou apenas severidade DAST?
4. **Análise Crítica**: Aluno diferencia true positives de false positives?

### Erros Comuns

1. **Erro: Não Validar Manualmente Findings**
   - **Situação**: Aluno assume que tudo que DAST reporta é vulnerabilidade real
   - **Feedback**: "Boa análise! DAST às vezes reporta false positives. Sempre valide cada High/Critical manualmente reproduzindo o ataque. Por exemplo, se DAST reporta SQL Injection mas aplicação retorna erro 400, pode ser false positive."

2. **Erro: Priorização Apenas por Severidade DAST**
   - **Situação**: Aluno prioriza High primeiro sem considerar contexto
   - **Feedback**: "Excelente identificação das vulnerabilidades! Lembre-se de que nem toda High é P1 se o endpoint não está em produção ou não afeta dados sensíveis. Considere: endpoint em produção? dados sensíveis? fácil explorar? Isso ajuda a priorizar por risco real."

3. **Erro: Não Configurar Autenticação**
   - **Situação**: Aluno não configura autenticação e testa apenas áreas públicas
   - **Feedback**: "Ótimo trabalho configurando OWASP ZAP! Para cobertura completa, configure autenticação para testar áreas protegidas. Isso encontra vulnerabilidades que só aparecem em áreas autenticadas."

4. **Erro: Não Analisar Evidência**
   - **Situação**: Aluno lista vulnerabilidades mas não analisa evidência (requisição/resposta)
   - **Feedback**: "Boa identificação! Para validar se vulnerabilidade é real, sempre analise a evidência (requisição e resposta). Se resposta mostra que ataque funcionou (ex: retornou dados de múltiplos usuários), é true positive."

### Dicas para Feedback

- ✅ **Reconheça**: Configuração técnica correta, análise detalhada, relatórios bem estruturados
- ❌ **Corrija**: Priorização incorreta, não considerar contexto, assumir que tudo é vulnerabilidade real
- 💡 **Incentive**: Validar findings manualmente, configurar autenticação, considerar contexto de negócio

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Base Prática**: Configurar OWASP ZAP é habilidade básica essencial para QA de segurança
2. **Interpretação de Resultados**: Ensina a interpretar findings DAST, não apenas ler relatórios
3. **Priorização Real**: Desenvolve capacidade de priorizar por risco real, não apenas severidade técnica
4. **Análise Crítica**: Ensina a validar findings e diferenciar true/false positives

**Conexão com o Curso:**
- Aula 2.2: DAST (teoria) → Este exercício (prática)
- Pré-requisito para: Exercício 2.2.3 (Integrar DAST no CI/CD)
- Base para: Módulo 3 (Aplicar DAST em contextos específicos)

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Relatório de Top 5 Vulnerabilities:**

```markdown
## Vulnerabilidade #1: SQL Injection - P1 IMEDIATO

**Severidade**: High 🔴  
**URL**: `http://app.com/api/users?id=1`  
**Parâmetro**: `id`  
**CWE**: CWE-89  
**OWASP**: A03:2021 – Injection  

**Evidência:**
```http
GET /api/users?id=1' OR '1'='1 HTTP/1.1

Response: 200 OK
[
  {"id": 1, "name": "User 1", "email": "user1@example.com"},
  {"id": 2, "name": "User 2", "email": "user2@example.com"}
]
```

**Análise de Risco:**
- Exploitability: ALTA - Pode ser explorado facilmente via API
- Impacto: CRÍTICO - Pode acessar dados de todos os usuários (LGPD violation)
- Contexto: Endpoint em produção, endpoint público, dados sensíveis

**Correção:**
```javascript
app.get('/api/users', (req, res) => {
  const userId = parseInt(req.query.id);
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    res.json(results);
  });
});
```

**Justificativa P1:**
- High + Em produção + Dados sensíveis + Fácil explorar = P1 IMEDIATO
```

**Características da Resposta:**
- ✅ Identifica vulnerabilidade corretamente
- ✅ Análise completa de risco (exploitability, impacto, contexto)
- ✅ Correção técnica adequada
- ✅ Priorização justificada
- ✅ Considera compliance (LGPD)

### Exemplo 2: Resposta Boa (Adequada)

**Relatório Simples:**
```markdown
## Vulnerabilidade #1: SQL Injection
- Severidade: High
- URL: /api/users?id=1
- Correção: Usar prepared statements
- Prioridade: P1
```

**Características da Resposta:**
- ✅ Identifica vulnerabilidade corretamente
- ✅ Propõe correção
- ⚠️ Priorização sem justificativa detalhada
- ⚠️ Não analisa risco completo (mas está correto)

---

## 🎯 Respostas Esperadas para Desafios Adicionais

### Desafio 1: Scan de API REST

**Solução Esperada:**

**1. Importar OpenAPI:**
```bash
docker exec zap zap-api-scan.py \
  -t http://api.com/openapi.json \
  -f openapi \
  -J zap-api.json \
  -r zap-api.html
```

**2. Configurar Autenticação para API:**
```xml
<authentication>
  <method>header</method>
  <headerName>Authorization</headerName>
  <headerValue>Bearer {%token%}</headerValue>
</authentication>
```

**3. Análise de Vulnerabilidades Específicas de APIs:**
- Autenticação/autorização
- Rate limiting
- Input validation
- Error handling

### Desafio 2: Otimização de Performance

**Solução Esperada:**

**Causas Comuns de Scan Lento:**
1. Aplicação muito grande (muitas URLs)
2. Políticas muito agressivas (muitos payloads)
3. Sem limitação de escopo

**Otimizações:**
1. Limitar escopo (apenas URLs críticas)
2. Reduzir profundidade de crawling
3. Usar scan passivo para validação rápida
4. Scan ativo apenas em URLs críticas

**Métricas de Sucesso:**
- Antes: 45 minutos
- Depois: Menos de 10 minutos (meta alcançada)
- Melhoria: Redução significativa (mais da metade do tempo original)

### Desafio 3: Integração Sem Quebrar Pipeline

**Solução Esperada:**

**1. Integração Não-Bloqueante Inicial:**
```yaml
- name: Run OWASP ZAP
  continue-on-error: true  # Não falha pipeline inicialmente
```

**2. Quality Gate Gradual:**
- Semana 1-2: Apenas reporta (não bloqueia)
- Semana 3-4: Bloqueia apenas Critical
- Mês 2+: Bloqueia Critical + High

---

---

## 📝 CRÉDITOS

═══════════════════════════════════════════════════════
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Baseado em**: Aula 2.2: DAST: Dynamic Application Security Testing  
**Referência**: Módulo 2 - Testes de Segurança na Prática  
**Data de revisão**: Janeiro/2026
═══════════════════════════════════════════════════════
