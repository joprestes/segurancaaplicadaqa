---
layout: exercise
title: "Exercício 2.2.1: Configurar OWASP ZAP em Aplicação Web"
slug: "owasp-zap-setup"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Básico"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-1-owasp-zap-setup/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

## Objetivo

Este exercício tem como objetivo **configurar OWASP ZAP do zero** e executar sua primeira análise DAST em uma aplicação web.

Ao completar este exercício, você será capaz de:

- Instalar e configurar OWASP ZAP usando Docker
- Executar scan passivo e ativo em aplicação web
- Interpretar resultados do OWASP ZAP
- Identificar e priorizar top 5 vulnerabilidades encontradas
- Configurar autenticação para testar áreas protegidas

---

## Descrição

Você vai configurar OWASP ZAP do zero, executar scans em uma aplicação web (própria ou de exemplo), analisar os resultados e identificar vulnerabilidades de segurança.

### Contexto

Como QA de segurança, é fundamental saber configurar e usar ferramentas DAST. OWASP ZAP é uma das ferramentas mais populares e este exercício desenvolve essa habilidade prática.

### Tarefa Principal

1. Instalar OWASP ZAP usando Docker
2. Preparar aplicação web para testar
3. Executar primeiro scan (passivo e ativo)
4. Analisar resultados e identificar top 5 vulnerabilidades
5. Configurar autenticação (opcional)
6. Criar relatório com análise dos findings

---

## Pré-requisitos

- Docker instalado e funcionando
- Aplicação web para teste (própria ou de exemplo)
- Acesso ao terminal e navegador

---

## Passo a Passo

### Passo 1: Preparar Ambiente

**1.1. Instalar Docker (se não tiver)**

```bash
# macOS (usando Colima - solução via CLI, sem Docker Desktop)
brew install colima docker docker-compose
colima start

# Linux (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker

# Linux (Fedora/RHEL)
sudo dnf install -y docker docker-compose
sudo systemctl start docker
sudo systemctl enable docker

# Windows (usando WSL2 + Docker Engine)
# Instalar WSL2 e depois:
# wsl --install
# No WSL2, seguir instruções Linux acima

# Verificar instalação
docker --version
docker-compose --version
```

**1.2. Preparar Aplicação Web para Testar**

Escolha um dos seguintes:

- **Opção A**: Usar aplicação própria (preferido)
  - Escolha uma aplicação web que você já trabalha
  - Ou crie uma aplicação simples de exemplo (Node.js, Python Flask, etc.)

- **Opção B**: Usar aplicação vulnerável de exemplo
  ```bash
  # OWASP Juice Shop (aplicação vulnerável moderna)
  docker run -d -p 3000:3000 bkimminich/juice-shop
  
  # Ou OWASP WebGoat
  docker run -d -p 8080:8080 webgoat/goatandwolf
  
  # Acessar: http://localhost:3000 (Juice Shop) ou http://localhost:8080 (WebGoat)
  ```

### Passo 2: Instalar e Configurar OWASP ZAP

**2.1. Executar OWASP ZAP via Docker**

```bash
# Baixar e executar OWASP ZAP
docker run -d --name zap \
  -p 8080:8080 \
  -p 8090:8090 \
  -v $(pwd)/zap-reports:/zap/wrk/:rw \
  owasp/zap2docker-stable zap-webswing.sh

# Verificar se está rodando
docker ps | grep zap

# Aguardar ZAP inicializar (pode levar 30-60 segundos)
# Verificar logs
docker logs -f zap
```

**2.2. Acessar OWASP ZAP**

- Abrir navegador em: `http://localhost:8080/zap/`
- Interface web do ZAP será carregada
- **Importante**: Primeira vez pode demorar alguns segundos para carregar

**2.3. Verificar Status**

- Dashboard deve mostrar interface do ZAP ✅
- Verificar que ZAP está pronto para usar

### Passo 3: Executar Primeiro Scan Passivo

**3.1. Scan Passivo Básico (via linha de comando)**

```bash
# Executar scan passivo rápido
docker exec zap zap-baseline.py -t http://localhost:3000

# Ou se usar aplicação em outro host:
docker exec zap zap-baseline.py -t http://app-staging.com

# O scan passivo:
# - Analisa requisições/respostas sem enviar payloads maliciosos
# - Detecta headers inseguros, informações expostas, etc.
# - É rápido e seguro
```

**3.2. Verificar Resultados do Scan Passivo**

O scan passivo gera relatório no terminal. Você verá:
- Número de alertas encontrados
- Severidade (High, Medium, Low, Informational)
- URLs testadas

### Passo 4: Executar Scan Ativo Completo

**4.1. Scan Ativo (via linha de comando)**

```bash
# Executar scan ativo completo
docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -J zap-report.json \
  -r zap-report.html

# O scan ativo:
# - Envia payloads de teste maliciosos
# - Testa SQL Injection, XSS, Command Injection, etc.
# - É mais lento mas encontra vulnerabilidades reais
# - Pode causar problemas se aplicação não estiver preparada
```

**4.2. Aguardar Processamento**

- O scan ativo pode levar 10-30 minutos dependendo do tamanho da aplicação
- Você verá logs do processo no terminal
- Ao final, verá: "PASS" ou "FAIL" com resumo

**4.3. Verificar Relatórios Gerados**

```bash
# Verificar que relatórios foram gerados
ls -la zap-reports/

# Deve conter:
# - zap-report.json (formato JSON)
# - zap-report.html (formato HTML - abrir no navegador)
```

### Passo 5: Analisar Resultados no OWASP ZAP

**5.1. Abrir Relatório HTML**

```bash
# Abrir relatório HTML no navegador
open zap-reports/zap-report.html  # macOS
xdg-open zap-reports/zap-report.html  # Linux
start zap-reports/zap-report.html  # Windows
```

**5.2. Explorar Findings**

No relatório HTML, você verá:

1. **Resumo Geral**:
   - Total de alertas
   - Por severidade (High, Medium, Low, Informational)
   - URLs testadas

2. **Alertas por Tipo**:
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Missing Security Headers
   - Information Disclosure
   - etc.

3. **Detalhes de Cada Alerta**:
   - URL afetada
   - Parâmetro vulnerável
   - Payload usado
   - Evidência (resposta da aplicação)
   - Recomendações de correção

**5.3. Usar Interface Web do ZAP (Opcional)**

Se preferir usar interface web:

1. Acessar `http://localhost:8080/zap/`
2. Ir em "Quick Start" → "Automated Scan"
3. Inserir URL: `http://localhost:3000`
4. Clicar em "Attack"
5. Aguardar scan completar
6. Ver resultados em "Alerts" tab

### Passo 6: Identificar Top 5 Vulnerabilidades

**6.1. Criar Relatório de Análise**

Para cada vulnerabilidade identificada, documente:

```markdown
## Vulnerabilidade #1: [Nome/Tipo]

### Detalhes
- **Severidade**: High / Medium / Low
- **URL**: `http://app.com/api/users?id=1`
- **Parâmetro**: `id`
- **CWE**: CWE-XX (se disponível)
- **OWASP Top 10**: AXX:2021 – [Categoria]

### Descrição
[Descrição detalhada do problema]

### Evidência
```http
GET /api/users?id=1' OR '1'='1 HTTP/1.1

Response: 200 OK
[
  {"id": 1, "name": "User 1"},
  {"id": 2, "name": "User 2"}
]
```

### Payload Usado
```
1' OR '1'='1
```

### Risco
[Qual o risco real? Pode ser explorado? Qual o impacto?]

### Correção Sugerida
[Como corrigir a vulnerabilidade]

### Priorização
- [ ] P1 - Corrigir IMEDIATAMENTE
- [ ] P2 - Corrigir neste Sprint
- [ ] P3 - Corrigir no próximo Sprint
- [ ] P4 - Backlog

### Validação
- [ ] É True Positive? (vulnerabilidade real)
- [ ] É False Positive? (não é vulnerabilidade real)
- [ ] Aplicação está em produção?
- [ ] Dados sensíveis afetados?
```

**6.2. Priorizar por Risco Real**

Considere:
- Severidade DAST vs Risco Real
- Exploitability (fácil explorar?)
- Impacto (dados sensíveis?)
- Contexto (aplicação em produção?)

### Passo 7: Configurar Autenticação (Opcional)

**7.1. Criar Arquivo de Configuração de Autenticação**

Criar arquivo `zap-auth.xml`:

{% raw %}
```xml
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
# Copiar arquivo de autenticação para container
docker cp zap-auth.xml zap:/zap/wrk/zap-auth.xml

# Executar scan com autenticação
docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -c /zap/wrk/zap-auth.xml \
  -J zap-report-auth.json \
  -r zap-report-auth.html
```

**7.3. Comparar Resultados**

- Scan sem autenticação: Testa apenas áreas públicas
- Scan com autenticação: Testa áreas protegidas também
- Comparar número de vulnerabilidades encontradas

---

## Desafios Adicionais (Para QAs Plenos)

Se você já tem experiência básica com OWASP ZAP, teste seus conhecimentos com estes desafios:

### Desafio 1: Scan de API REST

**Cenário**: Você precisa testar uma API REST que usa OpenAPI/Swagger.

**Tarefa**:
1. Importar documentação OpenAPI no ZAP
2. Configurar autenticação via header (Bearer token)
3. Executar scan focado em APIs
4. Analisar vulnerabilidades específicas de APIs (autenticação, autorização, rate limiting)

**Entregáveis**:
- Configuração de autenticação para API
- Relatório de scan de API
- Análise de vulnerabilidades encontradas

### Desafio 2: Otimização de Performance

**Cenário**: O scan está demorando 45 minutos para completar. Você precisa reduzir para menos de 10 minutos.

**Tarefa**:
1. Identifique causas do scan lento (muitas URLs? políticas muito agressivas?)
2. Otimize configuração para reduzir tempo
3. Configure scan apenas em URLs críticas
4. Documente otimizações realizadas

**Entregáveis**:
- Configuração otimizada (antes/depois)
- Tempo de scan reduzido (meta: < 10 minutos)
- Documentação de otimizações

### Desafio 3: Integração Sem Quebrar Pipeline

**Cenário**: Projeto já tem pipeline CI/CD complexo. Você precisa adicionar DAST sem quebrar o fluxo existente.

**Tarefa**:
1. Analise pipeline existente
2. Integre OWASP ZAP como etapa adicional (não bloqueia inicialmente)
3. Configure Quality Gate que falha apenas Critical
4. Teste integração com deploy real

**Entregáveis**:
- Pipeline atualizado com DAST
- Documentação de integração
- Plano de evolução do Quality Gate

---

## Troubleshooting: Problemas Comuns e Soluções

### Problema 1: OWASP ZAP Não Inicia (Docker)

**Sintoma**: `docker ps` mostra container, mas `http://localhost:8080` não responde

**Soluções**:
```bash
# 1. Verificar logs para erros
docker logs zap

# 2. Verificar se porto está disponível
lsof -i :8080  # macOS/Linux
netstat -ano | findstr :8080  # Windows

# 3. Verificar se container está rodando
docker ps | grep zap

# 4. Reiniciar container
docker restart zap

# 5. Se ainda não funcionar, recriar container
docker stop zap
docker rm zap
docker run -d --name zap -p 8080:8080 -p 8090:8090 owasp/zap2docker-stable zap-webswing.sh
```

### Problema 2: Scan Falha com "Connection Refused"

**Sintoma**: `ERROR: Connection refused` ao tentar scan

**Soluções**:
```bash
# 1. Verificar se aplicação está rodando
curl http://localhost:3000  # Ou URL da sua aplicação

# 2. Verificar se aplicação está acessível do container
docker exec zap curl http://host.docker.internal:3000  # macOS/Windows
docker exec zap curl http://172.17.0.1:3000  # Linux

# 3. Se aplicação está em outro host, usar IP/hostname correto
docker exec zap zap-baseline.py -t http://app-staging.com

# 4. Verificar firewall/network
# Certifique-se que aplicação está acessível
```

### Problema 3: Scan Muito Lento (>30 minutos)

**Sintoma**: Scan demora muito tempo para completar

**Soluções**:
```bash
# 1. Usar scan passivo apenas (mais rápido)
docker exec zap zap-baseline.py -t http://localhost:3000

# 2. Limitar escopo (apenas URLs específicas)
docker exec zap zap-baseline.py -t http://localhost:3000 -I ".*api.*"

# 3. Reduzir profundidade de crawling
docker exec zap zap-full-scan.py -t http://localhost:3000 -m 3

# 4. Usar políticas menos agressivas
# (configurar políticas customizadas no ZAP)
```

### Problema 4: Muitos False Positives

**Sintoma**: ZAP encontra muitas vulnerabilidades que não são reais

**Soluções**:
1. **Validar manualmente cada finding**:
   - Reproduzir manualmente o ataque
   - Verificar se vulnerabilidade é real

2. **Configurar contextos**:
   - Definir áreas públicas vs privadas
   - Configurar autenticação corretamente

3. **Ajustar políticas de scan**:
   - Desabilitar regras conhecidas por false positives
   - Focar em regras críticas apenas

### Problema 5: Autenticação Não Funciona

**Sintoma**: Scan não testa áreas protegidas

**Soluções**:
```xml
<!-- Verificar configuração de autenticação -->
<!-- zap-auth.xml deve ter: -->
- loginUrl correto
- loginRequestData com campos corretos
- loggedInIndicator que realmente indica login bem-sucedido
- Credenciais válidas
```

```bash
# Testar autenticação manualmente
curl -X POST http://localhost:3000/login \
  -d "email=test@example.com&password=TestPass123!"

# Verificar se retorna indicador de login (ex: "Dashboard")
```

### Problema 6: Scan Não Encontra Vulnerabilidades Óbvias

**Sintoma**: Vulnerabilidades conhecidas não são detectadas

**Soluções**:
1. **Verificar políticas de scan ativas**:
   - ZAP → Policies → Verificar regras habilitadas

2. **Verificar se scan ativo foi executado**:
   - Scan passivo não encontra vulnerabilidades que requerem payloads
   - Use `zap-full-scan.py` para scan ativo

3. **Verificar se aplicação está acessível**:
   - ZAP precisa conseguir acessar todas as URLs

4. **Executar scan com debug**:
   ```bash
   docker exec zap zap-full-scan.py -t http://localhost:3000 -d
   ```

---

## Dicas

1. **Primeira vez com ZAP**: Pode levar 30-60 segundos para inicializar completamente
2. **Aplicação grande**: O primeiro scan pode demorar. Seja paciente!
3. **Scan passivo primeiro**: Sempre execute scan passivo primeiro (mais rápido e seguro)
4. **Scan ativo em staging**: Execute scan ativo apenas em staging/QA, não em produção
5. **Muitos findings**: Não se assuste! É normal ter muitos findings no primeiro scan. Priorize por risco real.
6. **False positives**: Valide manualmente cada finding Critical/High
7. **Autenticação**: Configure autenticação corretamente para testar áreas protegidas
8. **Performance**: Use scan passivo para validação rápida, scan ativo para análise profunda

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] OWASP ZAP está rodando e acessível em `http://localhost:8080/zap/`
- [ ] Aplicação web está rodando e acessível
- [ ] Primeiro scan passivo executado com sucesso
- [ ] Primeiro scan ativo executado com sucesso
- [ ] Relatórios HTML e JSON gerados
- [ ] Top 5 vulnerabilidades identificadas e documentadas
- [ ] Relatório de análise criado com detalhes de cada vulnerabilidade
- [ ] Priorização por risco real realizada
- [ ] Autenticação configurada (opcional)

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Exercício 2.2.2: Testes Manuais com Burp Suite
- Exercício 2.2.3: Integrar DAST no CI/CD
- Configurar OWASP ZAP em aplicações de outros contextos (financeiro, educacional, etc.)
- Integrar OWASP ZAP em workflows de desenvolvimento

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Screenshot do relatório HTML do OWASP ZAP com resultados
2. Relatório das top 5 vulnerabilidades identificadas
3. Priorização justificada
4. Dúvidas ou desafios encontrados

{% include exercise-submission-form.html %}

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Projeto financeiro hipotético (Open Banking)

- **Foco especial**: Vulnerabilidades relacionadas a dados financeiros
- **Quality Gate rigoroso**: 0 Critical vulnerabilities
- **Priorização**: SQL Injection e Broken Access Control são P1 (críticos)
- **Compliance**: Vulnerabilidades devem ser corrigidas para atender PCI-DSS

Aplique os mesmos passos neste contexto hipotético, priorizando vulnerabilidades críticas para o setor financeiro.

---

**Duração Estimada**: 45-60 minutos  
**Nível**: Básico  
**Pré-requisitos**: Aula 2.2 (DAST: Dynamic Application Security Testing), Docker instalado, Aplicação web para testar
