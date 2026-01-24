---
exercise_id: lesson-2-2-exercise-3-false-positive-investigation
title: "Exercício 2.2.3b: Investigar False Positives DAST"
lesson_id: lesson-2-2
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.2.3b: Investigar False Positives DAST

## 📋 Enunciado Completo

**Cenário**: OWASP ZAP reportou **XSS Reflected (High)** no endpoint `/search?q=<script>alert(1)</script>`. Você precisa **validar se é TRUE ou FALSE POSITIVE** através de investigação técnica rigorosa.

**Contexto**: Ferramentas DAST têm taxa de False Positives de **20-40%** (Gartner, 2025). QA Security profissional NUNCA confia cegamente em ferramentas - **validação manual é essencial**.

### Tarefa

1. **Reproduzir payload manualmente** (curl, Burp Suite, ou navegador)
2. **Testar variações do payload** (bypass filters) - mínimo 5 técnicas
3. **Analisar resposta HTTP** em profundidade (encoding, CSP, sanitization)
4. **Consultar código-fonte** (se disponível) para entender proteções
5. **Documentar evidências** (screenshots, request/response completo)
6. **Concluir: TRUE ou FALSE POSITIVE** com justificativa técnica detalhada
7. **Propor ação**: Se FP, como ajustar ZAP? Se TP, qual correção?

---

## ✅ Soluções Detalhadas

### Passo 1: Reprodução Manual do Payload Original

**Objetivo**: Confirmar se payload do ZAP realmente executa JavaScript.

**Método A: curl (CLI)**

```bash
# 1. Reproduzir payload exato do ZAP
curl -v "https://app.exemplo.com/search?q=<script>alert(1)</script>" \
  -H "User-Agent: Mozilla/5.0" \
  -H "Accept: text/html" \
  2>&1 | tee payload_test1.txt

# Analisar response:
grep -A 20 "HTTP/1.1 200" payload_test1.txt
```

**O que buscar na resposta:**

```html
<!-- ❌ VULNERÁVEL (TRUE POSITIVE) -->
<div>Você buscou por: <script>alert(1)</script></div>
<!-- Payload refletido sem encoding = EXECUTA -->

<!-- ✅ PROTEGIDO (FALSE POSITIVE) -->
<div>Você buscou por: &lt;script&gt;alert(1)&lt;/script&gt;</div>
<!-- HTML entities: < vira &lt; = NÃO EXECUTA -->
```

**Método B: Navegador (Visual)**

1. Abra DevTools (F12) → Network tab
2. Navegue para: `https://app.exemplo.com/search?q=<script>alert(1)</script>`
3. **Observar**:
   - Alert popup apareceu? → TRUE POSITIVE
   - Texto literal `<script>` apareceu? → FALSE POSITIVE (sanitizado)
4. **Inspecionar elemento** (botão direito → Inspect):
   - Ver HTML renderizado (entities ou tag literal?)

**Método C: Burp Suite (Profissional)**

```
1. Proxy → Intercept on
2. Navegador: acesse URL vulnerável
3. Burp: capture request
4. Repeater → Send
5. Response → Render tab (ver se JS executou)
6. Response → Raw tab (ver encoding)
```

---

### Passo 2: Testar Variações do Payload (Bypass Techniques)

**Objetivo**: Atacantes não desistem após primeira falha. Testar 5-10 variações.

#### Técnica 1: Event Handlers (img, svg, iframe)

```bash
# Teste 1: img tag com onerror
curl "https://app.exemplo.com/search?q=<img src=x onerror=alert(1)>"
# Análise: Se executou = TP. Se codificou = FP.

# Teste 2: svg com onload
curl "https://app.exemplo.com/search?q=<svg onload=alert(1)>"

# Teste 3: iframe com javascript:
curl "https://app.exemplo.com/search?q=<iframe src='javascript:alert(1)'>"
```

#### Técnica 2: Case Manipulation (bypass filters simples)

```bash
# Teste 4: Mixed case
curl "https://app.exemplo.com/search?q=<ScRiPt>alert(1)</sCrIpT>"

# Teste 5: Double encoding
curl "https://app.exemplo.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

#### Técnica 3: Alternative Encodings

```bash
# Teste 6: Unicode encoding
curl "https://app.exemplo.com/search?q=<script>\u0061lert(1)</script>"

# Teste 7: HTML entities
curl "https://app.exemplo.com/search?q=<script>&#97;lert(1)</script>"
```

#### Técnica 4: Context Breaking (se em atributo)

```bash
# Teste 8: Se payload em atributo HTML
curl "https://app.exemplo.com/search?q=" onmouseover="alert(1)"

# Teste 9: Quebrar atributo com espaços
curl "https://app.exemplo.com/search?q='><script>alert(1)</script>"
```

#### Técnica 5: Polyglot Payloads

```bash
# Teste 10: Polyglot (funciona em múltiplos contextos)
curl "https://app.exemplo.com/search?q=javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
```

**Documentar Resultados:**

| # | Payload | Executou? | HTML Response | Conclusão |
|---|---------|-----------|---------------|-----------|
| 1 | `<script>alert(1)</script>` | ❌ | `&lt;script&gt;...` | Codificado |
| 2 | `<img src=x onerror=alert(1)>` | ❌ | `&lt;img src=...` | Codificado |
| 3 | `<svg onload=alert(1)>` | ❌ | `&lt;svg onload=...` | Codificado |
| ... | ... | ... | ... | ... |

**Interpretação:**
- Se TODOS testados foram bloqueados = **FALSE POSITIVE** (proteção efetiva)
- Se QUALQUER UM executou = **TRUE POSITIVE** (vulnerável)

---

### Passo 3: Análise Profunda da Resposta HTTP

**Checklist de Proteções:**

#### 3.1. HTML Encoding

```bash
# Verificar se < > " ' são codificados
curl -s "https://app.exemplo.com/search?q=<script>alert(1)</script>" | grep -o "&lt;\|&gt;\|&quot;\|&#39;"

# ✅ Se encontrar HTML entities = PROTEGIDO
# ❌ Se encontrar < > literal = VULNERÁVEL
```

#### 3.2. Content Security Policy (CSP)

```bash
# Verificar header CSP
curl -I "https://app.exemplo.com/search?q=test" | grep -i "Content-Security-Policy"

# Exemplo de CSP seguro:
# Content-Security-Policy: default-src 'self'; script-src 'self'
# (Bloqueia inline scripts, mesmo que refletido)
```

**Análise de CSP:**

```
# CSP Forte (bloqueia XSS inline):
script-src 'self'  → ✅ FALSE POSITIVE (mesmo refletido, não executa)

# CSP Fraco (permite inline):
script-src 'self' 'unsafe-inline'  → ❌ TRUE POSITIVE (executa)

# Sem CSP:
(ausente)  → ❌ Depende de encoding (potencial TP)
```

#### 3.3. X-XSS-Protection Header (Legacy)

```bash
# Verificar header XSS Protection (navegadores antigos)
curl -I "https://app.exemplo.com/" | grep -i "X-XSS-Protection"

# Exemplo:
# X-XSS-Protection: 1; mode=block
# (Proteção adicional, mas não substitui encoding/CSP)
```

#### 3.4. Framework Protections

**Se aplicação usa framework moderno:**

| Framework | Proteção Automática | Observação |
|-----------|-------------------|------------|
| **React (JSX)** | ✅ Sim | `{variable}` é auto-escaped |
| **Angular** | ✅ Sim | `{{variable}}` é auto-escaped |
| **Vue.js** | ✅ Sim | `{{variable}}` é auto-escaped |
| **PHP (echo)** | ❌ Não | Precisa `htmlspecialchars()` |
| **Node.js (template literal)** | ❌ Não | Precisa sanitização manual |

---

### Passo 4: Consultar Código-Fonte (Se Disponível)

**Análise de Código:**

#### Exemplo 1: React (Protegido por Padrão)

```javascript
// ✅ FALSE POSITIVE - React JSX auto-escapes
function SearchResults({ query }) {
  return (
    <div>
      Você buscou por: {query}
      {/* React converte < para &lt; automaticamente */}
    </div>
  );
}
```

**Conclusão**: FALSE POSITIVE - React protege por padrão.

#### Exemplo 2: PHP Vulnerável

```php
<?php
// ❌ TRUE POSITIVE - Sem sanitização
$query = $_GET['q'];
echo "<div>Você buscou por: $query</div>";
?>
```

**Conclusão**: TRUE POSITIVE - Nenhuma proteção.

#### Exemplo 3: PHP Protegido

```php
<?php
// ✅ FALSE POSITIVE - htmlspecialchars sanitiza
$query = htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
echo "<div>Você buscou por: $query</div>";
?>
```

**Conclusão**: FALSE POSITIVE - Encoding correto.

#### Exemplo 4: Node.js com Template Literal Vulnerável

```javascript
// ❌ TRUE POSITIVE - Template literal não escapa
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<div>Você buscou por: ${query}</div>`);
  // Template literal não sanitiza!
});
```

**Correção:**

```javascript
// ✅ Usar biblioteca de sanitização
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

app.get('/search', (req, res) => {
  const query = DOMPurify.sanitize(req.query.q);
  res.send(`<div>Você buscou por: ${query}</div>`);
});
```

---

### Passo 5: Documentar Evidências

**Template de Investigação:**

```markdown
## Relatório de Investigação: XSS Reflected em /search

### 1. Informações do Finding (ZAP)
- **URL**: https://app.exemplo.com/search?q=<script>alert(1)</script>
- **Parâmetro**: `q` (GET)
- **Severidade ZAP**: High (CVSS 7.5)
- **Confidence ZAP**: Medium
- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)

---

### 2. Reprodução Manual

**Teste 1: Payload Original**
```bash
curl "https://app.exemplo.com/search?q=<script>alert(1)</script>"
```

**Response:**
```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Security-Policy: default-src 'self'; script-src 'self'

<!DOCTYPE html>
<html>
<body>
  <div class="search-results">
    Você buscou por: &lt;script&gt;alert(1)&lt;/script&gt;
  </div>
</body>
</html>
```

**Observações:**
- ✅ HTML entities codificados (`<` → `&lt;`)
- ✅ CSP header presente (bloqueia inline scripts)
- ❌ Payload NÃO executou (testado no navegador)

**Screenshot:**
[Anexar screenshot do DevTools mostrando código-fonte com entities]

---

### 3. Variações de Payload (10 testes)

| # | Payload | Executou? | Resposta |
|---|---------|-----------|----------|
| 1 | `<script>alert(1)</script>` | ❌ | `&lt;script&gt;alert(1)&lt;/script&gt;` |
| 2 | `<img src=x onerror=alert(1)>` | ❌ | `&lt;img src=x onerror=alert(1)&gt;` |
| 3 | `<svg onload=alert(1)>` | ❌ | `&lt;svg onload=alert(1)&gt;` |
| 4 | `<ScRiPt>alert(1)</sCrIpT>` | ❌ | `&lt;ScRiPt&gt;alert(1)&lt;/sCrIpT&gt;` |
| 5 | `<iframe src="javascript:alert(1)">` | ❌ | `&lt;iframe src="javascript:alert(1)"&gt;` |
| 6 | `" onmouseover="alert(1)` | ❌ | `" onmouseover="alert(1)` (literal) |
| 7 | `'><script>alert(1)</script>` | ❌ | `'&gt;&lt;script&gt;alert(1)&lt;/script&gt;` |
| 8 | `%3Cscript%3Ealert(1)%3C/script%3E` | ❌ | `&lt;script&gt;alert(1)&lt;/script&gt;` |
| 9 | `<script>\u0061lert(1)</script>` | ❌ | `&lt;script&gt;\u0061lert(1)&lt;/script&gt;` |
| 10 | `javascript:/*...*/alert(1)` (polyglot) | ❌ | (codificado) |

**Resultado**: TODOS os 10 payloads foram bloqueados.

---

### 4. Análise de Proteções

**4.1. HTML Encoding:**
- ✅ Presente (< > " ' codificados)
- Framework: React 18.2
- Método: JSX auto-escape

**4.2. Content Security Policy:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```
- ✅ Bloqueia inline scripts
- ✅ Bloqueia eval()
- ✅ Permite apenas scripts do mesmo domínio

**4.3. Código-Fonte:**
```jsx
// src/components/SearchResults.jsx
function SearchResults({ query }) {
  return (
    <div className="search-results">
      Você buscou por: {query}
      {/* React JSX escapa automaticamente */}
    </div>
  );
}
```

**4.4. X-XSS-Protection:**
```
X-XSS-Protection: 1; mode=block
```
(Proteção legacy adicional)

---

### 5. Conclusão

**Veredito**: ❌ **FALSE POSITIVE**

**Justificativa Técnica:**
1. **HTML Encoding Presente**: React JSX sanitiza automaticamente (`<` → `&lt;`)
2. **CSP Bloquearia Mesmo Se Refletido**: Header CSP proíbe inline scripts
3. **10 Bypass Techniques Falharam**: Todos os payloads testados foram bloqueados
4. **Validação Manual**: Navegador não executou JavaScript em nenhum teste
5. **Código-Fonte Seguro**: React framework com proteção por padrão

**Por que ZAP reportou?**
- ZAP detecta payload refletido no HTML (string `<script>` presente no response)
- Porém, ZAP **não analisou CSP header** corretamente
- ZAP **não detectou HTML entities** (encoding)
- **Limitação da ferramenta**: Heurística baseada em padrões (não execução real)

---

### 6. Ações Recomendadas

**6.1. Marcar como False Positive no ZAP**
```
1. Alerts → XSS Reflected → Botão direito → Mark as False Positive
2. Adicionar comentário: "React JSX auto-escape + CSP bloqueando inline scripts"
```

**6.2. Ajustar Regras do ZAP (Reduzir FPs Futuros)**

Criar arquivo `.zap/rules.tsv`:
```tsv
10055	IGNORE	https://app.exemplo.com/search.*	React JSX auto-escape
```

**6.3. Documentar no README do Projeto**
```markdown
## Known False Positives (DAST)

### XSS Reflected em /search
- **Ferramenta**: OWASP ZAP
- **Status**: FALSE POSITIVE (validado em 24/01/2026)
- **Proteção**: React JSX + CSP
- **Evidência**: [Link para este relatório]
```

**6.4. Não Requer Correção**
- Código está seguro
- Proteções adequadas (encoding + CSP)
- Monitorar apenas (não priorizar)

---

### 7. Lições Aprendidas

1. **Ferramentas DAST Não São Perfeitas**: 30% dos alertas podem ser FP
2. **Validação Manual é Essencial**: Nunca confiar 100% em ferramentas
3. **CSP é Camada Adicional**: Mesmo com encoding, CSP protege contra bypass
4. **Frameworks Modernos Protegem**: React, Angular, Vue têm proteção default
5. **Documentar FPs Economiza Tempo**: Próximo scan não vai re-investigar

---
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios)

**Reprodução Manual:**
- [ ] Reproduziu payload original manualmente (curl ou navegador)
- [ ] Analisou resposta HTTP completa (headers + body)
- [ ] Determinou se payload executou ou foi bloqueado
- [ ] Incluiu evidências (screenshots ou output de curl)

**Testes de Bypass:**
- [ ] Testou pelo menos **3 variações** de payload (diferentes técnicas)
- [ ] Documentou resultado de cada teste (executou? resposta?)
- [ ] Considerou diferentes contextos (tag, atributo, URL)

**Conclusão Fundamentada:**
- [ ] Concluiu: TRUE ou FALSE POSITIVE
- [ ] Justificativa técnica detalhada (não apenas "acho que...")
- [ ] Identificou proteções presentes (encoding, CSP, framework)

### ⭐ Importantes (Qualidade da Resposta)

**Análise Profunda:**
- [ ] Testou **5+ variações** de payload (bypass techniques abrangentes)
- [ ] Analisou **Content Security Policy** (se presente)
- [ ] Consultou **código-fonte** (se disponível) para entender proteções
- [ ] Explicou **POR QUÊ** é TRUE ou FALSE POSITIVE (causa raiz)

**Documentação:**
- [ ] Relatório estruturado com seções claras
- [ ] Evidências visuais (screenshots do DevTools, response HTTP)
- [ ] Propôs **ação concreta** (correção se TP, ajuste de regra ZAP se FP)
- [ ] Formato replicável (outro QA consegue reproduzir investigação)

**Pensamento Crítico:**
- [ ] Considerou **contexto** (framework, tecnologia, ambiente)
- [ ] Avaliou **camadas de proteção** (defense in depth)
- [ ] Comparou **risco teórico** vs **risco real**

### 💡 Diferencial (Conhecimento Avançado)

**Técnicas Avançadas:**
- [ ] Testou **10+ variações** incluindo polyglots e encodings complexos
- [ ] Criou **teste automatizado** que valida proteção (Selenium, Playwright)
- [ ] Configurou **ZAP Custom Rule** para reduzir FPs similares (`.zap/rules.tsv`)
- [ ] Analisou **CSP directives** em profundidade (script-src, unsafe-inline, nonce)

**Contribuição ao Time:**
- [ ] Documentou finding no **Wiki do time** (knowledgebase de FPs)
- [ ] Propôs **melhoria no processo** DAST (otimizar configuração ZAP)
- [ ] Criou **dashboard de FPs** (quantos FPs por categoria?)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Ceticismo Saudável**: Não confia cegamente em ferramentas, valida manualmente?
2. **Pensamento Adversarial**: Testa múltiplos bypasses (pensando como atacante)?
3. **Análise Técnica**: Entende HTML encoding, CSP, framework protections?
4. **Documentação Forense**: Documenta evidências de forma clara e replicável?
5. **Comunicação com Devs**: Explica tecnicamente (não apenas "ferramenta disse")?

### Erros Comuns

**Erro 1: "Marcou como FALSE POSITIVE sem testar manualmente"**
- **Causa**: Confiou na intuição ou assumiu que framework protege
- **Feedback**: "Você PRECISA PROVAR que é FALSE POSITIVE. AÇÕES OBRIGATÓRIAS: 1) Reproduza payload manualmente (curl ou navegador), 2) Teste no mínimo 3 variações (img tag, svg, case manipulation), 3) Documente response HTTP (payload foi codificado? Executou?), 4) Screenshot do DevTools. Sem evidências técnicas = investigação incompleta. Refaça com validação manual rigorosa."

**Erro 2: "Testou apenas payload original (não tentou bypasses)"**
- **Causa**: Não pensou como atacante (adversarial mindset)
- **Feedback**: "Atacantes testam DEZENAS de variações até achar bypass. Você testou apenas 1. TESTE MÍNIMO: 1) Event handlers (`<img onerror=alert(1)>`), 2) Case manipulation (`<ScRiPt>`), 3) Context breaking (`'><script>`), 4) Alternative encodings (`%3Cscript%3E`), 5) Polyglots. Se TODOS falharem = FALSE POSITIVE confiável. Se QUALQUER UM funcionar = TRUE POSITIVE. Uma proteção pode ter falhas."

**Erro 3: "Não explicou POR QUÊ é FALSE POSITIVE"**
- **Causa**: Apenas disse "não é vulnerável" sem justificativa técnica
- **Feedback**: "Dev precisa entender POR QUÊ não é vulnerável. EXPLIQUE: 1) Qual proteção está bloqueando? (HTML encoding? CSP? Framework?), 2) COMO funciona essa proteção? (exemplo: React JSX converte < para &lt;), 3) EVIDÊNCIA: mostre response com entities. Comunicação técnica precisa ser educativa, não apenas conclusão final."

**Erro 4: "Ignorou Content Security Policy (CSP)"**
- **Causa**: Focou apenas em encoding, não viu headers HTTP
- **Feedback**: "CSP é CAMADA ADICIONAL DE PROTEÇÃO. ANÁLISE: 1) Rode `curl -I <url>` para ver headers, 2) Procure por 'Content-Security-Policy', 3) Verifique se `script-src` permite inline (`'unsafe-inline'`?), 4) CSP forte SOZINHO pode tornar XSS FALSE POSITIVE (mesmo refletido, não executa). Revise seção 'CSP' da Aula 2.2."

**Erro 5: "Não propôs ação após investigação"**
- **Causa**: Apenas concluiu TRUE/FALSE, não disse o que fazer depois
- **Feedback**: "Investigação SEM AÇÃO é incompleta. SE FALSE POSITIVE: 1) Marque no ZAP (evita re-trabalho), 2) Ajuste rules.tsv (reduz ruído futuro), 3) Documente (wiki do time). SE TRUE POSITIVE: 1) Crie ticket com severidade correta, 2) Proponha correção técnica (código), 3) Priorize (P0? P1?). Próximo passo SEMPRE deve estar claro."

**Erro 6: "Usou apenas navegador (não testou programaticamente)"**
- **Causa**: Não documentou evidências técnicas replicáveis
- **Feedback**: "Navegador é útil visualmente, mas NÃO é prova técnica. EVIDÊNCIAS TÉCNICAS: 1) curl com output completo (request + response), 2) Burp Suite Repeater (intercept + manipulate), 3) Screenshots do DevTools → Elements tab (ver HTML renderizado), 4) Screenshots do DevTools → Network tab (ver response raw). Investigação profissional é REPLICÁVEL por outro QA."

### Dicas para Feedback Construtivo

**Para investigação exemplar:**
> "Investigação exemplar! Você demonstrou: 1) Ceticismo saudável (não confiou cegamente no ZAP), 2) Rigor técnico (testou 10 variações de payload, analisou CSP, consultou código-fonte), 3) Documentação forense (evidências claras, screenshots, request/response completo), 4) Pensamento crítico (explicou POR QUÊ é FP tecnicamente), 5) Ação concreta (ajustou rules.tsv, documentou no wiki). Seu padrão de investigação está no nível de Security Analyst sênior. Próximo desafio: automatize validações com Selenium/Playwright (criar teste que valida proteção)."

**Para investigação intermediária:**
> "Boa investigação! Você reproduziu payload e concluiu corretamente. Para elevar o nível: 1) APROFUNDE bypass techniques (testou apenas 2 variações, tente 5-10 incluindo polyglots), 2) ANALISE CSP header (presente? Configurado corretamente?), 3) EXPLIQUE tecnicamente POR QUÊ proteção funciona (não apenas 'está seguro'), 4) PROPONHA ação (marcar FP no ZAP? Ajustar regras?). Sua conclusão está correta, agora adicione profundidade técnica e recomendações."

**Para dificuldades:**
> "Investigar FALSE POSITIVES é desafiador. Vamos simplificar: 1) REPRODUÇÃO: Copie URL do ZAP, teste no navegador (DevTools aberto), alert popup apareceu? Sim = TP, Não = FP, 2) VARIAÇÕES: Teste 3 payloads: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, 3) RESPOSTA: Botão direito → Inspect → veja HTML (tags literais ou &lt; &gt;?), 4) CONCLUSÃO: Se TODOS foram bloqueados = FALSE POSITIVE. Siga passo a passo, documente cada teste. Tutorial: https://portswigger.net/web-security/cross-site-scripting."

### Contexto Pedagógico

**Por que este exercício é crítico:**

1. **Redução de Ruído**: 30% dos alertas DAST são FP - validar economiza tempo do time
2. **Comunicação com Devs**: Dev ignora alertas se muitos FPs - validação mantém credibilidade
3. **Pensamento Crítico**: Não aceitar ferramentas cegamente é habilidade essencial de QA Security
4. **Compreensão de Proteções**: Entender CSP, encoding, frameworks é conhecimento fundamental
5. **Eficiência do Time**: FPs documentados evitam re-trabalho em futuros scans

**Conexão com o Curso:**
- **Pré-requisito**: Exercício 2.2.1 (Baseline Scan), conhecimento de XSS, HTML, HTTP
- **Aplica conceitos**: TRUE vs FALSE POSITIVE, HTML Encoding, CSP, Framework Protections
- **Prepara para**: Exercício 2.2.4 (Análise de Relatório Completo), Aula 2.3 (Pentest - validação manual essencial)
- **Integra com**: Aula 2.1 (SAST também tem FPs), Módulo 3 (Secure Development - como implementar proteções)

**Habilidades desenvolvidas:**
- Validação manual de vulnerabilidades (exploit)
- Bypass techniques (adversarial thinking)
- Análise de proteções (CSP, encoding, frameworks)
- Debugging de aplicações web (DevTools, Burp Suite)
- Documentação forense (evidências técnicas)
- Comunicação técnica com desenvolvedores
- Gerenciamento de ruído (FPs) em ferramentas de segurança

**Estatísticas da Indústria:**
- 35% dos alertas DAST são FALSE POSITIVES (Gartner, 2025)
- Times que validam FPs têm 60% menos re-trabalho (Forrester, 2024)
- Devs ignoram 70% dos alertas não validados (SANS, 2024)
- Validação manual aumenta credibilidade do QA Security em 4x (Veracode, 2025)

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
