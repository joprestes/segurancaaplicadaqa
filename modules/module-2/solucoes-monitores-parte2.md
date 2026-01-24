# 🔐 Guia de Soluções - Aulas 2.2 a 2.5 (Continuação)

**Uso**: RESTRITO A MONITORES  
**Abordagem**: Qualitativa (sem notas numéricas)

---

<a id="exercicio-221"></a>
## 📘 Exercício 2.2.1: Configurar OWASP ZAP em Aplicação Web

**Nível**: Básico  
**Tempo estimado**: 45 minutos  
**Tipo**: Hands-on prático

### ✅ Objetivo de Aprendizado
Verificar se o aluno consegue configurar e executar um scan DAST básico com OWASP ZAP.

### 📋 O Que Observar na Correção

**Aspectos técnicos:**
- Instalação do OWASP ZAP realizada corretamente
- Configuração de proxy (manual ou automática)
- Execução de baseline scan ou active scan
- Interpretação básica dos resultados

**Aspectos de compreensão:**
- Aluno entende a diferença entre SAST e DAST?
- Compreende quando usar cada tipo de scan (passive vs active)?
- Identifica limitações do DAST?

### 🎯 Resposta Esperada

**Entregáveis:**
1. Screenshot do ZAP configurado (URL alvo visível)
2. Relatório HTML gerado pelo ZAP
3. Top 3 vulnerabilidades identificadas com:
   - Nome da vulnerabilidade
   - URL afetada
   - Nível de severidade
   - Recomendação de correção

**Exemplo de boa resposta:**
```markdown
### Configuração
- Ferramenta: OWASP ZAP 2.14.0
- Alvo: http://testphp.vulnweb.com (site de teste)
- Tipo de scan: Baseline (passive)
- Duração: 8 minutos

### Top 3 Vulnerabilidades Encontradas:

1. **Missing Anti-clickjacking Header** (Medium)
   - URL: http://testphp.vulnweb.com/
   - Descrição: Aplicação não possui X-Frame-Options header
   - Recomendação: Adicionar header X-Frame-Options: DENY
   - Contexto: Pode permitir clickjacking attacks

2. **Cross-Site Scripting (XSS)** (High)
   - URL: http://testphp.vulnweb.com/search.php?test=<script>
   - Descrição: Input não sanitizado refletido na resposta
   - Recomendação: Implementar sanitização de inputs
   - Contexto: Permite injeção de JavaScript malicioso

3. **SQL Injection** (High)
   - URL: http://testphp.vulnweb.com/artists.php?artist=1'
   - Descrição: Parâmetro vulnerável a SQLi
   - Recomendação: Usar prepared statements
   - Contexto: Pode expor dados sensíveis do banco
```

### ❌ Erros Comuns

**Erro 1: "Não consegui configurar o proxy"**
- **Causa**: Não entendeu que ZAP atua como proxy HTTP
- **Orientação**: Explique o conceito de proxy interceptor. Mostre diagrama: Browser → ZAP → Aplicação. Sugira usar "Manual Explore" ao invés de configurar proxy do navegador.

**Erro 2: "Scan não encontrou nada"**
- **Causa**: Usou URL incorreta ou aplicação não tem vulnerabilidades óbvias
- **Orientação**: Recomendar usar aplicações intencionalmente vulneráveis (DVWA, WebGoat, testphp.vulnweb.com). Explicar que nem toda aplicação terá vulnerabilidades detectáveis por DAST.

**Erro 3: "Listou todas as vulnerabilidades sem interpretar"**
- **Causa**: Apenas exportou relatório sem análise crítica
- **Orientação**: Pedir para RE-FAZER selecionando apenas top 3 mais críticas E explicar o IMPACTO de cada uma no contexto da aplicação. Não queremos "copiar e colar", queremos ANÁLISE.

### 💡 Como Dar Feedback Construtivo

**Para alunos que demonstraram domínio:**
> "Excelente execução! Você demonstrou compreensão do DAST e interpretou os findings corretamente. Próximo desafio: configure o ZAP para autenticação (aplicação com login) e execute um authenticated scan. Isso é essencial para testar áreas protegidas."

**Para alunos com dificuldades intermediárias:**
> "Bom progresso na configuração! Vi que você executou o scan com sucesso. Para melhorar: aprofunde a análise de cada vulnerabilidade. Pergunte-se: 1) Isso é explorável? 2) Qual o impacto real? 3) Prioridade urgente ou backlog? Revisitar seção 'Interpretação de Resultados DAST' da aula."

**Para alunos que travaram:**
> "Vejo que você enfrentou dificuldades. Vamos simplificar: 1) Instale o ZAP Desktop (não use Docker inicialmente), 2) Use 'Automated Scan' com URL http://testphp.vulnweb.com, 3) Aguarde terminar, 4) Exporte relatório. Após conseguir isso, agende monitoria para tirar dúvidas sobre interpretação."

---

<a id="exercicio-223"></a>
## 📘 Exercício 2.2.3: Investigação de False Positive em DAST

**Nível**: Intermediário  
**Tempo estimado**: 60 minutos  
**Tipo**: Análise investigativa

### ✅ Objetivo de Aprendizado
Avaliar capacidade do aluno de diferenciar true positive de false positive e validar manualmente findings do DAST.

### 📋 O Que Observar na Correção

**Habilidades críticas:**
- Pensamento crítico (não aceita finding sem validar)
- Capacidade de reprodução manual de vulnerabilidades
- Compreensão técnica (entende O QUE é XSS, como explorar)
- Documentação estruturada

**Sinais de excelência:**
- Reproduziu o payload manualmente (Burp Suite ou curl)
- Testou variações do payload
- Consultou código-fonte (se disponível)
- Documentou evidências (screenshots de tentativas)

### 🎯 Resposta Esperada

**Cenário típico**: DAST reportou XSS Reflected (High) em `/search?q=<script>alert(1)</script>`

**Investigação esperada:**

```markdown
## Investigação de False Positive

### 1. Finding Original
- Ferramenta: OWASP ZAP
- Vulnerabilidade: Reflected XSS
- URL: https://app.exemplo.com/search?q=<script>alert(1)</script>
- Severidade: High (CVSS 7.1)

### 2. Reprodução Manual

**Teste 1: Payload original**
```bash
curl "https://app.exemplo.com/search?q=<script>alert(1)</script>"
# Resposta: <div class="results">Busca por: &lt;script&gt;alert(1)&lt;/script&gt;</div>
# ✅ HTML entities codificados, payload NÃO executado
```

**Teste 2: Variações do payload**
- `<img src=x onerror=alert(1)>` → Codificado
- `<svg onload=alert(1)>` → Codificado
- `javascript:alert(1)` → Codificado

**Teste 3: Inspeção do código-fonte (React)**
```javascript
// SearchResults.jsx
<div className="results">
  Busca por: {query}  {/* React sanitiza automaticamente via JSX */}
</div>
```

### 3. Conclusão

**Veredito**: ❌ **FALSE POSITIVE**

**Justificativa técnica**:
- Aplicação usa React que sanitiza automaticamente via JSX
- HTML entities codificados (&lt; ao invés de <)
- Testado 5 payloads diferentes, nenhum executou
- Código-fonte confirma uso correto de JSX

**Ação recomendada**:
- Marcar como False Positive no ZAP
- Documentar no README que aplicação usa React (framework já protege contra XSS básico)
- Ajustar regra do scanner para reduzir FPs em apps React

**Lição aprendida**:
DAST tem ~20-30% de taxa de false positives. QA Security NUNCA deve criar ticket sem validar manualmente. Sempre reproduza antes de escalar para desenvolvimento.
```

### ❌ Erros Comuns

**Erro 1: "Marquei como FP sem testar"**
- **Problema**: Aluno assumiu que é FP sem evidências
- **Orientação**: "Você precisa PROVAR que é FP. Mostre screenshots das tentativas de exploração falhadas. Sem evidência = não é confiável."

**Erro 2: "Testei apenas o payload original"**
- **Problema**: Não tentou bypasses
- **Orientação**: "Bom começo, mas atacantes tentam variações. Teste ao menos 3-5 payloads diferentes (img tag, svg, event handlers). Isso demonstra thoroughness."

**Erro 3: "Marcou como True Positive incorretamente"**
- **Problema**: Não percebeu que payload foi sanitizado
- **Orientação**: "Olhe a RESPOSTA HTTP. Se você vê `&lt;script&gt;` ao invés de `<script>`, significa que foi encodado = NÃO é vulnerável. Revise conceito de HTML encoding."

### 💡 Feedback Pedagógico

**Para análise profissional:**
> "Investigação impecável! Você reproduziu manualmente, testou variações, consultou código-fonte e documentou com evidências. Esse é o padrão de um QA Security sênior. Seu raciocínio técnico está correto: React JSX sanitiza automaticamente. Próximo nível: escreva um teste automatizado (Selenium/Playwright) que valida essa proteção."

**Para análise superficial:**
> "Você chegou à conclusão correta (FP), mas faltou profundidade. Adicione: 1) Mais payloads testados (pelo menos 3), 2) Screenshot das respostas HTTP, 3) Explicação técnica do POR QUÊ não é vulnerável (HTML encoding? Framework protege?). Objetivo: qualquer dev deve poder entender sua análise sem precisar perguntar."

---

<a id="exercicio-231"></a>
## 📘 Exercício 2.3.1: Interpretar Relatório de Pentest

**Nível**: Básico (para QA)  
**Tempo estimado**: 120 minutos  
**Tipo**: Análise de documento + priorização

### ✅ Objetivo de Aprendizado
Verificar se o aluno consegue ler um relatório de pentest profissional e extrair ações práticas (não precisa EXECUTAR pentest, precisa INTERPRETAR).

### 📋 O Que Observar na Correção

**Habilidades essenciais para QA:**
- Leitura de relatório técnico (Executive Summary vs Technical Details)
- Priorização por contexto de negócio (não apenas CVSS)
- Criação de plano de ação realista
- Comunicação para stakeholders técnicos e não-técnicos

**NÃO esperamos:**
- Que aluno saiba executar exploits
- Conhecimento profundo de ferramentas de pentest (Metasploit, etc)
- Habilidades de exploitation manual

### 🎯 Resposta Esperada

**Relatório fornecido no exercício:**
- 23 findings (2 Critical, 8 High, 10 Medium, 3 Low)
- Principais riscos: SQL Injection, IDOR, XSS

**Análise esperada do aluno:**

```markdown
## Análise do Relatório de Pentest

### 1. Leitura do Executive Summary
- Duração do pentest: 5 dias úteis
- Escopo: app.xyz.com + api.xyz.com
- Tipo: Gray Box (com credenciais de teste)
- Principais riscos: SQLi, IDOR, Authentication Bypass

### 2. Priorização por Contexto

| Finding | CVSS | Prioridade QA | Justificativa |
|---------|------|---------------|---------------|
| SQL Injection em /api/products/search | 9.8 | **P0 - CRÍTICA** | Permite dump de banco → Exposição de PII de 5M usuários → Risco LGPD |
| Authentication Bypass em /admin | 9.1 | **P0 - CRÍTICA** | Acesso total ao painel admin → Manipulação de pedidos, dados de clientes |
| IDOR em /api/orders/:id | 8.2 | **P1 - ALTA** | Vazamento de dados de pedidos (nome, endereço, itens) → Violação de privacidade |
| XSS em /search | 6.1 | **P2 - MÉDIA** | Requer engenharia social (enviar link malicioso) → Impacto limitado |
| Rate Limiting ausente | 3.1 | **P3 - BAIXA** | Brute force é mitigado por bloqueio no frontend → Risco residual baixo |

### 3. Plano de Remediação (Top 5)

**Sprint Atual (Blocker):**
1. ✅ SQL Injection
   - Responsável: @backend-team
   - Prazo: 2 dias úteis
   - Ação: Implementar prepared statements em todos os endpoints de busca
   - Teste QA: Reproduzir exploit do relatório + validar correção

2. ✅ Authentication Bypass
   - Responsável: @security-team
   - Prazo: 3 dias úteis
   - Ação: Validar roles server-side + assinar cookies com HMAC
   - Teste QA: Tentar manipular cookie após correção

**Próxima Sprint:**
3. ✅ IDOR em Orders
   - Responsável: @backend-team
   - Prazo: 1 semana
   - Ação: Adicionar ownership check em OrderController
   - Teste QA: Validar que user A não acessa orders de user B

**Backlog:**
4. ✅ XSS (P2 - Média)
5. ✅ Rate Limiting (P3 - Baixa)

### 4. Comunicação para Stakeholders

**Para CEO/CTO:**
> "Pentest identificou 2 vulnerabilidades críticas que podem expor dados de clientes (SQL Injection e falha de autenticação). Estamos priorizando correção urgente (prazo: 5 dias). Outras 8 vulnerabilidades serão tratadas nas próximas 2 semanas. Risco de vazamento de dados está sendo mitigado."

**Para Time de Dev:**
> "Relatório completo anexado. Prioridade máxima: SQL Injection no endpoint /api/products/search (usar prepared statements) e Authentication Bypass no /admin (validar roles server-side). Criei tickets com POCs (proof-of-concept) para facilitar reprodução. Agendar code review após correção."
```

### ❌ Erros Comuns

**Erro 1: "Priorização só por CVSS"**
- **Problema**: Aluno usou apenas CVSS Score sem considerar contexto
- **Orientação**: "CVSS 9.8 em endpoint de TESTE pode ser P3. CVSS 6.0 em checkout pode ser P1. Pergunte: 1) Quais dados são expostos? 2) Facilidade de exploração? 3) Impacto no negócio? Repriorize considerando esses 3 fatores."

**Erro 2: "Não criou plano de ação"**
- **Problema**: Apenas listou vulnerabilidades sem definir próximos passos
- **Orientação**: "QA Security não apenas IDENTIFICA problemas, mas COORDENA correção. Adicione: quem vai corrigir? Prazo? Como QA vai validar? Isso transforma relatório em ACTION ITEMS."

**Erro 3: "Comunicação muito técnica para CEO"**
- **Problema**: Usou jargão técnico (CVSS, CWE, exploitation) com stakeholder não-técnico
- **Orientação**: "CEO não precisa saber o que é SQL Injection. Precisa saber: 1) Qual o RISCO (dados vazados), 2) Qual o IMPACTO ($, reputação, LGPD), 3) Quanto tempo pra corrigir. Reescreva em linguagem de negócio."

### 💡 Feedback Pedagógico

**Para análise matura:**
> "Análise exemplar! Você demonstrou maturidade profissional ao re-priorizar por contexto e criar plano de ação detalhado. Sua comunicação para stakeholders é apropriada (técnica para devs, negócio para CEO). Próximo desafio: liderar a validação das correções reproduzindo os exploits do pentester."

**Para análise superficial:**
> "Boa leitura do relatório, mas faltou profundidade estratégica. Você listou as vulnerabilidades, mas: 1) Não justificou a priorização (por que SQLi é P0?), 2) Faltou plano de ação (quem, quando, como), 3) Comunicação muito técnica (simplifique para stakeholders). Revise seção 'Papéis do QA' da aula 2.3."

---

<a id="exercicio-254"></a>
## 📘 Exercício 2.5.4: War Room de CVE Crítica (Log4Shell)

**Nível**: Avançado ⭐⭐  
**Tempo estimado**: 90 minutos  
**Tipo**: Simulação de crise + tomada de decisão

### ✅ Objetivo de Aprendizado
Avaliar capacidade de resposta rápida a CVEs críticas (cenário real: Log4Shell descoberto há 2h, você tem 4h para mapear exposição).

### 📋 O Que Observar na Correção

**Competências críticas:**
- Agilidade na resposta (mindset de urgência)
- Uso de SBOM para identificar dependências
- Priorização de sistemas por criticidade
- Comunicação clara sob pressão
- Plano de ação estruturado

**Diferenciais de um aluno excepcional:**
- Automatizou busca em múltiplos repos
- Criou script para verificar versões
- Documentou em tempo real (Google Doc compartilhado)
- Propôs mitigações temporárias (WAF rules)

### 🎯 Resposta Esperada

**Cenário**: CVE-2021-44228 (Log4Shell) publicado às 14h. CVSS 10.0. Exploração ativa na internet.

**Resposta esperada (War Room - primeiras 4 horas):**

```markdown
## War Room: Log4Shell Response

### Timeline de Ações

**14:00 - CVE publicado**
- Severidade: CRITICAL (CVSS 10.0)
- Afeta: Apache Log4j 2.0-beta9 a 2.14.1
- Exploit: Remote Code Execution via JNDI lookup

**14:15 - Identificação de exposição (usando SBOM)**
```bash
# Buscar em todos os SBOMs de produção
grep -r "log4j" sboms/production/*.json

# Resultado: 12 aplicações usando Log4j
# 7 aplicações: versão 2.14.0 (VULNERÁVEL)
# 3 aplicações: versão 2.15.0 (SEGURA)
# 2 aplicações: versão desconhecida (precisa verificar)
```

**14:30 - Priorização de sistemas**

| Sistema | Log4j Version | Criticidade | Exposição | Prioridade |
|---------|---------------|-------------|-----------|------------|
| API Pagamentos | 2.14.0 | **CRÍTICA** | Internet | **P0 - IMEDIATO** |
| Portal Cliente | 2.14.0 | **ALTA** | Internet | **P0 - IMEDIATO** |
| Admin Interno | 2.14.0 | MÉDIA | Intranet | P1 - Urgente |
| Microservice Notificações | 2.14.0 | MÉDIA | Interno | P1 - Urgente |
| Dashboard Analytics | 2.15.0 | - | Internet | ✅ Seguro |

**15:00 - Plano de Mitigação Imediata**

**Opção 1: Patch urgente (6-8 horas)**
- Atualizar Log4j para 2.15.0 em TODOS os serviços
- Testar em staging (1-2h por app)
- Deploy em produção via pipeline acelerado
- **Risco**: Pode quebrar funcionalidades (testes reduzidos)

**Opção 2: Mitigação temporária + Patch (4h + 24h)**
- Implementar WAF rule bloqueando JNDI payloads (IMEDIATO)
- Configurar JVM flag `-Dlog4j2.formatMsgNoLookups=true` (IMEDIATO)
- Patch completo nas próximas 24h com testes adequados
- **Risco**: Mitigação pode ter bypasses

**Decisão**: Opção 2 (mitigação + patch)

**15:30 - Implementação de mitigações**
```bash
# 1. Adicionar JVM flag em TODOS os deploys
export JAVA_OPTS="-Dlog4j2.formatMsgNoLookups=true"

# 2. WAF rule (CloudFlare)
# Bloquear requests com padrões: ${jndi:ldap, ${jndi:rmi, ${jndi:dns

# 3. Monitoramento intensivo
# Alertas para tentativas de exploração
```

**16:00 - Comunicação**

**Para CTO:**
> "Log4Shell (CVE crítica) afeta 7 de nossas aplicações. Implementamos mitigações temporárias (WAF + JVM flag) nas últimas 2h. APIs de Pagamento e Portal Cliente protegidos. Patch completo será deployado nas próximas 24h após testes. Monitoramento ativo 24/7."

**Para Time de Infra:**
> "Aplicar JVM flag `-Dlog4j2.formatMsgNoLookups=true` em TODOS os serviços Java. Script anexado. Prioridade: Pagamentos > Portal > Admin. Validar que flag está ativa via logs. Plantão 24h até patch completo."

**17:00 - Validação**
- [ ] JVM flag aplicada em produção (7 apps)
- [ ] WAF rule ativa (teste com payload dummy)
- [ ] Monitoramento configurado (alertas SOC)
- [ ] Patch em andamento (staging)

**18:00 - Retrospectiva (24h depois)**
- **O que funcionou**: SBOM permitiu identificar exposição em 15min
- **O que melhorar**: 2 apps não tinham SBOM (descobertos manualmente)
- **Action items**: 
  - Automatizar geração de SBOM no CI/CD
  - Criar runbook para resposta a CVEs críticas
  - Inventário completo de dependências (sem exceções)
```

### ❌ Erros Comuns

**Erro 1: "Demorou muito para identificar exposição"**
- **Problema**: Aluno não usou SBOM, buscou manualmente
- **Orientação**: "Em CVE crítica, você tem MINUTOS, não HORAS. SBOM deve estar atualizado e acessível. Se não tem SBOM, essa deveria ser sua primeira action item: implementar geração automática. Refaça o exercício usando SBOM."

**Erro 2: "Decidiu patchear TUDO imediatamente"**
- **Problema**: Não considerou riscos de deploy sem testes
- **Orientação**: "Deploy sem testes em 12 aplicações = alto risco de quebrar produção. Você causou um outage de 4h porque aplicação quebrou após patch. Decisão correta: mitigação temporária (WAF + JVM flag) + patch testado. Segurança E estabilidade importam."

**Erro 3: "Não comunicou para stakeholders"**
- **Problema**: Resolveu tecnicamente mas não atualizou gestão
- **Orientação**: "Em crise, comunicação é TÃO IMPORTANTE quanto solução técnica. CTO precisa saber: 1) Estamos expostos? 2) O que fizemos? 3) Quando estará resolvido? Sem comunicação, gestão assume que você não está gerenciando."

### 💡 Feedback Pedagógico

**Para resposta profissional:**
> "Resposta de nível sênior! Você demonstrou: 1) Agilidade (identificou em 15min), 2) Pragmatismo (mitigação temporária), 3) Comunicação clara, 4) Mindset de crise. Sua decisão de não patchear sem testes está CORRETA - muitas empresas quebraram produção tentando ser rápidas demais. Você está pronto para liderar resposta a incidentes."

**Para resposta com lacunas:**
> "Você chegou à solução correta (mitigação + patch), mas: 1) Demorou muito para identificar exposição (deveria ser <30min), 2) Faltou comunicação para stakeholders, 3) Não documentou processo de validação. Em crise, velocidade + comunicação são críticas. Pratique com outro CVE (ex: Spring4Shell) aplicando as lições aprendidas."

---

## 📊 Resumo: Abordagem de Correção Qualitativa

### Princípios para Monitores

1. **Foco em Aprendizado, Não em Nota**
   - Não atribua notas numéricas (0-10, percentuais)
   - Avalie: "Demonstrou compreensão?" vs "Não demonstrou ainda"
   - Use: "Nível Básico / Intermediário / Avançado"

2. **Feedback Sempre Construtivo**
   - Destaque o que está BOM primeiro
   - Identifique lacunas ESPECÍFICAS
   - Forneça CAMINHO para melhoria (não apenas "está errado")

3. **Contextualização**
   - Aluno é iniciante? Ajuste expectativas
   - Aluno já tem experiência? Eleve o nível de exigência
   - Compare com padrão da indústria, não com outros alunos

4. **Orientações Práticas**
   - "Refaça X considerando Y" > "Está errado"
   - "Veja seção Z da aula" > "Você não entendeu"
   - "Agende monitoria para..." > "Não sei como te ajudar"

### Classificação de Domínio (Sem Notas)

**NÍVEL AVANÇADO** (Pronto para o mercado)
- Demonstra pensamento crítico consistente
- Resolve problemas sem consultar material
- Documentação profissional
- **Feedback**: Desafios avançados, sugestão de contribuição open-source

**NÍVEL INTERMEDIÁRIO** (Precisa de prática)
- Compreende conceitos mas precisa de apoio na aplicação
- Resolve com consulta ao material
- Documentação adequada mas pode melhorar
- **Feedback**: Exercícios complementares, revisão de seções específicas

**NÍVEL BÁSICO** (Precisa de reforço)
- Dificuldade em conceitos fundamentais
- Não consegue resolver mesmo com material
- Documentação incompleta ou confusa
- **Feedback**: Agendar monitoria, refazer aula, material complementar

---

**Fim do Guia de Soluções - Aulas 2.2 a 2.5**

_Próxima atualização: Adicionar exemplos de correções reais de alunos_
