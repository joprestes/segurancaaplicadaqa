---
layout: page
title: "Guia de Soluções para Monitores - Módulo 2"
permalink: /modules/testes-seguranca-pratica/solucoes-monitores/
exclude_from_nav: true
---

# 🔐 Guia de Soluções para Monitores - Módulo 2

**Módulo**: Testes de Segurança na Prática  
**Versão**: 1.0  
**Data**: Janeiro 2026  
**Uso**: RESTRITO A MONITORES E INSTRUTORES

---

## ⚠️ AVISO IMPORTANTE

Este documento contém:
- ✅ **Gabaritos** de todos os exercícios do Módulo 2
- ✅ **Critérios de correção** detalhados
- ✅ **Exemplos de respostas esperadas**
- ✅ **Orientações de feedback** para alunos
- ✅ **Erros comuns** e como orientar correção

**NÃO COMPARTILHE** este material com alunos. É exclusivo para fins de monitoria/instrução.

---

## 📋 Índice

### Aula 2.1: SAST
- [Exercício 2.1.1: Configurar SonarQube](#exercicio-211)
- [Exercício 2.1.2: Criar Regras Customizadas Semgrep](#exercicio-212)
- [Exercício 2.1.3: Integrar SAST no CI/CD](#exercicio-213)
- [Exercício 2.1.4: Validar e Priorizar Findings](#exercicio-214)
- [Exercício 2.1.5: Trade-off Segurança vs Entrega](#exercicio-215)

### Aula 2.2: DAST
- [Exercício 2.2.1: Configurar OWASP ZAP](#exercicio-221)
- [Exercício 2.2.2: Integrar DAST no CI/CD](#exercicio-222)
- [Exercício 2.2.3: Investigação de False Positive](#exercicio-223)
- [Exercício 2.2.4: Análise de Relatório DAST Complexo](#exercicio-224)

### Aula 2.3: Pentest
- [Exercício 2.3.1: Interpretar Relatório de Pentest](#exercicio-231)
- [Exercício 2.3.2: Validar Correções de Pentest](#exercicio-232)
- [Exercício 2.3.3: Preparar Escopo de Pentest](#exercicio-233)
- [Exercício 2.3.4: Post-Mortem de Incidente](#exercicio-234)

### Aula 2.4: Automação
- [Exercício 2.4.1: Configurar SAST no GitHub Actions](#exercicio-241)
- [Exercício 2.4.2: Integrar DAST no Pipeline](#exercicio-242)
- [Exercício 2.4.3: Implementar Quality Gates](#exercicio-243)
- [Exercício 2.4.4: Otimização de Pipeline](#exercicio-244)
- [Exercício 2.4.5: Criar Política de Segurança Executável](#exercicio-245)

### Aula 2.5: SCA
- [Exercício 2.5.1: Configurar Snyk](#exercicio-251)
- [Exercício 2.5.2: npm audit e yarn audit](#exercicio-252)
- [Exercício 2.5.3: Gerar SBOM](#exercicio-253)
- [Exercício 2.5.4: War Room de CVE Crítica (Log4Shell)](#exercicio-254)
- [Exercício 2.5.5: Dependência Vulnerável Sem Patch](#exercicio-255)

---

<a id="exercicio-211"></a>
## 📘 Exercício 2.1.1: Configurar SonarQube em Projeto Próprio

**Nível**: Básico  
**Tempo estimado**: 60 minutos  
**Tipo**: Hands-on técnico

### ✅ Objetivo do Exercício
Avaliar se o aluno consegue instalar, configurar e executar análise SAST com SonarQube do zero.

### 📋 Critérios de Avaliação (Abordagem Qualitativa)

**Aspectos a observar:**

1. **Instalação e Configuração**
   - Aluno conseguiu instalar SonarQube (Docker ou local)?
   - Configurou corretamente token e projeto?
   - Documentou o processo?

2. **Execução do Scan**
   - Scan executou sem erros?
   - Aluno demonstrou compreensão dos comandos?
   - Há evidências (logs, screenshots)?

3. **Análise de Resultados** (aspecto mais importante)
   - Identificou vulnerabilidades relevantes?
   - Compreendeu a severidade de cada uma?
   - Priorizou baseado em contexto (não apenas CVSS)?

4. **Documentação**
   - Relatório é claro e objetivo?
   - Incluiu todos os entregáveis solicitados?
   - Demonstrou reflexão sobre os findings?

### 🎯 Resposta Esperada

#### Entregáveis Obrigatórios:
1. **Screenshots do SonarQube Dashboard**
   - Dashboard mostrando projeto configurado
   - Overview com métricas (bugs, vulnerabilities, code smells)
   - Página de "Security Hotspots"

2. **Comando de execução do scanner**
   ```bash
   # Exemplo esperado (Node.js):
   sonar-scanner \
     -Dsonar.projectKey=meu-projeto \
     -Dsonar.sources=. \
     -Dsonar.host.url=http://localhost:9000 \
     -Dsonar.login=<token>
   ```

3. **Top 5 vulnerabilidades** (exemplo de resposta aceitável):
   ```markdown
   1. SQL Injection no endpoint /api/users (CRITICAL)
      - CWE-89
      - Linha 45 de UserController.js
      - Prioridade: ALTA (dados sensíveis)
   
   2. Hardcoded Password em config.js (HIGH)
      - CWE-798
      - Linha 12
      - Prioridade: ALTA (credenciais expostas)
   
   3. Cross-Site Scripting (XSS) em /search (MEDIUM)
      - CWE-79
      - Linha 78 de SearchComponent.js
      - Prioridade: MÉDIA (input não sanitizado)
   
   4. Insecure Randomness em token generation (MEDIUM)
      - CWE-330
      - Linha 34 de AuthService.js
      - Prioridade: MÉDIA (previsibilidade de tokens)
   
   5. Missing CSRF Protection (LOW)
      - CWE-352
      - Global (middleware ausente)
      - Prioridade: BAIXA (aplicação não tem estado)
   ```

4. **Relatório de análise**
   - Deve conter: Total de issues, breakdown por severidade, recomendações

### ❌ Erros Comuns e Como Orientar

#### Erro 1: "Não consegui instalar o SonarQube"
**Causa**: Porta 9000 ocupada ou problemas com Docker  
**Orientação**: 
- Verificar se porta 9000 está livre: `lsof -i :9000`
- Usar porta alternativa: `-p 9001:9000`
- Verificar logs do container: `docker logs sonarqube`

#### Erro 2: "Scan executou mas não apareceu nada no dashboard"
**Causa**: Token inválido ou project key incorreto  
**Orientação**:
- Verificar token no SonarQube (My Account > Security)
- Conferir `sonar-project.properties` ou comando
- Verificar logs do scanner para erros

#### Erro 3: "Listou vulnerabilidades mas não priorizou"
**Causa**: Aluno apenas copiou output do SonarQube  
**Orientação**:
- Pedir para RE-PRIORIZAR baseado em contexto do projeto
- Explicar: CVSS ≠ Prioridade real (contexto importa)
- Solicitar justificativa para cada priorização

### 💡 Feedback Construtivo

**Se aluno foi bem (90-100%)**:
> "Excelente trabalho! Você demonstrou domínio completo do SonarQube. Próximo desafio: explore Quality Gates e integração com CI/CD. Sugestão: configure um Quality Gate customizado para seu projeto."

**Se aluno teve dificuldade média (70-89%)**:
> "Bom progresso! Você conseguiu configurar e executar o scan. Para melhorar: aprofunde a análise das vulnerabilidades. Não apenas liste, mas explique o IMPACTO de cada uma no contexto do seu projeto. Revise a seção 'Priorização de Findings' da aula."

**Se aluno teve dificuldade alta (<70%)**:
> "Vejo que você enfrentou dificuldades. Vamos por partes: 1) Refaça a instalação seguindo o passo a passo da documentação oficial. 2) Use um projeto de exemplo primeiro (OWASP WebGoat). 3) Agende monitoria para tirar dúvidas específicas."

---

<a id="exercicio-212"></a>
## 📘 Exercício 2.1.2: Criar Regras Customizadas Semgrep

**Nível**: Intermediário  
**Tempo estimado**: 90 minutos  
**Tipo**: Hands-on técnico + análise

### ✅ Objetivo do Exercício
Avaliar se o aluno entende a sintaxe do Semgrep e consegue criar regras customizadas para detectar vulnerabilidades específicas.

### 📋 Critérios de Avaliação

| Critério | Peso | O que avaliar |
|----------|------|---------------|
| **Regra customizada funcional** | 40% | Regra detecta vulnerabilidade específica corretamente |
| **Sintaxe correta YAML** | 20% | Arquivo `.semgrep.yml` válido |
| **Teste da regra** | 20% | Evidência de execução e detecção |
| **Documentação** | 20% | README explicando o que a regra detecta e por quê |

### 🎯 Resposta Esperada

#### Entregável: Regra Semgrep customizada

**Exemplo de resposta EXCELENTE** (detectar uso de `eval()` em JavaScript):

```yaml
rules:
  - id: dangerous-eval-usage
    pattern: eval($ARG)
    message: |
      Uso de eval() detectado. Eval executa código arbitrário e é vetor
      de ataque para Code Injection (CWE-94). 
      
      Alternativa segura: 
      - Use JSON.parse() para parsing de JSON
      - Use Function() constructor com sanitização
      - Reescreva lógica sem eval
    severity: ERROR
    languages:
      - javascript
      - typescript
    metadata:
      cwe: "CWE-94: Improper Control of Generation of Code"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
      likelihood: HIGH
      impact: HIGH
      references:
        - https://owasp.org/www-community/attacks/Code_Injection
```

**Teste**:
```bash
# Código vulnerável (test-cases/vulnerable.js)
const userInput = req.body.code;
eval(userInput); // ❌ Deve ser detectado

# Executar Semgrep
semgrep --config custom-rules.yml test-cases/

# Output esperado:
# test-cases/vulnerable.js
# severity:error rule:dangerous-eval-usage: Uso de eval() detectado...
```

#### O que torna a resposta EXCELENTE:
- ✅ Regra funcional (detecta `eval()`)
- ✅ Mensagem educativa (explica o risco + CWE)
- ✅ Alternativas sugeridas
- ✅ Metadata completa (CWE, OWASP)
- ✅ Teste com caso vulnerável

### ❌ Erros Comuns e Como Orientar

#### Erro 1: "Regra detecta TUDO, até casos seguros (muitos false positives)"
**Causa**: Pattern muito genérico  
**Exemplo ruim**: `pattern: $FUNC(...)`  
**Orientação**:
- Seja mais específico: `pattern: eval($ARG)`
- Use `pattern-not` para excluir casos seguros
- Teste com código real antes de finalizar

#### Erro 2: "YAML inválido (erro de sintaxe)"
**Causa**: Indentação incorreta  
**Orientação**:
- Semgrep é MUITO sensível a indentação
- Use SEMPRE 2 espaços (não tabs)
- Valide YAML online: https://www.yamllint.com/

#### Erro 3: "Regra muito simples (apenas detecta, sem contexto)"
**Causa**: Faltou documentação/metadata  
**Orientação**:
- Adicione `message` explicando O RISCO
- Inclua `metadata` com CWE/OWASP
- Sugira ALTERNATIVA SEGURA na mensagem

### 💡 Feedback Construtivo

**Se aluno criou regra avançada**:
> "Impressionante! Sua regra está production-ready. Você incluiu metadata, CWE, alternativas seguras. Próximo nível: contribua para o repositório oficial do Semgrep (https://github.com/returntocorp/semgrep-rules). Sua regra seria útil para a comunidade!"

**Se aluno criou regra básica mas funcional**:
> "Boa! A regra funciona. Para elevar o nível: 1) Adicione `metadata` com CWE/OWASP, 2) Melhore a `message` explicando o IMPACTO, 3) Teste com mais casos (positivos e negativos). Veja exemplos do repositório oficial para inspiração."

---

<a id="exercicio-213"></a>
## 📘 Exercício 2.1.3: Integrar SAST no CI/CD

**Nível**: Intermediário  
**Tempo estimado**: 90 minutos  
**Tipo**: DevSecOps integration

### ✅ Objetivo do Exercício
Avaliar se o aluno consegue integrar ferramentas SAST (SonarQube ou CodeQL) em pipeline CI/CD e configurar Quality Gates.

### 📋 Critérios de Avaliação

| Critério | Peso | O que avaliar |
|----------|------|---------------|
| **Pipeline funcional** | 30% | Workflow CI/CD executa scan automaticamente |
| **Quality Gate configurado** | 30% | Pipeline bloqueia se vulnerabilidades críticas |
| **Notificações** | 15% | Alertas configurados (Slack, email, PR comment) |
| **Documentação** | 15% | README com instruções de setup |
| **Testes** | 10% | Evidência de execução (logs, screenshots) |

### 🎯 Resposta Esperada

#### Entregável: Workflow GitHub Actions (exemplo)

```yaml
# .github/workflows/security-scan.yml
name: Security SAST Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  sast-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Shallow clones desabilitados para análise completa
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.projectKey=meu-projeto
            -Dsonar.qualitygate.wait=true
      
      - name: Quality Gate Check
        run: |
          STATUS=$(curl -s -u ${{ secrets.SONAR_TOKEN }}: \
            "${{ secrets.SONAR_HOST_URL }}/api/qualitygates/project_status?projectKey=meu-projeto" \
            | jq -r '.projectStatus.status')
          
          if [ "$STATUS" != "OK" ]; then
            echo "❌ Quality Gate FAILED"
            echo "🔍 Vulnerabilidades críticas encontradas"
            exit 1
          fi
          echo "✅ Quality Gate PASSED"
      
      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '✅ SAST scan completed. Check SonarQube dashboard for details.'
            })
```

#### Quality Gate Configuration (SonarQube):
```
Condições do Quality Gate:
- Vulnerabilities (Critical) = 0
- Vulnerabilities (High) <= 2
- Security Hotspots Reviewed >= 80%
- Code Smells (Critical) <= 5
- Coverage >= 70%
```

### ❌ Erros Comuns e Como Orientar

#### Erro 1: "Pipeline executa mas não bloqueia quando tem vulnerabilidade"
**Causa**: Faltou `-Dsonar.qualitygate.wait=true` ou step de verificação  
**Orientação**:
- Adicionar flag `qualitygate.wait=true`
- OU criar step separado que verifica status via API
- Garantir que pipeline falha (`exit 1`) se Quality Gate = FAILED

#### Erro 2: "Secrets expostos no código do workflow"
**Causa**: Hardcoded tokens/URLs  
**Orientação**:
- ❌ NUNCA: `SONAR_TOKEN: abc123`
- ✅ SEMPRE: `SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}`
- Configurar secrets no GitHub: Settings > Secrets and variables > Actions

#### Erro 3: "Pipeline muito lento (>15 minutos)"
**Causa**: Scan completo em cada PR  
**Orientação**:
- Use análise incremental: `sonar.pullrequest.key`
- Cache de dependências: `actions/cache`
- Considere executar scan completo só em `main`, incremental em PRs

### 💡 Feedback Construtivo

**Se pipeline está production-ready**:
> "Excelente integração! Seu pipeline está pronto para produção. Você configurou Quality Gates, notificações e tratamento de erros. Sugestão de melhoria: adicione cache para acelerar (atualmente ~8min, pode cair para ~3min com cache de `node_modules`)."

**Se pipeline funciona mas falta polish**:
> "Bom trabalho! O básico está funcionando. Para profissionalizar: 1) Adicione step de notificação (PR comment ou Slack), 2) Configure Quality Gate no SonarQube (atualmente está usando default), 3) Documente no README como devs devem interpretar falhas do pipeline."

---

<a id="exercicio-214"></a>
## 📘 Exercício 2.1.4: Validar e Priorizar Findings SAST

**Nível**: Intermediário  
**Tempo estimado**: 60 minutos  
**Tipo**: Análise crítica

### ✅ Objetivo do Exercício
Avaliar capacidade do aluno de diferenciar true/false positives e priorizar vulnerabilidades por contexto de negócio (não apenas CVSS).

### 📋 Critérios de Avaliação

| Critério | Peso | O que avaliar |
|----------|------|---------------|
| **Identificação de False Positives** | 35% | Aluno identifica corretamente FPs com justificativa técnica |
| **Priorização contextual** | 35% | Priorização baseada em contexto, não só CVSS |
| **Justificativas** | 20% | Explicações técnicas sólidas |
| **Plano de ação** | 10% | Define próximos passos claros |

### 🎯 Resposta Esperada

#### Cenário do Exercício:
SAST reportou 15 vulnerabilidades em aplicação de e-commerce:
1. SQL Injection (CRITICAL) em `/admin/users` - Acesso restrito a admins
2. Hardcoded API Key (HIGH) em `config.js` - É API key de TESTE (sandbox)
3. XSS (MEDIUM) em `/search` - Input sanitizado em frontend (React)
4. Path Traversal (HIGH) em `/uploads` - Aplicação não permite file upload
5. Insecure Randomness (LOW) em geração de ID de pedido

#### Resposta ESPERADA (exemplo de análise):

| # | Vulnerabilidade | CVSS | True/False Positive | Prioridade | Justificativa |
|---|-----------------|------|---------------------|------------|---------------|
| 1 | SQL Injection em /admin/users | 9.8 | ✅ TRUE | **P1 - ALTA** | Endpoint `/admin` tem autenticação mas sem prepared statements. Exploitável se atacante comprometer conta admin. **CORRIGIR URGENTE**. |
| 2 | Hardcoded API Key | 8.5 | ❌ FALSE | P3 - BAIXA | API key é de ambiente sandbox (Stripe Test Key). Não há risco. **Criar issue para documentar que é teste**. |
| 3 | XSS em /search | 6.1 | ❌ FALSE | P4 - INFORMATIVO | React sanitiza automaticamente via JSX. Testado manualmente: payload `<script>alert(1)</script>` renderiza como texto. **Ignorar ou ajustar regra SAST**. |
| 4 | Path Traversal em /uploads | 7.5 | ❌ FALSE | P4 - INFORMATIVO | Aplicação NÃO tem feature de upload. Endpoint `/uploads` serve arquivos estáticos (CDN). Sem input de usuário. **False positive - ignorar**. |
| 5 | Insecure Randomness em ID pedido | 3.1 | ✅ TRUE | **P2 - MÉDIA** | IDs sequenciais permitem enumeration de pedidos. Embora precise de autenticação, atacante pode descobrir total de vendas (info sensível). **CORRIGIR mas não blocker**. |

#### Plano de Ação:
```markdown
## Próximos Passos

### Imediato (Sprint atual):
1. ✅ P1: Corrigir SQL Injection usando prepared statements
   - Assignar: @dev-backend
   - Prazo: 2 dias
   - Teste: Reproduzir exploit + validar correção

### Curto Prazo (Próxima sprint):
2. ✅ P2: Substituir Math.random() por UUID v4 na geração de IDs
   - Assignar: @dev-backend
   - Prazo: 1 semana
   - Teste: Verificar entropia dos IDs gerados

### Backlog (Housekeeping):
3. ✅ Documentar que API key em config.js é de teste (adicionar comentário)
4. ✅ Ajustar regra SAST para ignorar XSS em componentes React
5. ✅ Remover endpoint /uploads do escopo do scanner (não aplicável)
```

### ❌ Erros Comuns e Como Orientar

#### Erro 1: "Aluno marca TODOS como True Positive"
**Causa**: Confiança cega na ferramenta  
**Orientação**:
> "SAST tem taxa de 20-40% de false positives. Você DEVE validar manualmente. Pergunte-se: 1) Esse código é realmente executado? 2) Há mitigações (sanitização, validação)? 3) O contexto permite exploração?"

#### Erro 2: "Priorização só por CVSS (ignora contexto)"
**Causa**: Não entendeu diferença entre severidade vs prioridade  
**Orientação**:
> "CVSS 9.8 em endpoint de TESTE pode ser P3. CVSS 6.0 em checkout pode ser P1. Priorize por: 1) Dados expostos (PII, financeiros), 2) Facilidade de exploração, 3) Impacto no negócio."

### 💡 Feedback Construtivo

**Se aluno acertou >80% da análise**:
> "Análise impecável! Você demonstrou pensamento crítico e não confiou cegamente na ferramenta. Sua priorização contextual está correta. Esse é o diferencial de um QA Security sênior."

---

<a id="exercicio-215"></a>
## 📘 Exercício 2.1.5: Trade-off Segurança vs Entrega

**Nível**: Avançado ⭐⭐  
**Tempo estimado**: 90 minutos  
**Tipo**: Análise estratégica + decisão

### ✅ Objetivo do Exercício
Avaliar maturidade do aluno em tomar decisões de trade-off entre segurança e velocidade de entrega em cenários reais.

### 📋 Critérios de Avaliação

| Critério | Peso | O que avaliar |
|----------|------|---------------|
| **Análise de risco** | 30% | Compreensão do impacto real da vulnerabilidade |
| **Decisão fundamentada** | 30% | Justificativa técnica e de negócio |
| **Plano de mitigação** | 25% | Medidas compensatórias se decidir liberar |
| **Comunicação** | 15% | Clareza na comunicação com stakeholders |

### 🎯 Cenário do Exercício

**Contexto**: Black Friday em 48 horas. Deploy planejado amanhã (17h).  
SAST encontrou 3 vulnerabilidades no último PR:

1. **SQL Injection (CRITICAL)** em novo endpoint de busca avançada
   - CVSS: 9.8
   - Endpoint: `/api/advanced-search` (novo, ainda não divulgado)
   - Fix: 8 horas de dev + 4 horas de teste

2. **XSS Reflected (MEDIUM)** em página de confirmação de pedido
   - CVSS: 6.1
   - Exploitável apenas com engenharia social (link malicioso)
   - Fix: 2 horas de dev + 1 hora de teste

3. **Missing Rate Limiting (LOW)** em endpoint de login
   - CVSS: 3.1
   - Permite brute force (mas já existe bloqueio após 5 tentativas no front)
   - Fix: 4 horas de dev + 2 horas de teste

**Pergunta**: O que você faria?

### ✅ Resposta EXCELENTE (exemplo)

```markdown
## Decisão

### ✅ LIBERAR DEPLOY com mitigações

#### Justificativa:

**Contexto de Negócio**:
- Black Friday representa 40% da receita anual
- Atraso de 24h = perda estimada de R$2M
- Concorrentes já lançaram suas promoções
- Risco reputacional alto se não cumprirmos prazo anunciado

**Análise de Risco por Vulnerabilidade**:

1. **SQL Injection (CRITICAL)**
   - ❌ **BLOQUEAR esse endpoint especificamente**
   - Motivo: Risco inaceitável (dump de DB, PII exposto)
   - Mitigação: Desabilitar `/api/advanced-search` via feature flag
   - Impacto: Busca avançada não é crítica para Black Friday (90% usa busca básica)

2. **XSS Reflected (MEDIUM)**
   - ⚠️ **ACEITAR TEMPORARIAMENTE** (deploy com risco calculado)
   - Motivo: Exploração requer eng. social + URL maliciosa
   - Mitigações:
     * WAF rule para bloquear payloads XSS comuns
     * Monitoramento de alertas SOC intensificado
     * Fix deployado em hotfix 24h após Black Friday
   - Risco residual: BAIXO (não há casos de XSS explorado via email no histórico)

3. **Missing Rate Limiting (LOW)**
   - ✅ **ACEITAR** (já tem controle no frontend)
   - Motivo: Impacto mínimo (já bloqueio após 5 tentativas no client)
   - Mitigação: Backlog para implementar rate limiting no backend
   - Risco residual: MUITO BAIXO

#### Plano de Ação:

**Hoje (antes do deploy)**:
- [ ] Desabilitar feature flag de Advanced Search
- [ ] Configurar WAF rule anti-XSS (CloudFlare/AWS WAF)
- [ ] Briefing para time SOC: monitoramento intensivo durante BF

**Black Friday (monitoramento)**:
- [ ] Plantão de QA + Dev durante pico de vendas (10h-22h)
- [ ] Dashboard de segurança em tempo real (alertas XSS, SQL injection attempts)

**Pós Black Friday (remediação)**:
- [ ] Hotfix XSS (prazo: 48h após BF)
- [ ] Fix SQL Injection completo + testes (prazo: 1 semana)
- [ ] Post-mortem da decisão

#### Comunicação para Stakeholders:

**Para C-Level (CEO, CTO)**:
> "Identificamos 3 vulnerabilidades. Uma (Critical) bloqueia feature não-essencial. Outras duas (Medium/Low) aceitamos com mitigações temporárias (WAF + monitoramento). Deploy segue amanhã com risco controlado. Correções permanentes em 1 semana."

**Para Time de Dev**:
> "Deploy liberado COM EXCEÇÃO de Advanced Search (SQL Injection). Implementem feature flag para desabilitar. XSS em confirmação de pedido fica para hotfix pós-BF (já configuramos WAF). Rate limiting fica pra próxima sprint."

**Para Time de Infra/SOC**:
> "Ativem regra WAF anti-XSS no CloudFlare (anexo: ruleset). Monitoramento intensivo durante BF: alertas de SQL injection attempts e XSS payload detection. Contato emergencial: meu celular 24/7."
```

### ❌ Erros Comuns e Como Orientar

#### Erro 1: "Bloquear TUDO (zero risk tolerance)"
**Resposta do aluno**: "Não podemos deployar com vulnerabilidades. Adiar Black Friday."  
**Orientação**:
> "Segurança não é absoluta. É GESTÃO DE RISCO. Você acabou de causar R$2M de prejuízo. Black Friday não espera. A decisão correta é: quais riscos podemos MITIGAR e aceitar temporariamente? Feature flags, WAF, monitoramento são ferramentas pra isso."

#### Erro 2: "Liberar TUDO (ignorar segurança)"
**Resposta do aluno**: "É Black Friday, ignora as vulnerabilidades e corrige depois."  
**Orientação**:
> "SQL Injection CRITICAL não é negociável. Você acabou de expor 5 milhões de CPFs. Resultado: multa LGPD de R$50M + processo. A decisão correta é: qual vulnerabilidade é INACEITÁVEL mesmo com mitigação? SQL Injection é. XSS pode ser mitigado."

#### Erro 3: "Faltou plano de mitigação"
**Resposta do aluno**: "Vou deployar e torcer pra não ser explorado."  
**Orientação**:
> "Aceitar risco SEM mitigação é irresponsável. Se vai deployar com XSS, precisa de: 1) WAF rule, 2) Monitoramento, 3) Plano de rollback, 4) Prazo de fix. Risco CALCULADO ≠ Risco IGNORADO."

### 💡 Feedback Construtivo

**Se aluno tomou decisão equilibrada**:
> "Decisão impecável! Você demonstrou maturidade profissional: bloqueou o inaceitável (SQL Injection), mitigou o aceitável (XSS via WAF), e comunicou claramente para stakeholders. Essa é a postura de um Lead QA Security. Parabéns!"

**Se aluno foi muito conservador ou muito liberal**:
> "Sua análise tem pontos válidos, mas faltou equilíbrio. Lembre-se: QA Security não é 'polícia do não'. É GESTOR DE RISCO. Revise o framework: 1) Qual o impacto REAL? 2) Quais mitigações existem? 3) Qual o custo de atrasar vs. risco de liberar? Refaça o exercício com esse mindset."

---

## 📊 Resumo da Correção - Aula 2.1

| Exercício | Tipo | Tempo Correção | Prioridade |
|-----------|------|----------------|------------|
| 2.1.1 | Técnico | 10-15 min | Alta (fundamento) |
| 2.1.2 | Técnico | 15-20 min | Média |
| 2.1.3 | DevSecOps | 15-20 min | Alta (integração) |
| 2.1.4 | Análise | 20-30 min | Alta (pensamento crítico) |
| 2.1.5 | Estratégico | 30-40 min | **Crítica** (diferencial) |

**Total estimado para corrigir Aula 2.1**: ~2 horas por aluno

---

_[Continua para Aula 2.2...]_

---

## 🔄 Controle de Versão

| Versão | Data | Mudanças |
|--------|------|----------|
| 1.0 | Jan/2026 | Versão inicial - Aula 2.1 completa |
| 1.1 | (pendente) | Aulas 2.2 a 2.5 |

---

**Próximas seções a serem adicionadas**:
- ⏳ Aula 2.2: DAST (4 exercícios)
- ⏳ Aula 2.3: Pentest (4 exercícios)
- ⏳ Aula 2.4: Automação (5 exercícios)
- ⏳ Aula 2.5: SCA (5 exercícios)
