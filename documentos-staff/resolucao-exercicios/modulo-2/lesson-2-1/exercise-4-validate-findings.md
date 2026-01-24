---
exercise_id: lesson-2-1-exercise-4-validate-findings
title: "Exercício 2.1.4: Validar Findings (True/False Positive)"
lesson_id: lesson-2-1
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.1.4: Validar Findings (True/False Positive)

## 📋 Enunciado Completo

Este exercício tem como objetivo **analisar relatório SAST com 50+ findings**, **validar manualmente quais são TRUE vs FALSE POSITIVES**, e **criar plano de remediação priorizado** baseado em risco real (não apenas CVSS).

**Contexto**: Ferramentas SAST têm taxa de **False Positives de 20-40%** (Gartner, 2025). QA Security profissional NUNCA confia cegamente em ferramentas - **validação manual é essencial** para evitar trabalho desnecessário do time de desenvolvimento e manter credibilidade.

### Tarefa

1. **Analisar relatório SAST completo** (SonarQube, Semgrep, ou similar)
2. **Validar manualmente top 10-15 findings** (TRUE vs FALSE POSITIVE)
3. **Testar exploração** de vulnerabilidades críticas (POC quando aplicável)
4. **Priorizar por risco real** (não apenas CVSS - considerar contexto de negócio)
5. **Criar plano de remediação com sprints** e responsáveis
6. **Documentar processo de triagem** (template replicável)
7. **Configurar exceções** para False Positives no SAST

---

## ✅ Soluções Detalhadas

### Passo 1: Análise Inicial do Relatório SAST

**1.1. Carregar Relatório**

```bash
# Se SonarQube
# Acesse: http://sonarqube.example.com/dashboard?id=my-project
# Navegue para: Security Hotspots → Vulnerabilities

# Se Semgrep (exportar JSON)
semgrep scan --config=p/security-audit --json --output=findings.json .

# Análise rápida do JSON
cat findings.json | jq '[.results[] | .extra.severity] | group_by(.) | map({severity: .[0], count: length})'
# Output:
# [
#   {"severity": "ERROR", "count": 8},    # Critical
#   {"severity": "WARNING", "count": 15}, # High
#   {"severity": "INFO", "count": 31}     # Medium/Low
# ]
```

**1.2. Agrupar por Tipo**

```markdown
## Resumo do Relatório SAST

### Total de Findings: 54

**Por Severidade:**
- Critical: 8 (15%)
- High: 15 (28%)
- Medium: 21 (39%)
- Low: 10 (18%)

**Por Categoria (CWE):**
- Injection (SQLi, Command Injection): 12 findings (22%)
- Hardcoded Secrets: 8 findings (15%)
- Insecure Cryptography: 6 findings (11%)
- Path Traversal: 4 findings (7%)
- Outros: 24 findings (45%)

**Padrões Identificados:**
- 8 de 12 injection vulnerabilities estão em `/api/*` (falta de input validation centralizada)
- 8 hardcoded secrets estão em arquivos de config (falta de gestão de secrets)
- 6 crypto issues usam MD5/SHA1 (algoritmos obsoletos)
```

---

### Passo 2: Validação Manual - TRUE vs FALSE POSITIVE

**Template de Validação:**

```markdown
## Finding #1: SQL Injection em UserController.getUser()

### Informações do SAST
- **Ferramenta**: SonarQube
- **Arquivo**: `src/controllers/UserController.java`
- **Linha**: 45
- **Severidade**: CRITICAL (CVSS 9.8)
- **CWE**: CWE-89 (SQL Injection)
- **Confidence**: High

### Código Flagado
```java
// Line 45
public User getUser(String userId) {
    String query = "SELECT * FROM users WHERE id = '" + userId + "'";
    return db.executeQuery(query);
}
```

### Validação Manual

**Teste 1: Reprodução Local**
```bash
# Payload SQLi básico
curl "http://localhost:8080/api/users/1' OR '1'='1' --"

# Resultado:
# Status: 200 OK
# Body: [{"id": 1, "name": "Admin"}, {"id": 2, "name": "User2"}, ...] 
# ✅ Retornou TODOS os usuários (bypass de filtro)
```

**Teste 2: Union-Based SQLi**
```bash
curl "http://localhost:8080/api/users/1' UNION SELECT password,email,cpf FROM users--"

# Resultado:
# Status: 200 OK
# Body: [{"id": "5f4dcc3b...", "name": "admin@example.com", ...}]
# ✅ Vazou senhas hash e CPFs
```

**Conclusão: ✅ TRUE POSITIVE**

**Evidências:**
1. Payload básico (`' OR '1'='1' --`) funcionou
2. Union-based SQLi extraiu dados sensíveis
3. Código em **PRODUÇÃO**, endpoint **PÚBLICO**
4. Dados sensíveis afetados: senhas hash, CPFs, emails

**Risco Real:**
- Exposição de 50K+ registros de clientes
- Violação LGPD (Art. 48) - notificação ANPD obrigatória
- Potencial escalação para RCE (via `xp_cmdshell` se SQL Server)

**Prioridade: P0 - IMEDIATO (< 48h)**

---

## Finding #2: Hardcoded Password em DatabaseConfig.java

### Informações do SAST
- **Ferramenta**: Semgrep
- **Arquivo**: `src/test/config/DatabaseConfig.java`
- **Linha**: 12
- **Severidade**: HIGH (CVSS 7.5)
- **CWE**: CWE-798 (Use of Hard-coded Credentials)

### Código Flagado
```java
// Line 12 (src/test/config/DatabaseConfig.java)
public class DatabaseConfig {
    private static final String DB_PASSWORD = "test123";
    // ...
}
```

### Validação Manual

**Análise de Contexto:**
1. **Arquivo**: `src/test/config/` (diretório de testes)
2. **Uso**: Database de teste local (não produção)
3. **Dados**: Nenhum dado real (fixtures de teste)
4. **Exposição**: Não vai para produção (excluído no build)

**Verificação no pom.xml:**
```xml
<build>
  <resources>
    <resource>
      <directory>src/main/resources</directory>
      <!-- src/test/ NÃO incluído no build final -->
    </resource>
  </resources>
</build>
```

**Conclusão: ❌ FALSE POSITIVE**

**Justificativa:**
- Código está em `src/test/` (não vai para produção)
- Senha é para DB de teste local (H2 in-memory)
- Nenhum dado sensível em risco
- Prática comum em testes (fixtures)

**Ação:**
1. Marcar como FALSE POSITIVE no SonarQube
2. Adicionar exceção: `// NOSONAR - Test configuration, not production`
3. Documentar no README: "Senhas hardcoded em `src/test/` são aceitáveis (não vão para prod)"

**Prioridade: P4 - IGNORAR (aceitar risco)**
```

---

### Passo 3: Matriz de Priorização Contextual

**Critérios de Priorização:**

| Critério | Peso | Como Avaliar |
|----------|------|--------------|
| **CVSS Base Score** | 20% | Severidade técnica (0-10) |
| **Contexto de Negócio** | 30% | Dados sensíveis? Compliance (LGPD, PCI-DSS)? |
| **Exploitabilidade** | 25% | Fácil (URL) ou difícil (race condition, auth)? |
| **Impacto Real** | 25% | Quantos users afetados? Downtime? |

**Exemplo de Priorização:**

| # | Finding | CVSS | Contexto | Exploitabilidade | Impacto | **Prioridade** |
|---|---------|------|----------|------------------|---------|--------------|
| 1 | SQL Injection (checkout) | 9.8 | 🔴 LGPD + PCI-DSS | 🔴 Trivial (URL) | 🔴 50K users | **P0** |
| 2 | Hardcoded API Key (prod) | 8.5 | 🔴 Acesso total | 🟠 Fácil (repo público) | 🔴 Sistema inteiro | **P0** |
| 3 | XSS Stored (comments) | 7.5 | 🟠 Phishing | 🟠 Moderado (post comment) | 🟠 Usuários que veem | **P1** |
| 4 | Path Traversal (logs) | 8.0 | 🟡 Config exposure | 🟠 Fácil (URL) | 🟡 Configs (não PII) | **P2** |
| 5 | MD5 Hash (test utils) | 6.0 | 🟢 Código de teste | 🟢 Não exploitável | 🟢 Zero | **P4 (FP)** |

**Legenda:**
- **P0 - IMEDIATO**: < 48h (Critical em prod + dados sensíveis + fácil exploração)
- **P1 - URGENTE**: < 2 semanas (High em prod + impacto significativo)
- **P2 - PRÓXIMA SPRINT**: < 1 mês (Medium ou High sem exposição direta)
- **P3 - BACKLOG**: Gradual (Low + código não crítico)
- **P4 - ACEITAR RISCO**: Ignorar (FALSE POSITIVE ou risco negligenciável)

---

### Passo 4: Plano de Remediação

```markdown
## Plano de Remediação - 4 Semanas

### Sprint 0 (Hotfix - 48h)
**Objetivo**: Zerar vulnerabilidades P0

| # | Vulnerabilidade | Responsável | Correção | Validação | Status |
|---|-----------------|-------------|----------|-----------|--------|
| 1 | SQL Injection (6 endpoints) | @backend-team | Prepared statements | Pentest manual | 🔄 |
| 2 | Hardcoded API Key (Stripe) | @devops-team | AWS Secrets Manager | Integration test | 📋 |

**Entregável**: Patch em produção (27/01 18h), relatório de validação

---

### Sprint 1 (Semanas 1-2)
**Objetivo**: Corrigir High (P1) + testes automatizados

| # | Vulnerabilidade | Responsável | Correção | Testes | Status |
|---|-----------------|-------------|----------|--------|--------|
| 3 | XSS Stored (comments) | @backend-team | DOMPurify sanitization | Selenium tests | 📋 |
| 4 | CSRF (profile update) | @backend-team | CSRF tokens | Integration tests | 📋 |
| 5 | Insecure Deserialization | @backend-team | Safe deserializer | Unit tests | 📋 |

**Entregável**: Features corrigidas + 12 testes automatizados

---

### Sprint 2 (Semanas 3-4)
**Objetivo**: Medium (P2) + refactoring sistêmico

| # | Ação | Responsável | Implementação | Validação | Status |
|---|------|-------------|---------------|-----------|--------|
| 6 | Input Validation Middleware | @backend-team | Joi/Yup validator | SonarQube rescan | 📋 |
| 7 | Secrets Management | @devops-team | Migrate all to Secrets Manager | Audit | 📋 |
| 8 | Crypto Upgrade (MD5 → SHA256) | @backend-team | Replace hash functions | Unit tests | 📋 |

**Entregável**: Refactoring sistêmico + 0 Critical/High no SAST

---

### Métricas de Sucesso

| Métrica | Baseline (Hoje) | Meta (4 semanas) |
|---------|-----------------|------------------|
| **Critical Findings** | 8 | 0 |
| **High Findings** | 15 | 0 |
| **Medium Findings** | 21 | < 5 |
| **False Positives Identificados** | 0 | 12+ (documentados) |
| **Cobertura de Testes de Segurança** | 0% | 80% |
```

---

### Passo 5: Configurar Exceções no SAST

**5.1. SonarQube - Marcar False Positives**

1. Acesse finding no SonarQube
2. **Mark as** → **Won't Fix** ou **False Positive**
3. Adicione comentário justificando
4. Código:
```java
// NOSONAR - Test configuration, not production (validated 2026-01-24)
private static final String TEST_PASSWORD = "test123";
```

**5.2. Semgrep - Criar `.semgrepignore`**

```yaml
# .semgrep/rules-exceptions.yml
rules:
  - id: hardcoded-credentials
    paths:
      exclude:
        - "src/test/**"
        - "**/*Test.java"
        - "**/*TestConfig.java"
    message: "Test files can have hardcoded credentials (not production)"
```

**5.3. Documentar False Positives**

```markdown
# docs/security/KNOWN_FALSE_POSITIVES.md

## Known False Positives (SAST)

### 1. Hardcoded Credentials em `src/test/**`
- **Ferramenta**: SonarQube, Semgrep
- **Status**: FALSE POSITIVE (validado em 24/01/2026)
- **Justificativa**: Código de teste, não vai para produção
- **Ação**: Adicionado `// NOSONAR` e exceção no Semgrep
- **Revisar em**: 24/04/2026 (trimestral)

### 2. MD5 Hash em `TestUtils.java`
- **Ferramenta**: SonarQube
- **Status**: FALSE POSITIVE (validado em 24/01/2026)
- **Justificativa**: Hash para fixtures de teste (não criptografia real)
- **Ação**: Marcado como "Won't Fix" no SonarQube
- **Revisar em**: 24/04/2026 (trimestral)
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios)

**Validação Manual:**
- [ ] Validou pelo menos 10 findings manualmente
- [ ] Distinguiu TRUE de FALSE POSITIVES com evidências técnicas
- [ ] Testou exploração de pelo menos 2 vulnerabilidades críticas (POC)
- [ ] Documentou processo de validação (replicável)

**Priorização:**
- [ ] Priorizou por risco contextual (não apenas CVSS)
- [ ] Considerou contexto de negócio (LGPD, PCI-DSS, impacto)
- [ ] Criou matriz de priorização (P0, P1, P2, P3, P4)
- [ ] Justificou decisões (por que P0 vs P2?)

**Plano de Remediação:**
- [ ] Plano com sprints definidos (timeline realista)
- [ ] Responsáveis atribuídos (backend, devops, qa)
- [ ] Métricas de sucesso claras (redução de vulnerabilidades)
- [ ] Action items acionáveis (não vagos)

### ⭐ Importantes (Qualidade da Resposta)

**Profundidade Técnica:**
- [ ] POCs funcionais para vulnerabilidades críticas (curl, screenshots)
- [ ] Analisou código-fonte (não apenas relatório SAST)
- [ ] Considerou variações de exploit (bypass techniques)
- [ ] Documentou impacto de negócio (não apenas técnico)

**Gestão de False Positives:**
- [ ] Configurou exceções no SAST (regras, anotações)
- [ ] Documentou FPs (wiki, README)
- [ ] Criou processo de revisão (trimestral)
- [ ] Comunicou para time (não re-investigar)

**Processo Replicável:**
- [ ] Template de validação criado (outros QAs podem usar)
- [ ] Checklist de priorização documentado
- [ ] Comunicação clara para stakeholders (dev, PO, CEO)

### 💡 Diferencial (Conhecimento Avançado)

**Automação:**
- [ ] Script de validação automatizada (testes de exploração)
- [ ] Dashboard de métricas (% TP vs FP ao longo do tempo)
- [ ] Integração com Jira (tickets criados automaticamente)

**Estratégia de Longo Prazo:**
- [ ] Baseline para código legado (remediação graduada)
- [ ] SLA de correção (Critical 7 dias, High 30 dias)
- [ ] Security Champions program (devs treinados)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Ceticismo Saudável**: Não confia cegamente em ferramentas SAST?
2. **Validação Manual**: Testa exploração real (não apenas lê relatório)?
3. **Priorização Contextual**: Considera negócio (não apenas CVSS)?
4. **Gestão de False Positives**: Documenta e configura exceções?
5. **Comunicação Multi-Nível**: Adapta para devs (técnico) vs PO (negócio)?

### Erros Comuns

**Erro 1: "Marcou tudo como TRUE POSITIVE sem validar manualmente"**
- **Causa**: Confiou 100% no SAST, não testou exploração
- **Feedback**: "SAST tem 20-40% FALSE POSITIVES. VALIDAÇÃO OBRIGATÓRIA: 1) Para CADA finding Critical/High, tente explorar manualmente, 2) Analise código-fonte (contexto: teste vs prod?), 3) Documente evidências (POC funcionou? Screenshot?), 4) Se não conseguir explorar = investigar se é FP. Exemplo: SQLi reportado em `TestUtils.java` (código de teste) = provavelmente FP. Sem validação = devs vão perder tempo corrigindo FPs."

**Erro 2: "Priorizou APENAS por CVSS (ignorou contexto)"**
- **Causa**: Não considerou se código está em produção, dados sensíveis, facilidade de exploração
- **Feedback**: "CVSS é GENÉRICO. Priorização real considera CONTEXTO: 1) Código em produção ou teste? (teste = menos crítico), 2) Dados sensíveis afetados? (CPF, cartão = P0), 3) Facilidade de exploração? (URL param = fácil, race condition = difícil), 4) Compliance? (LGPD, PCI-DSS = P0). EXEMPLO: SQLi CVSS 9.8 em endpoint de teste isolado = P2 (não Critical). Re-priorize usando matriz de risco contextual."

**Erro 3: "Não documentou processo de triagem"**
- **Causa**: Validou findings mas não criou template replicável
- **Feedback**: "Processo não documentado = não é escalável. DOCUMENTE: 1) Template de validação (outros QAs usam), 2) Checklist de priorização (critérios claros), 3) False Positives conhecidos (wiki/README), 4) SLA de correção (P0 48h, P1 2 sem). BENEFÍCIO: Próximo scan (mensal) você não re-investiga mesmos FPs. Time cresce = processo documentado permite onboarding rápido."

**Erro 4: "Não configurou exceções para FALSE POSITIVES no SAST"**
- **Causa**: Validou FPs mas não marcou na ferramenta
- **Feedback**: "FPs não marcados = aparecem em TODO scan futuro (ruído). CONFIGURAR EXCEÇÕES: 1) SonarQube: Mark as 'Won't Fix' + comentário, 2) Semgrep: adicione em `.semgrepignore` ou custom rules, 3) Código: adicione `// NOSONAR` com justificativa. VALIDAÇÃO: Próximo scan não deve reportar FPs conhecidos. Gestão de ruído é essencial para credibilidade do SAST."

**Erro 5: "Plano de remediação vago ('corrigir vulnerabilidades')"**
- **Causa**: Não definiu responsáveis, prazos, sprints
- **Feedback**: "Plano vago não é acionável. PLANO EXECUTÁVEL: 1) Sprint 0 (48h): 6 Critical (responsável: @backend, prazo: 27/01), 2) Sprint 1 (2 sem): 15 High (responsável: @backend + @qa), 3) MÉTRICAS: Reduzir Critical de 8 → 0. Sem responsáveis + prazos = plano não sai do papel. Crie tickets no Jira para cada vulnerability com: POC, código de correção, checklist de validação."

**Erro 6: "Não testou POC de vulnerabilidades críticas"**
- **Causa**: Apenas leu relatório SAST, não validou se é explorável
- **Feedback**: "Finding reportado ≠ finding explorável. TESTE POC: 1) SQLi: tente `' OR '1'='1' --`, funcionou?, 2) XSS: tente `<script>alert(1)</script>`, executou?, 3) Path Traversal: tente `../../../../etc/passwd`, leu arquivo?. EXEMPLO: SonarQube reportou SQLi, você testou e descobriu que input é validado (regex) = FALSE POSITIVE. POC é prova técnica, não apenas intuição."

### Dicas para Feedback Construtivo

**Para validação exemplar:**
> "Validação exemplar! Você demonstrou: 1) Rigor técnico (testou POCs, analisou código-fonte, distinguiu TPs de FPs), 2) Priorização contextual (considerou LGPD, PCI-DSS, impacto de negócio), 3) Gestão de ruído (documentou FPs, configurou exceções no SAST), 4) Plano executável (sprints, responsáveis, métricas). Seu trabalho está no nível de Security Analyst sênior. Próximo desafio: automatize validações (scripts de exploit), crie dashboard de tendências (% TP/FP ao longo do tempo), lidere Security Champions program."

**Para validação intermediária:**
> "Boa validação! Você distinguiu TPs de FPs e priorizou findings. Para elevar o nível: 1) TESTE POCs (não apenas analise código - valide exploração real), 2) DOCUMENTE processo (template replicável para outros QAs), 3) CONFIGURE exceções SAST (FPs conhecidos não devem aparecer em futuros scans), 4) CRIE matriz de priorização contextual (CVSS + contexto de negócio). Sua análise está correta, agora adicione rigor e documentação."

**Para dificuldades:**
> "Validar findings é desafiador com 50+ alertas. Vamos simplificar: 1) FOQUE no top 10 (ordene por CVSS, valide os 10 primeiros), 2) TEMPLATE: Para cada finding: a) É TRUE ou FALSE POSITIVE? (teste POC), b) Prioridade? (P0 se Critical em prod + PII), c) Responsável + prazo?, 3) DOCUMENTE em planilha simples (Finding | TP/FP | Prioridade | Responsável | Prazo). Após conseguir validação básica, agende monitoria para refinar. Template disponível neste gabarito."

### Contexto Pedagógico

**Por que este exercício é crítico:**

1. **Redução de Trabalho Desnecessário**: 30% dos findings SAST são FPs - validar economiza semanas de trabalho do dev
2. **Credibilidade do QA Security**: Devs ignoram alertas se muitos FPs - validação mantém confiança
3. **Priorização Inteligente**: Não basta severidade - contexto de negócio é crucial (LGPD, compliance)
4. **Gestão de Ruído**: FPs documentados e exceções configuradas = scans futuros são limpos
5. **Habilidade Essencial**: Security Analyst/Engineer roles exigem esta competência

**Conexão com o Curso:**
- **Pré-requisito**: Exercício 2.1.1 (Configurar SonarQube), 2.1.3 (SAST no CI/CD), conhecimento de exploits
- **Aplica conceitos**: TRUE vs FALSE POSITIVE, priorização por risco, matriz de decisão, gestão de exceções
- **Prepara para**: Exercício 2.1.5 (Trade-offs segurança vs entrega), Aula 2.2 (DAST - mesma validação), cargo de Security Analyst
- **Integra com**: Módulo 3 (Secure Development - como corrigir vulnerabilidades), Módulo 4 (DevSecOps - automação de validação)

**Habilidades desenvolvidas:**
- Validação manual de vulnerabilidades (POC, exploração)
- Análise de código-fonte (identificar contexto)
- Priorização por risco contextual (não apenas CVSS)
- Gestão de False Positives (documentação, exceções)
- Comunicação técnica e de negócio
- Criação de planos de remediação executáveis
- Gestão de ruído em ferramentas de segurança

**Estatísticas da Indústria:**
- 35% dos findings SAST são FALSE POSITIVES (Gartner, 2025)
- Times que validam FPs economizam 50% do tempo de remediação (Forrester, 2024)
- Devs ignoram 80% dos alertas não validados (SANS, 2024)
- Priorização contextual aumenta eficiência de correção em 4x (Veracode, 2025)
- Security Analysts que documentam processos têm 3x mais impacto (DevOps Research, 2025)

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
