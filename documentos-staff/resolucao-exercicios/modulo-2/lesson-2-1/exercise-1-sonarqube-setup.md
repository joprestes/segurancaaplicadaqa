---
exercise_id: lesson-2-1-exercise-1-sonarqube-setup
title: "Exercício 2.1.1: Configurar SonarQube em Projeto Próprio"
lesson_id: lesson-2-1
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.1.1: Configurar SonarQube em Projeto Próprio

## 📋 Enunciado Completo

Este exercício tem como objetivo **configurar SonarQube do zero** em um projeto existente e executar sua primeira análise SAST.

### Tarefa

1. Instalar SonarQube usando Docker
2. Configurar projeto no SonarQube
3. Executar primeiro scan
4. Analisar resultados e identificar top 5 vulnerabilidades
5. Criar relatório com análise dos findings

---

## ✅ Soluções Detalhadas

### Passo 1: Instalação do SonarQube

**Solução Esperada:**

O aluno deve demonstrar que instalou SonarQube com sucesso usando Docker:

```bash
# Comando correto
docker run -d --name sonarqube \
  -p 9000:9000 \
  -v sonarqube_data:/opt/sonarqube/data \
  sonarqube:lts-community

# Verificação
docker ps | grep sonarqube
# Deve mostrar container rodando
```

**Evidência de Instalação Correta:**
- Screenshot mostrando `http://localhost:9000` acessível
- Dashboard do SonarQube exibindo "SonarQube is up and running"
- Container rodando (`docker ps` mostra `sonarqube`)

**Variações Aceitáveis:**
- Usar Docker Compose ao invés de `docker run` (mais profissional)
- Instalar localmente via download manual (menos recomendado mas válido)
- Usar SonarQube Cloud (válido se justificado)

---

### Passo 2: Configuração do Projeto

**Solução Esperada:**

O aluno deve ter criado projeto no SonarQube e gerado token:

```properties
# sonar-project.properties (arquivo na raiz do projeto)
sonar.projectKey=meu-projeto-sast
sonar.projectName=Meu Projeto SAST
sonar.sources=src
sonar.sourceEncoding=UTF-8
sonar.exclusions=**/node_modules/**,**/dist/**
```

**Evidência de Configuração Correta:**
- Screenshot do projeto criado no SonarQube
- Token gerado e documentado (parcialmente oculto: `squ_1234...`
- Arquivo `sonar-project.properties` presente no projeto

**Erros Comuns:**
- **Não gerar token**: Aluno tenta executar scan sem token
- **Token exposto**: Aluno commita token no git (ponto de segurança!)
- **Configuração incorreta**: `sonar.sources` apontando para diretório inexistente

---

### Passo 3: Execução do Scan

**Solução Esperada:**

O aluno deve executar scan com sucesso:

```bash
# Comando correto (exemplo)
sonar-scanner \
  -Dsonar.projectKey=meu-projeto-sast \
  -Dsonar.sources=src \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=$SONAR_TOKEN
```

**Evidência de Execução Correta:**
- Log mostrando "EXECUTION SUCCESS"
- Dashboard do SonarQube atualizado com resultados
- Screenshot mostrando métricas: Bugs, Vulnerabilities, Code Smells, Coverage

**Tempo Esperado:**
- Projeto pequeno (< 1000 linhas): 1-2 minutos
- Projeto médio (1000-10000 linhas): 3-5 minutos
- Projeto grande (> 10000 linhas): 5-15 minutos

**Problemas Comuns e Correções:**
- **Erro: Invalid token**: Gerar novo token, verificar variável $SONAR_TOKEN
- **Scan muito lento**: Adicionar exclusões no `sonar-project.properties`
- **Não encontra código**: Verificar `sonar.sources` está correto

---

### Passo 4: Análise de Resultados - Top 5 Vulnerabilidades

**Solução Esperada:**

O aluno deve documentar **pelo menos 3 vulnerabilidades** com análise crítica:

#### Exemplo de Boa Resposta:

```markdown
## Vulnerabilidade #1: SQL Injection em UserController

### Detalhes
- **Severidade**: CRITICAL (9.8)
- **Arquivo**: `src/controllers/UserController.java`
- **Linha**: 45
- **CWE**: CWE-89 (SQL Injection)
- **OWASP Top 10**: A03:2021 – Injection

### Descrição
Concatenação de strings na construção de query SQL permite injeção de código malicioso.

### Código Flagado
```java
String query = "SELECT * FROM users WHERE username = '" + username + "'";
ResultSet rs = stmt.executeQuery(query);
```

### Risco Real
**TRUE POSITIVE** ✅ 
- Exploitável por qualquer usuário com acesso ao endpoint `/api/login`
- Pode expor todos os dados do banco (dump completo)
- Permite bypass de autenticação
- **Contexto**: Código está em produção, endpoint público

### Correção Sugerida
```java
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();
```

### Priorização
- [x] **P0 - IMEDIATO** (< 24h)
  - Justificativa: Risco crítico, código em produção, fácil exploração
  - Ação: Hotfix urgente + comunicar security team
```

**Características de Análise Profissional:**
- ✅ Identifica vulnerabilidade corretamente
- ✅ Avalia se é TRUE ou FALSE POSITIVE
- ✅ Considera **contexto** (código em produção? Dados sensíveis?)
- ✅ Prioriza por **risco real**, não apenas CVSS Score
- ✅ Propõe correção técnica válida

**Níveis de Priorização Esperados:**

| Prioridade | Quando usar |
|------------|-------------|
| **P0 - IMEDIATO** | Critical em produção + dados sensíveis + fácil exploração |
| **P1 - URGENTE** | High em produção + impacto significativo |
| **P2 - SPRINT ATUAL** | Medium ou High sem exposição direta |
| **P3 - PRÓXIMO SPRINT** | Low ou Medium em código não crítico |
| **P4 - BACKLOG** | Low + False Positive + código de teste |

---

## 📊 Critérios de Avaliação (Abordagem Qualitativa)

### ✅ Aspectos Essenciais (Obrigatórios)

**Instalação e Configuração:**
- [ ] SonarQube instalado e rodando corretamente
- [ ] Projeto criado no SonarQube
- [ ] Token gerado e utilizado (sem expor no git)
- [ ] Arquivo `sonar-project.properties` configurado adequadamente

**Execução do Scan:**
- [ ] Scan executado com sucesso ("EXECUTION SUCCESS")
- [ ] Dashboard mostra resultados da análise
- [ ] Aluno conseguiu acessar e navegar nos resultados

**Análise de Vulnerabilidades:**
- [ ] Identificou pelo menos 3 vulnerabilidades
- [ ] Documentou detalhes básicos (arquivo, linha, severidade)
- [ ] Demonstrou compreensão do tipo de vulnerabilidade

### ⭐ Aspectos Importantes (Qualidade da Resposta)

**Análise Crítica:**
- [ ] Avaliou se vulnerabilidades são TRUE ou FALSE POSITIVES
- [ ] Considerou contexto de execução (produção vs teste)
- [ ] Priorizou por risco real, não apenas CVSS
- [ ] Propôs correções técnicas válidas

**Documentação:**
- [ ] Relatório estruturado e organizado
- [ ] Evidências visuais (screenshots) incluídas
- [ ] Justificativas claras para priorização
- [ ] Código de correção quando aplicável

### 💡 Aspectos Diferencial (Conhecimento Avançado)

**Profundidade Técnica:**
- [ ] Testou correções propostas (validou que funcionam)
- [ ] Identificou vulnerabilidades não óbvias (Security Hotspots)
- [ ] Considerou múltiplos contextos (financeiro, educacional, etc.)
- [ ] Configurou Quality Gate personalizado

**Práticas Profissionais:**
- [ ] Documentou processo de instalação (README)
- [ ] Configurou CI/CD integration (Desafio Adicional)
- [ ] Criou estratégia de remediação para projeto legado
- [ ] Otimizou performance do scan

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Habilidade Técnica**: Consegue instalar e configurar ferramenta SAST?
2. **Pensamento Crítico**: Distingue True Positive de False Positive?
3. **Priorização por Risco**: Prioriza por contexto ou apenas por CVSS?
4. **Comunicação**: Documentação é clara e acionável para devs?

### Erros Comuns

**Erro 1: "Não consegui instalar SonarQube (Docker não funciona)"**
- **Causa**: Docker não instalado ou configurado
- **Orientação**: "Verifique se Docker está instalado (`docker --version`). Se não tiver, instale via instruções oficiais. Alternativamente, use SonarQube Cloud (https://sonarcloud.io) temporariamente."

**Erro 2: "Scan executou mas não encontrou nada"**
- **Causa**: Projeto sem código vulnerável OU configuração incorreta
- **Orientação**: "Verifique se `sonar.sources` está apontando para diretório correto. Se projeto realmente não tem vulnerabilidades, use projeto de exemplo (WebGoat, Juice Shop) ou adicione código vulnerável de propósito para praticar."

**Erro 3: "Listou 50+ vulnerabilidades sem análise"**
- **Causa**: Apenas exportou relatório sem análise crítica
- **Orientação**: "Você listou as vulnerabilidades, mas faltou ANÁLISE. Selecione top 3-5 mais críticas e responda: 1) É TRUE ou FALSE POSITIVE? 2) Qual o RISCO REAL (considerando contexto)? 3) Como CORRIGIR? 4) Qual a PRIORIDADE? Refaça focando em qualidade, não quantidade."

**Erro 4: "Priorizou tudo como P0 (IMEDIATO)"**
- **Causa**: Não considerou contexto, priorizou apenas por CVSS
- **Orientação**: "P0 deve ser reservado para vulnerabilidades CRÍTICAS em PRODUÇÃO com DADOS SENSÍVEIS. Re-priorize considerando: 1) Código está em produção? 2) Endpoint é público? 3) Dados sensíveis são afetados? 4) Facilidade de exploração? Use matriz de risco."

**Erro 5: "Marcou tudo como FALSE POSITIVE sem evidências"**
- **Causa**: Não validou manualmente, assumiu que SAST está errado
- **Orientação**: "Você precisa PROVAR que é FALSE POSITIVE. Para cada um: 1) Reproduza manualmente (tente explorar), 2) Mostre evidências (screenshots, logs), 3) Explique POR QUÊ não é vulnerável. Sem evidências = não é confiável."

**Erro 6: "Token exposto no git"**
- **Causa**: Commitou token sem proteger
- **Orientação**: "⚠️ SEGURANÇA! Você expôs token no repositório git. Isso é um risco de segurança sério. AÇÕES: 1) Revogue token imediatamente no SonarQube, 2) Remova do histórico do git (git filter-branch), 3) Adicione `.env` no `.gitignore`, 4) Use variáveis de ambiente. Refaça exercício aplicando práticas seguras."

### Dicas para Feedback Construtivo

**Para alunos com domínio completo:**
> "Excelente trabalho! Você demonstrou proficiência técnica (instalação, configuração, scan) e pensamento crítico (distinguiu TRUE de FALSE POSITIVES, priorizou por contexto). Sua análise está no nível de um QA Security pleno. Próximo desafio: configure Quality Gate rigoroso e integre SonarQube no CI/CD (Exercício 2.1.3)."

**Para alunos com dificuldades intermediárias:**
> "Boa execução técnica! Você conseguiu instalar e executar scan com sucesso. Para melhorar: aprofunde análise de TRUE vs FALSE POSITIVES (valide manualmente tentando explorar) e re-priorize considerando contexto de negócio. Revise seção 'Priorização de Findings' da Aula 2.1."

**Para alunos que travaram:**
> "Vejo que você enfrentou dificuldades. Vamos simplificar: 1) Use Docker Desktop (interface gráfica) se CLI é difícil, 2) Teste com projeto menor (< 500 linhas), 3) Siga documentação oficial passo a passo: https://docs.sonarqube.org/latest/try-out-sonarqube/. Após conseguir scan básico, agende monitoria para tirar dúvidas."

### Contexto Pedagógico

**Por que este exercício é fundamental:**

1. **Habilidade Base**: Configuração de ferramentas SAST é competência essencial para QA Security
2. **Hands-on Real**: Simula tarefa real de primeiro dia em projeto (setup de ferramentas)
3. **Pensamento Crítico**: Desenvolve capacidade de analisar findings, não apenas aceitar
4. **Priorização**: Ensina a priorizar por risco real (não apenas scores)
5. **Base para Automação**: Pré-requisito para integração CI/CD (Exercício 2.1.3)

**Conexão com o Curso:**
- **Pré-requisito**: Aula 2.1 (SAST: Static Application Security Testing)
- **Aplica conceitos**: SAST, CVSS, True/False Positives, Quality Gates
- **Prepara para**: Exercício 2.1.3 (SAST no CI/CD), Exercício 2.1.4 (Validar Findings)
- **Integra com**: Aula 2.2 (DAST), Aula 2.4 (Automação)

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Exemplar (Nível Avançado)

```markdown
## Relatório de Análise SAST - Projeto Open Banking (Hipotético)

### Resumo Executivo
- **Projeto**: API de Open Banking (Node.js + Express)
- **Linhas de código**: 3.245
- **Data do scan**: 2026-01-24
- **Tempo de scan**: 4m 32s

### Resultados Gerais
- **Vulnerabilities**: 12 (2 Critical, 5 High, 4 Medium, 1 Low)
- **Security Hotspots**: 8 (3 High, 5 Medium)
- **Bugs**: 23
- **Code Smells**: 87

### Top 5 Vulnerabilidades Priorizadas

#### 1. SQL Injection em TransactionController (P0 - IMEDIATO)
- **Arquivo**: `src/controllers/TransactionController.js:156`
- **Severidade**: CRITICAL (CVSS 9.8)
- **Status**: ✅ TRUE POSITIVE (validado manualmente)

**Código Vulnerável:**
```javascript
const query = `SELECT * FROM transactions WHERE user_id = '${userId}'`;
const result = await db.query(query);
```

**Validação Manual:**
```bash
# Teste com payload malicioso
curl -X GET 'http://localhost:3000/api/transactions?userId=1%27%20OR%20%271%27=%271'
# Resultado: Retornou TODAS as transações do banco
```

**Risco Real:**
- Exploração: Trivial (apenas modificar query string)
- Impacto: Exposição de dados financeiros de TODOS os clientes
- Compliance: Viola PCI-DSS Requirement 6.5.1
- Contexto: Endpoint PÚBLICO, código em PRODUÇÃO

**Correção Aplicada:**
```javascript
const query = 'SELECT * FROM transactions WHERE user_id = $1';
const result = await db.query(query, [userId]);
```

**Validação da Correção:**
```bash
curl -X GET 'http://localhost:3000/api/transactions?userId=1%27%20OR%20%271%27=%271'
# Resultado após correção: 400 Bad Request (payload bloqueado)
```

**Prioridade**: P0 - Hotfix IMEDIATO (< 24h)

---

#### 2. Hardcoded API Key em ConfigService (P1 - URGENTE)
- **Arquivo**: `src/services/ConfigService.js:12`
- **Severidade**: HIGH (CVSS 7.5)
- **Status**: ✅ TRUE POSITIVE

**Código Vulnerável:**
```javascript
const API_KEY = "sk_live_1234567890abcdef";  // Hardcoded secret
```

**Risco Real:**
- Exploração: Fácil (key exposta no repositório git)
- Impacto: Acesso não autorizado a API de pagamentos (Stripe)
- Compliance: Viola PCI-DSS Requirement 3.4
- Contexto: Código commitado em repositório PÚBLICO no GitHub

**Correção Aplicada:**
```javascript
const API_KEY = process.env.STRIPE_API_KEY;
```

**Ações Adicionais:**
- Revogada key antiga no Stripe
- Gerada nova key e armazenada no AWS Secrets Manager
- Adicionada `.env` no `.gitignore`
- Limpado histórico do git (git filter-branch)

**Prioridade**: P1 - URGENTE (< 48h)

---

[... demais vulnerabilidades ...]

### Estratégia de Remediação

| Sprint | Ações | Meta |
|--------|-------|------|
| **Sprint Atual** | Corrigir P0 e P1 (SQLi + Hardcoded Key) | 0 Critical |
| **Próximo Sprint** | Corrigir P2 (5 High vulnerabilities) | 0 High |
| **Mês 2** | Triagem de Security Hotspots | Reduzir 50% |
| **Mês 3** | Quality Gate rigoroso (0 Critical + 0 High) | Manter qualidade |

### Quality Gate Configurado
```yaml
Conditions:
  - New Critical Vulnerabilities: 0
  - New High Vulnerabilities: max 2
  - Security Rating: A ou B
  - Security Hotspots Review: 100% (todas revisadas)
```

### Lições Aprendidas
1. **SAST encontra vulnerabilidades reais**: 7 de 12 eram TRUE POSITIVES (58%)
2. **Contexto é crucial**: CVSS 9.8 em endpoint de teste = P3, em produção = P0
3. **Validação manual é essencial**: 5 FALSE POSITIVES foram identificados
4. **Automação economiza tempo**: Scan automatizado (4min) vs revisão manual (horas)
```

**Por que é exemplar:**
- ✅ Análise técnica profunda com validação manual
- ✅ Considera contexto de negócio (Open Banking, PCI-DSS)
- ✅ Priorização justificada com matriz de risco
- ✅ Correções testadas e validadas
- ✅ Estratégia de remediação de longo prazo
- ✅ Quality Gate configurado adequadamente
- ✅ Documentação profissional (formato de relatório real)

---

### Exemplo 2: Resposta Adequada (Nível Intermediário)

```markdown
## Análise SAST - Projeto Node.js API

### Configuração
- Instalei SonarQube via Docker (`docker run -d -p 9000:9000 sonarqube`)
- Criei projeto "minha-api"
- Gerei token e executei scan

### Resultados
Total de 8 vulnerabilidades encontradas:
- 1 Critical
- 3 High
- 4 Medium

### Top 3 Vulnerabilidades

#### 1. SQL Injection (Critical)
- **Arquivo**: `src/user.js` linha 45
- **Problema**: Query usa concatenação de strings
- **Correção**: Usar prepared statements
- **Prioridade**: P0 (crítico)

#### 2. Hardcoded Password (High)
- **Arquivo**: `src/config.js` linha 12
- **Problema**: Senha hardcoded no código
- **Correção**: Mover para variável de ambiente
- **Prioridade**: P1 (urgente)

#### 3. XSS Reflected (High)
- **Arquivo**: `src/search.js` linha 67
- **Problema**: Input não sanitizado
- **Correção**: Sanitizar entrada com DOMPurify
- **Prioridade**: P2 (importante)
```

**Por que é adequado:**
- ✅ Completou instalação e scan com sucesso
- ✅ Identificou vulnerabilidades corretamente
- ✅ Propôs correções técnicas válidas
- ✅ Priorizou adequadamente
- ⚠️ Faltou: validação manual (TRUE vs FALSE POSITIVE)
- ⚠️ Faltou: contexto de negócio e impacto real
- ⚠️ Faltou: evidências visuais (screenshots)

**Feedback sugerido:**
> "Boa execução! Você configurou SonarQube e identificou vulnerabilidades corretamente. Para elevar o nível: 1) Valide manualmente se são TRUE ou FALSE POSITIVES (tente explorar), 2) Adicione contexto (código está em produção? Dados sensíveis?), 3) Inclua screenshots do dashboard. Sua análise está no caminho certo!"

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
