---
exercise_id: lesson-2-1-exercise-1-sonarqube-setup
title: "Exercício 2.1.1: Configurar SonarQube em Projeto Próprio"
lesson_id: lesson-2-1
module: module-2
difficulty: "Básico"
last_updated: 2025-01-15
---

# Exercício 2.1.1: Configurar SonarQube em Projeto Próprio

## 📋 Enunciado Completo

Este exercício tem como objetivo **configurar SonarQube do zero** em um projeto existente e executar sua primeira análise SAST.

### Tarefa Principal

1. Instalar SonarQube usando Docker
2. Configurar projeto no SonarQube
3. Executar primeiro scan
4. Analisar resultados e identificar top 5 vulnerabilidades
5. Criar relatório com análise dos findings

---

## ✅ Soluções Detalhadas

### Passo 1: Preparar Ambiente

**Solução Esperada:**
- Docker instalado e funcionando (`docker --version`)
- Projeto escolhido para análise (próprio ou exemplo)
- Ambiente preparado para análise

**Verificações Comuns:**
- Docker Desktop rodando (macOS/Windows)
- Memória suficiente (SonarQube precisa mínimo 2GB)
- Projeto acessível localmente

**Problemas Comuns:**
- Docker não instalado → Instalar Docker Desktop
- Porta 9000 ocupada → Mudar porta ou liberar porta
- Memória insuficiente → Aumentar memória do Docker

### Passo 2: Instalar e Configurar SonarQube

**Solução Esperada:**

**2.1. Executar SonarQube via Docker**
```bash
docker run -d --name sonarqube \
  -p 9000:9000 \
  -v sonarqube_data:/opt/sonarqube/data \
  -v sonarqube_extensions:/opt/sonarqube/extensions \
  -v sonarqube_logs:/opt/sonarqube/logs \
  sonarqube:lts-community
```

**Verificações:**
- Container rodando: `docker ps | grep sonarqube`
- Logs sem erros: `docker logs sonarqube`
- Acessível: `curl http://localhost:9000` (retorna HTML)

**2.2. Primeira Acesso**
- URL: `http://localhost:9000`
- Login: `admin` / `admin`
- Trocar senha na primeira vez
- Dashboard deve mostrar "SonarQube is up and running"

**Solução Alternativa (Se Docker Não Funciona):**
- Instalar SonarQube manualmente (mais complexo)
- Usar SonarCloud (versão SaaS - requer conta)

### Passo 3: Instalar SonarScanner

**Solução Esperada (Opção A - Homebrew):**
```bash
brew install sonar-scanner
sonar-scanner --version
```

**Solução Alternativa (Opção B - Docker):**
```bash
docker pull sonarsource/sonar-scanner-cli
# Usar em comando docker run (mostrado no passo 6)
```

**Problemas Comuns:**
- Comando não encontrado → Adicionar ao PATH
- Versão incompatível → Atualizar SonarScanner

### Passo 4: Criar Projeto no SonarQube

**Solução Esperada:**

**4.1. Criar Projeto**
1. Ir em "Create Project" ou "+"
2. Escolher "Manually"
3. Project key: `meu-projeto-sast` (ou nome único)
4. Display name: `Meu Projeto SAST`
5. Clicar em "Set Up"

**Importante:**
- Project key deve ser único no SonarQube
- Usar nomes descritivos para Display name

**4.2. Gerar Token**
1. Escolher "Generate a token"
2. Token name: `meu-token-local` (ou descritivo)
3. Copiar token **imediatamente** (não aparece novamente)
4. Guardar token seguro

**Exemplo de Token:**
```
squ_1234567890abcdef1234567890abcdef12345678
```

**Problemas Comuns:**
- Token não funciona → Verificar permissões (deve ter "Execute Analysis")
- Token expirado → Gerar novo token

### Passo 5: Configurar Projeto Local

**Solução Esperada:**

**5.1. Arquivo `sonar-project.properties` (Exemplo para Python):**
```properties
# sonar-project.properties
sonar.projectKey=meu-projeto-sast
sonar.projectName=Meu Projeto SAST
sonar.projectVersion=1.0

# Código fonte
sonar.sources=src
sonar.tests=tests
sonar.sourceEncoding=UTF-8

# Linguagem Python
sonar.language=py

# Exclusões
sonar.exclusions=**/venv/**,**/__pycache__/**,**/*.pyc

# Regras de segurança
sonar.security.hotspots=high,medium
```

**5.2. Variáveis de Ambiente:**
```bash
export SONAR_TOKEN="squ_1234567890abcdef1234567890abcdef12345678"
export SONAR_HOST_URL="http://localhost:9000"
```

**Variações por Linguagem:**

**JavaScript/TypeScript:**
```properties
sonar.language=js
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.exclusions=**/node_modules/**,**/dist/**,**/build/**
```

**Java:**
```properties
sonar.language=java
sonar.java.binaries=target/classes
sonar.exclusions=**/target/**
```

**Configurações Importantes:**
- `sonar.sources`: Diretório do código fonte (não incluir node_modules, venv, etc.)
- `sonar.exclusions`: Padrões de arquivos a ignorar (reduz tempo de scan)
- `sonar.projectKey`: Deve ser igual ao criado no SonarQube

### Passo 6: Executar Primeiro Scan

**Solução Esperada (SonarScanner Local):**
```bash
cd /caminho/para/seu/projeto

sonar-scanner \
  -Dsonar.projectKey=meu-projeto-sast \
  -Dsonar.sources=src \
  -Dsonar.host.url=$SONAR_HOST_URL \
  -Dsonar.login=$SONAR_TOKEN
```

**Solução Alternativa (Docker):**
```bash
docker run --rm \
  -v $(pwd):/usr/src \
  -e SONAR_TOKEN=$SONAR_TOKEN \
  -e SONAR_HOST_URL=$SONAR_HOST_URL \
  sonarsource/sonar-scanner-cli \
  -Dsonar.projectKey=meu-projeto-sast \
  -Dsonar.sources=src \
  -Dsonar.host.url=$SONAR_HOST_URL \
  -Dsonar.login=$SONAR_TOKEN
```

**Saída Esperada:**
```
INFO: Scanner configuration file: /opt/sonar-scanner/conf/sonar-scanner.properties
INFO: Project root configuration file: /usr/src/sonar-project.properties
INFO: SonarScanner 4.x.x
INFO: ...
INFO: EXECUTION SUCCESS
```

**Tempo de Execução:**
- Projeto pequeno (< 1k LOC): 1-3 minutos
- Projeto médio (1k-10k LOC): 5-15 minutos
- Projeto grande (> 10k LOC): 15-60 minutos

**Problemas Comuns:**
- `ERROR: Invalid token` → Verificar token e permissões
- `ERROR: Project key not found` → Criar projeto primeiro no SonarQube
- Scan muito lento → Verificar exclusões e tamanho do projeto

### Passo 7: Analisar Resultados

**Solução Esperada:**

**7.1. Dashboard Principal**
- Acessar: `http://localhost:9000` → Projects → Seu projeto
- Visualizar métricas:
  - Vulnerabilities (Critical, High, Medium, Low)
  - Security Hotspots
  - Bugs
  - Code Smells
  - Security Rating (A-E)

**7.2. Explorar Vulnerabilities**
1. Clicar em "Vulnerabilities"
2. Filtrar por severidade (Critical primeiro)
3. Clicar em cada vulnerabilidade para ver detalhes:
   - Arquivo e linha
   - Descrição do problema
   - Exemplo de correção
   - CWE e OWASP Top 10

**7.3. Explorar Security Hotspots**
- Hotspots são potenciais problemas (menos críticos que vulnerabilities)
- Revisar cada hotspot manualmente
- Marcar como "Safe" ou "Vulnerable" após análise

**Interpretação dos Resultados:**

**Vulnerabilities (Vulnerabilidades Confirmadas):**
- Critical/High: Corrigir urgentemente
- Medium: Corrigir quando possível
- Low: Priorizar baixo

**Security Hotspots (Pontos de Atenção):**
- Revisar manualmente
- Podem ser false positives
- Documentar decisão (Safe/Vulnerable)

**Bugs e Code Smells:**
- Não são vulnerabilidades de segurança
- Mas indicam problemas de qualidade
- Endereçar gradualmente

### Passo 8: Top 5 Vulnerabilidades

**Solução Esperada - Estrutura do Relatório:**

```markdown
## Top 5 Vulnerabilidades Identificadas

### Vulnerabilidade #1: SQL Injection em UserService.getUser()
- **Severidade SAST**: Critical 🔴
- **CWE**: CWE-89 (SQL Injection)
- **OWASP Top 10**: A03:2021 – Injection
- **Arquivo**: `src/services/UserService.java`
- **Linha**: 45

**Descrição:**
O código concatena input do usuário diretamente em query SQL sem sanitização, permitindo SQL Injection.

**Código Flagado:**
```java
@GetMapping("/users/{id}")
public User getUser(@PathVariable String id) {
    String query = "SELECT * FROM users WHERE id = " + id;  // ❌ Vulnerável
    return db.executeQuery(query);
}
```

**Risco:**
- Exploitability: ALTA - Pode ser explorado facilmente via API
- Impacto: ALTO - Pode expor dados de todos os usuários
- Contexto: Código em produção, dados sensíveis

**Correção Sugerida:**
```java
@GetMapping("/users/{id}")
public User getUser(@PathVariable String id) {
    // ✅ Validação de entrada
    if (!isValidUserId(id)) {
        throw new IllegalArgumentException("Invalid user ID");
    }
    
    // ✅ Prepared Statement
    String query = "SELECT * FROM users WHERE id = ?";
    return db.executeQuery(query, id);  // Parâmetroizado
}
```

**Priorização:** P1 - Corrigir IMEDIATAMENTE
- Critical + Em produção + Dados sensíveis
- Violação PCI-DSS/LGPD se dados pessoais envolvidos

**Validação:**
- ✅ True Positive (vulnerabilidade real confirmada)
- ✅ Código está em produção
- ✅ Dados sensíveis afetados (nomes, emails)

---

### Vulnerabilidade #2: Hardcoded Secret em ConfigService
- **Severidade SAST**: Critical 🔴
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **OWASP Top 10**: A07:2021 – Identification and Authentication Failures
- **Arquivo**: `src/config/ConfigService.py`
- **Linha**: 12

[Repetir estrutura similar...]

---

[Continuar para #3, #4, #5...]
```

**Critérios para Seleção do Top 5:**
1. Severidade (Critical/High primeiro)
2. Código em produção
3. Dados sensíveis afetados
4. Exploitability alta
5. Compliance violado (PCI-DSS, LGPD)

### Passo 9: Quality Gate (Opcional mas Recomendado)

**Solução Esperada:**

**9.1. Configurar Quality Gate Básico**
1. Ir em "Quality Gates" → "Sonar way" (ou criar novo)
2. Adicionar condições:
   - Security Rating: A ou B
   - New Vulnerabilities: 0 Critical
   - New Vulnerabilities: Máximo 5 High
   - Security Hotspots: 0 Critical/High (novos)

**9.2. Estratégia Gradual (Recomendada):**

**Semana 1-2 (Muito Permissivo):**
- Security Rating: Qualquer
- New Vulnerabilities: 0 Critical apenas

**Semana 3-4 (Médio):**
- Security Rating: A ou B
- New Vulnerabilities: 0 Critical, máx 10 High

**Mês 2+ (Rigoroso):**
- Security Rating: A ou B
- New Vulnerabilities: 0 Critical, máx 5 High
- Security Hotspots: 0 Critical/High novas

**Por Que Gradual?**
- Não bloqueia time desde o início
- Permite adaptação gradual
- Reduz resistência à ferramenta

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Configuração Técnica:**
- [ ] SonarQube instalado e rodando corretamente
- [ ] Projeto criado no SonarQube com configuração adequada
- [ ] Token gerado e configurado corretamente
- [ ] Arquivo `sonar-project.properties` criado com configurações apropriadas
- [ ] Primeiro scan executado com sucesso (sem erros fatais)

**Análise de Resultados:**
- [ ] Dashboard acessado e explorado (entendeu métricas principais)
- [ ] Top 5 vulnerabilidades identificadas e documentadas

### ⭐ Importantes (Recomendados para Resposta Completa)

**Relatório de Análise:**
- [ ] Relatório criado com estrutura clara e organizada
- [ ] Cada vulnerabilidade documentada com:
  - Severidade, CWE, OWASP Top 10
  - Código flagado (exemplo concreto)
  - Código corrigido (solução segura)
  - Análise de risco (exploitability, impacto, contexto)

**Priorização:**
- [ ] Priorização realizada considerando:
  - Severidade SAST vs Risco Real
  - Contexto (produção vs desenvolvimento)
  - Dados sensíveis afetados
  - Compliance aplicável (LGPD, PCI-DSS, etc.)

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Quality Gate:**
- [ ] Quality Gate configurado e testado
- [ ] Estratégia gradual documentada (baseline → permissivo → rigoroso)

**Análise Avançada:**
- [ ] Identifica false positives e documenta razão claramente
- [ ] Considera contexto de negócio específico (financeiro, educacional, etc.)
- [ ] Propõe estratégia de redução gradual de vulnerabilities com metas

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Capacidade Técnica**: Aluno consegue configurar SonarQube do zero?
2. **Interpretação de Resultados**: Aluno entende os findings?
3. **Priorização**: Aluno prioriza por risco real ou apenas severidade SAST?
4. **Análise Crítica**: Aluno diferencia true positives de false positives?

### Erros Comuns

1. **Erro: Configuração Incorreta do sonar-project.properties**
   - **Situação**: Aluno configura `sonar.sources` incluindo node_modules/venv
   - **Feedback**: "Boa configuração inicial! Note que incluir `node_modules/` ou `venv/` no `sonar.sources` vai tornar o scan muito lento. Esses diretórios devem estar em `sonar.exclusions` porque contêm código de terceiros que você não controla."

2. **Erro: Priorização Apenas por Severidade SAST**
   - **Situação**: Aluno prioriza Critical primeiro sem considerar contexto
   - **Feedback**: "Excelente identificação das vulnerabilidades! Lembre-se de que nem toda Critical é P1 se o código não está em produção. Considere: código em produção? dados sensíveis? fácil explorar? Isso ajuda a priorizar por risco real."

3. **Erro: Não Configurar Quality Gate**
   - **Situação**: Aluno não configura Quality Gate
   - **Feedback**: "Ótimo trabalho configurando SonarQube! Para usar em produção, recomendamos configurar Quality Gate para bloquear merge quando encontrar Critical vulnerabilities. Isso previne que código vulnerável chegue à branch principal."

4. **Erro: Não Identificar False Positives**
   - **Situação**: Aluno assume que tudo que SAST reporta é vulnerabilidade real
   - **Feedback**: "Boa análise! SAST às vezes reporta false positives. Sempre valide cada Critical/High manualmente. Por exemplo, hardcoded password em teste unitário geralmente é false positive porque não é usado em produção."

### Dicas para Feedback

- ✅ **Reconheça**: Configuração técnica correta, análise detalhada, relatórios bem estruturados
- ❌ **Corrija**: Priorização incorreta, não considerar contexto, assumir que tudo é vulnerabilidade real
- 💡 **Incentive**: Configurar Quality Gate, identificar false positives, considerar contexto de negócio

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Base Prática**: Configurar SonarQube é habilidade básica essencial para QA de segurança
2. **Interpretação de Resultados**: Ensina a interpretar findings SAST, não apenas ler relatórios
3. **Priorização Real**: Desenvolve capacidade de priorizar por risco real, não apenas severidade técnica
4. **Análise Crítica**: Ensina a validar findings e diferenciar true/false positives

**Conexão com o Curso:**
- Aula 2.1: SAST (teoria) → Este exercício (prática)
- Pré-requisito para: Exercício 2.1.3 (Integrar SAST no CI/CD)
- Base para: Módulo 3 (Aplicar SAST em contextos específicos)

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Relatório de Top 5 Vulnerabilities:**

```markdown
## Vulnerabilidade #1: SQL Injection - P1 IMEDIATO

**Severidade**: Critical 🔴  
**Arquivo**: `src/api/users.py:45`  
**CWE**: CWE-89  
**OWASP**: A03:2021 – Injection  

**Código Vulnerável:**
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ SQL Injection
    return db.execute(query)
```

**Análise de Risco:**
- Exploitability: ALTA - Pode ser explorado via API
- Impacto: CRÍTICO - Pode acessar dados de todos os usuários
- Contexto: Código em produção, endpoint público, dados sensíveis (LGPD)

**Correção:**
```python
def get_user(user_id):
    if not user_id.isdigit():  # ✅ Validação
        raise ValueError("Invalid user ID")
    query = "SELECT * FROM users WHERE id = %s"  # ✅ Prepared statement
    return db.execute(query, (user_id,))
```

**Justificativa P1:**
- Critical + Em produção + Dados sensíveis + Fácil explorar = P1 IMEDIATO
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
- Severidade: Critical
- Arquivo: src/api/users.py:45
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

### Desafio 1: Projeto com 500+ Vulnerabilities

**Solução Esperada:**

**1. Criar Baseline:**
- Acessar SonarQube → Projeto → Settings → General
- Criar novo baseline: "Baseline 2024-01-15"
- Marcar todas as vulnerabilities existentes como baseline

**2. Configurar Quality Gate Gradual:**
```yaml
# Semana 1-2: Permissivo
Quality Gate:
  - Security Rating: Qualquer
  - New Vulnerabilities: 0 Critical apenas (após baseline)

# Mês 1: Médio
Quality Gate:
  - Security Rating: A, B, ou C
  - New Vulnerabilities: 0 Critical, máx 10 High (novas)

# Mês 3+: Rigoroso
Quality Gate:
  - Security Rating: A ou B
  - New Vulnerabilities: 0 Critical, máx 5 High (novas)
  - Redução de 20% de vulnerabilities antigas por trimestre
```

**3. Estratégia de Redução:**
- Trimestre 1: Reduzir 50 Critical → 30 Critical (meta: -40%)
- Trimestre 2: Reduzir 30 Critical → 15 Critical (meta: -50%)
- Trimestre 3: Reduzir 15 Critical → 5 Critical (meta: -67%)
- Trimestre 4: Eliminar todas Critical (meta: 100%)

**4. Template de Triagem:**
```markdown
## Nova Vulnerability: [ID]

- Severidade: Critical/High/Medium/Low
- Baseline? Sim/Em baseline / Não/Novo código
- Ação: Corrigir / Aceitar Risco / False Positive
- Responsável: [Nome]
- Prazo: [Data]
```

### Desafio 2: Otimização de Performance

**Solução Esperada:**

**Causas Comuns de Scan Lento:**
1. Projeto muito grande (> 100k LOC)
2. Muitas linguagens analisadas
3. Incluindo node_modules/vendor/venv
4. Quality Gate muito complexo
5. Regras muito complexas ativas

**Otimizações:**

**1. Exclusões Agressivas:**
```properties
# sonar-project.properties
sonar.exclusions=**/node_modules/**,**/vendor/**,**/venv/**,**/__pycache__/**,**/*.min.js,**/*.bundle.js,**/dist/**,**/build/**
```

**2. Analisar Apenas Código Fonte:**
```properties
sonar.sources=src/main  # Não src/
sonar.tests=tests       # Separar testes
sonar.test.inclusions=**/*Test.*  # Apenas arquivos de teste
```

**3. Scan Diferencial (CI/CD):**
```bash
# Analisar apenas mudanças no PR
sonar-scanner \
  -Dsonar.pullrequest.key=$PR_NUMBER \
  -Dsonar.pullrequest.branch=$PR_BRANCH \
  -Dsonar.pullrequest.base=$BASE_BRANCH
```

**4. Modo Preview (Rápido):**
```bash
sonar-scanner -Dsonar.analysis.mode=preview
```

**Métricas de Sucesso:**
- Antes: 25 minutos
- Depois: < 5 minutos (meta alcançada)
- Melhoria: 80% de redução

### Desafio 3: Integração Sem Quebrar Pipeline

**Solução Esperada:**

**1. Análise de Pipeline Existente:**
- Identificar jobs/stages existentes
- Identificar pontos de integração
- Verificar dependências entre jobs

**2. Integração Não-Bloqueante Inicial:**
```yaml
# .github/workflows/ci.yml
jobs:
  build:
    # ... jobs existentes ...
  
  sonarqube:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
    
    # Não bloqueia outros jobs inicialmente
    continue-on-error: true
```

**3. Quality Gate Gradual:**
```yaml
# Semana 1-2: Apenas reporta
- name: SonarQube Scan
  continue-on-error: true  # Não falha pipeline

# Semana 3-4: Bloqueia apenas Critical
- name: SonarQube Scan
  continue-on-error: false
  # Quality Gate: 0 Critical apenas

# Mês 2+: Bloqueia Critical + High
- name: SonarQube Scan
  continue-on-error: false
  # Quality Gate: 0 Critical, máx 5 High
```

**4. Plano de Evolução:**
```markdown
## Evolução do Quality Gate

### Fase 1 (Semanas 1-2): Monitoramento
- SonarQube roda mas não bloqueia
- Time se acostuma com findings
- Coleta métricas de baseline

### Fase 2 (Semanas 3-4): Bloqueio Crítico
- Bloqueia apenas Critical novas
- Comunica time sobre bloqueio
- Documenta processo de triagem

### Fase 3 (Mês 2): Bloqueio High
- Bloqueia Critical + High novas
- Time já acostumado
- Redução visível de vulnerabilities

### Fase 4 (Mês 3+): Rigoroso
- Quality Gate completo ativo
- Redução contínua de vulnerabilities
- Cultura de segurança estabelecida
```

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
