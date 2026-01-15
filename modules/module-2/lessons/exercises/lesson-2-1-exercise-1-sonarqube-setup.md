---
layout: exercise
title: "Exercício 2.1.1: Configurar SonarQube em Projeto Próprio"
slug: "sonarqube-setup"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Básico"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-1-exercise-1-sonarqube-setup/
lesson_url: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
---

## Objetivo

Este exercício tem como objetivo **configurar SonarQube do zero** em um projeto existente e executar sua primeira análise SAST.

Ao completar este exercício, você será capaz de:

- Instalar e configurar SonarQube usando Docker
- Configurar projeto no SonarQube
- Executar primeiro scan de análise estática
- Interpretar resultados do SonarQube
- Identificar e priorizar top 5 vulnerabilidades encontradas

---

## Descrição

Você vai configurar SonarQube Community Edition do zero, conectar a um projeto existente (seu próprio projeto ou um projeto de exemplo), executar uma análise completa e interpretar os resultados.

### Contexto

Como QA de segurança, é fundamental saber configurar e usar ferramentas SAST. SonarQube é uma das ferramentas mais populares e este exercício desenvolve essa habilidade prática.

### Tarefa Principal

1. Instalar SonarQube usando Docker
2. Configurar projeto no SonarQube
3. Executar primeiro scan
4. Analisar resultados e identificar top 5 vulnerabilidades
5. Criar relatório com análise dos findings

---

## Requisitos

### Passo 1: Preparar Ambiente

**1.1. Instalar Docker (se não tiver)**

```bash
# macOS
brew install docker

# Ou baixar Docker Desktop: https://www.docker.com/products/docker-desktop

# Verificar instalação
docker --version
```

**1.2. Preparar Projeto para Análise**

Escolha um dos seguintes:

- **Opção A**: Usar projeto próprio (preferido)
  - Escolha um projeto Python, JavaScript, Java, ou C# que você já trabalha
  - Ou crie um projeto simples de exemplo

- **Opção B**: Usar projeto de exemplo
  ```bash
  # Clonar projeto vulnerável de exemplo (OWASP WebGoat ou Juice Shop)
  git clone https://github.com/OWASP/WebGoat.git
  cd WebGoat
  ```

### Passo 2: Instalar e Configurar SonarQube

**2.1. Executar SonarQube via Docker**

```bash
# Baixar e executar SonarQube Community Edition
docker run -d --name sonarqube \
  -p 9000:9000 \
  -v sonarqube_data:/opt/sonarqube/data \
  -v sonarqube_extensions:/opt/sonarqube/extensions \
  -v sonarqube_logs:/opt/sonarqube/logs \
  sonarqube:lts-community

# Verificar se está rodando
docker ps | grep sonarqube

# Aguardar SonarQube inicializar (pode levar 1-2 minutos)
# Verificar logs
docker logs -f sonarqube
```

**2.2. Acessar SonarQube**

- Abrir navegador em: `http://localhost:9000`
- Login padrão: `admin` / `admin`
- **Importante**: Na primeira vez, será solicitado trocar a senha
  - Nova senha: `admin123` (ou sua escolha segura)
  - Guarde essa senha, você vai precisar!

**2.3. Verificar Status**

- Dashboard deve mostrar: "SonarQube is up and running" ✅

### Passo 3: Instalar SonarScanner

**3.1. Instalar SonarScanner (escolha uma opção)**

**Opção A: Via Homebrew (macOS)**
```bash
brew install sonar-scanner
```

**Opção B: Via Docker (recomendado)**
```bash
docker pull sonarsource/sonar-scanner-cli
```

**Opção C: Download Manual**
- Baixar: https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/
- Extrair e adicionar ao PATH

**3.2. Verificar Instalação**

```bash
sonar-scanner --version
# Deve mostrar versão do scanner
```

### Passo 4: Criar Projeto no SonarQube

**4.1. Criar Projeto Manualmente**

1. No SonarQube (`http://localhost:9000`):
   - Clicar em "Create Project" ou "+"
   - Escolher "Manually"
   - Project key: `meu-projeto-sast` (ou nome do seu projeto)
   - Display name: `Meu Projeto SAST` (ou nome descritivo)
   - Clicar em "Set Up"

**4.2. Gerar Token**

1. Na página de setup do projeto:
   - Escolher: "Generate a token"
   - Token name: `meu-token-local`
   - Clicar em "Generate"
   - **Copiar e guardar o token!** (aparece apenas uma vez)
   - Exemplo: `squ_1234567890abcdef1234567890abcdef12345678`

### Passo 5: Configurar Projeto Local

**5.1. Criar Arquivo `sonar-project.properties`**

Criar arquivo na raiz do seu projeto:

```properties
# sonar-project.properties
sonar.projectKey=meu-projeto-sast
sonar.projectName=Meu Projeto SAST
sonar.projectVersion=1.0

# Código fonte
sonar.sources=src
sonar.tests=test
sonar.sourceEncoding=UTF-8

# Linguagem (ajustar conforme seu projeto)
# Para JavaScript/TypeScript:
sonar.language=js
sonar.javascript.lcov.reportPaths=coverage/lcov.info

# Para Python:
sonar.language=py

# Para Java:
sonar.language=java

# Exclusões (não analisar)
sonar.exclusions=**/node_modules/**,**/dist/**,**/build/**,**/*.spec.ts

# Regras de segurança
sonar.security.hotspots=high,medium
```

**5.2. Configurar Variáveis de Ambiente**

```bash
# Definir variáveis para o scan
export SONAR_TOKEN="seu_token_aqui"  # Token gerado no passo 4.2
export SONAR_HOST_URL="http://localhost:9000"
```

**Ou criar arquivo `.env`** (não commitar no git):

```bash
# .env
SONAR_TOKEN=squ_1234567890abcdef1234567890abcdef12345678
SONAR_HOST_URL=http://localhost:9000
```

### Passo 6: Executar Primeiro Scan

**6.1. Executar SonarScanner**

```bash
# No diretório raiz do projeto
cd /caminho/para/seu/projeto

# Se usar SonarScanner local:
sonar-scanner \
  -Dsonar.projectKey=meu-projeto-sast \
  -Dsonar.sources=src \
  -Dsonar.host.url=$SONAR_HOST_URL \
  -Dsonar.login=$SONAR_TOKEN

# Se usar Docker:
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

**6.2. Aguardar Processamento**

- O scan pode levar alguns minutos dependendo do tamanho do projeto
- Você verá logs do processo no terminal
- Ao final, verá: "EXECUTION SUCCESS"

### Passo 7: Analisar Resultados no SonarQube

**7.1. Acessar Projeto no SonarQube**

1. Abrir `http://localhost:9000`
2. Ir em "Projects" → Seu projeto
3. Dashboard mostra resultados da análise

**7.2. Explorar Findings**

1. **Vulnerabilities (Vulnerabilidades de Segurança)**:
   - Clicar em "Vulnerabilities"
   - Ver lista de vulnerabilidades encontradas
   - Filtrar por severidade (Critical, High, Medium, Low)

2. **Security Hotspots**:
   - Clicar em "Security Hotspots"
   - Ver potenciais problemas de segurança
   - Revisar cada hotspot

3. **Bugs e Code Smells**:
   - Explorar outras métricas de qualidade
   - Entender a diferença entre bugs e code smells

### Passo 8: Identificar Top 5 Vulnerabilidades

**8.1. Criar Relatório de Análise**

Para cada vulnerabilidade identificada, documente:

```markdown
## Vulnerabilidade #1: [Nome/Tipo]

### Detalhes
- **Severidade**: Critical / High / Medium / Low
- **Arquivo**: `caminho/para/arquivo`
- **Linha**: 45
- **CWE**: CWE-XX (se disponível)
- **OWASP Top 10**: AXX:2021 – [Categoria]

### Descrição
[Descrição detalhada do problema]

### Código Flagado
```linguagem
[código vulnerável aqui]
```

### Risco
[Qual o risco real? Pode ser explorado? Qual o impacto?]

### Correção Sugerida
```linguagem
[código corrigido aqui]
```

### Priorização
- [ ] P1 - Corrigir IMEDIATAMENTE
- [ ] P2 - Corrigir neste Sprint
- [ ] P3 - Corrigir no próximo Sprint
- [ ] P4 - Backlog

### Validação
- [ ] É True Positive? (vulnerabilidade real)
- [ ] É False Positive? (não é vulnerabilidade real)
- [ ] Código está em produção?
- [ ] Dados sensíveis afetados?
```

**8.2. Priorizar por Risco Real**

Considere:
- Severidade SAST vs Risco Real
- Exploitability (fácil explorar?)
- Impacto (dados sensíveis?)
- Contexto (código em produção?)

### Passo 9: Configurar Quality Gate (Opcional)

**9.1. Configurar Quality Gate Básico**

No SonarQube:
1. Ir em "Quality Gates"
2. Editar "Sonar way" ou criar novo
3. Adicionar condições:
   - Security Rating: A ou B
   - Vulnerabilities: 0 Critical, máximo 5 High
   - Security Hotspots: 0 Critical/High

**9.2. Verificar Quality Gate**

- Re-executar scan
- Verificar se Quality Gate passa ou falha
- Ajustar condições se necessário

---

## Desafios Adicionais (Para QAs Plenos)

Se você já tem experiência básica com SonarQube, teste seus conhecimentos com estes desafios:

### Desafio 1: Projeto com 500+ Vulnerabilities

**Cenário**: Você herdou um projeto legado que tem 523 vulnerabilities (45 Critical, 128 High). O time quer começar a usar SonarQube, mas Quality Gate está bloqueando todo o desenvolvimento.

**Tarefa**:
1. Configure baseline: "Aceitar tudo que existe hoje"
2. Configure Quality Gate que bloqueia apenas novas Critical/High vulnerabilities
3. Crie estratégia de redução gradual (metas por trimestre)
4. Documente processo de triagem para novas vulnerabilities

**Entregáveis**:
- Configuração de Quality Gate ajustada
- Documento com estratégia de redução
- Template de triagem para novas vulnerabilities

### Desafio 2: Otimização de Performance

**Cenário**: O scan está demorando 25 minutos para completar. O time reclama que está muito lento para usar em cada PR.

**Tarefa**:
1. Identifique causas do scan lento (projeto grande? muitas linguagens? regras complexas?)
2. Otimize configuração para reduzir tempo de scan
3. Configure scan diferencial (analisar apenas mudanças) se possível
4. Documente otimizações realizadas

**Entregáveis**:
- Configuração otimizada (antes/depois)
- Tempo de scan reduzido (meta: < 5 minutos)
- Documentação de otimizações

### Desafio 3: Integração Sem Quebrar Pipeline

**Cenário**: Projeto já tem pipeline CI/CD complexo com múltiplas etapas. Você precisa adicionar SonarQube sem quebrar o fluxo existente.

**Tarefa**:
1. Analise pipeline existente (.github/workflows/ ou .gitlab-ci.yml)
2. Integre SonarQube como etapa adicional (não bloqueia inicialmente)
3. Configure Quality Gate que falha apenas Critical
4. Teste integração com PR real
5. Gradualmente aperte Quality Gate após time se acostumar

**Entregáveis**:
- Pipeline atualizado com SonarQube
- Documentação de integração
- Plano de evolução do Quality Gate

---

## Troubleshooting: Problemas Comuns e Soluções

### Problema 1: SonarQube Não Inicia (Docker)

**Sintoma**: `docker ps` mostra container, mas `http://localhost:9000` não responde

**Soluções**:
```bash
# 1. Verificar logs para erros
docker logs sonarqube

# 2. Verificar se porto está disponível
lsof -i :9000  # macOS/Linux
netstat -ano | findstr :9000  # Windows

# 3. Verificar memória (SonarQube precisa mínimo 2GB)
docker stats sonarqube

# 4. Se erro de memória, aumentar limite:
docker run -d --name sonarqube \
  -p 9000:9000 \
  -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
  -v sonarqube_data:/opt/sonarqube/data \
  sonarqube:lts-community

# 5. Reiniciar container
docker restart sonarqube
```

### Problema 2: Scan Falha com "Invalid Token"

**Sintoma**: `ERROR: Error during SonarQube Scanner execution: Invalid token`

**Soluções**:
```bash
# 1. Verificar se token está correto
echo $SONAR_TOKEN  # Deve mostrar token

# 2. Verificar se token não expirou (gerar novo)
# Acessar SonarQube → My Account → Security → Generate new token

# 3. Verificar permissões do token
# Token deve ter permissão "Execute Analysis"

# 4. Verificar URL do SonarQube
echo $SONAR_HOST_URL  # Deve ser http://localhost:9000 ou URL correta
```

### Problema 3: Scan Muito Lento (>10 minutos)

**Sintoma**: Scan demora muito tempo para completar

**Soluções**:
```properties
# sonar-project.properties

# 1. Excluir arquivos grandes/não relevantes
sonar.exclusions=**/*.min.js,**/*.bundle.js,**/vendor/**,**/node_modules/**

# 2. Separar código de testes
sonar.tests=test
sonar.test.inclusions=**/*Test.java

# 3. Analisar apenas código fonte principal
sonar.sources=src/main  # Ao invés de src/

# 4. Usar modo preview para análise rápida (sem histórico)
# Adicionar no comando: -Dsonar.analysis.mode=preview
```

### Problema 4: Muitos False Positives

**Sintoma**: SAST flagga muitas vulnerabilities que não são reais

**Soluções**:
1. **Configurar exceções documentadas**:
   ```java
   @SuppressWarnings("java:S2068") // Hardcoded credential - false positive
   // Razão: Password é para teste, não usado em produção
   String testPassword = "changeme123";
   ```

2. **Desabilitar regras não aplicáveis**:
   - SonarQube → Quality Profiles → Desabilitar regras específicas
   - Criar profile customizado para seu projeto

3. **Ajustar severidade de regras**:
   - SonarQube → Quality Profiles → Mudar severidade de regras que geram muitos false positives

### Problema 5: Quality Gate Bloqueia Tudo

**Sintoma**: Pipeline sempre falha por causa de Quality Gate

**Soluções**:
```yaml
# Estratégia Gradual:

# Semana 1-2: Muito Permissivo
Quality Gate:
  - Security Rating: Qualquer
  - New Vulnerabilities: 0 Critical apenas
  
# Semana 3-4: Médio
Quality Gate:
  - Security Rating: A ou B
  - New Vulnerabilities: 0 Critical, máx 10 High
  
# Mês 2+: Rigoroso
Quality Gate:
  - Security Rating: A ou B
  - New Vulnerabilities: 0 Critical, máx 5 High
  - Security Hotspots: 0 Critical/High novas
```

### Problema 6: Scan Não Encontra Vulnerabilidades Óbvias

**Sintoma**: Código vulnerável conhecido não é flagado

**Soluções**:
1. **Verificar Quality Profile ativo**:
   - SonarQube → Projeto → Quality Profiles
   - Verificar se regras de segurança estão ativas

2. **Verificar linguagem detectada**:
   - SonarQube → Projeto → Code
   - Verificar se linguagem está sendo detectada corretamente

3. **Verificar exclusões**:
   - SonarQube → Projeto → Settings → Exclusions
   - Verificar se arquivo não está sendo excluído

4. **Executar scan com debug**:
   ```bash
   sonar-scanner -X  # Modo verbose/debug
   ```

---

## Dicas

1. **Primeira vez com SonarQube**: Pode levar 1-2 minutos para inicializar completamente
2. **Projeto grande**: O primeiro scan pode demorar. Seja paciente!
3. **Token expirado**: Se o token não funcionar, gere um novo no SonarQube
4. **Erro de conexão**: Verifique se SonarQube está rodando: `docker ps | grep sonarqube`
5. **Linguagem não suportada**: Verifique linguagens suportadas: https://docs.sonarqube.org/latest/analysis/languages/overview/
6. **Muitos findings**: Não se assuste! É normal ter muitos findings no primeiro scan. Priorize por risco real.
7. **Quality Gate muito rígido**: Comece permissivo e aperte gradualmente
8. **Performance lenta**: Exclua arquivos não relevantes, separe código de testes
9. **False positives**: Configure exceções documentadas, ajuste regras

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] SonarQube está rodando e acessível em `http://localhost:9000`
- [ ] Projeto criado no SonarQube
- [ ] Token gerado e configurado
- [ ] Primeiro scan executado com sucesso
- [ ] Dashboard mostra resultados da análise
- [ ] Top 5 vulnerabilidades identificadas e documentadas
- [ ] Relatório de análise criado com detalhes de cada vulnerabilidade
- [ ] Priorização por risco real realizada

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Exercício 2.1.2: Criar Regras Customizadas Semgrep
- Exercício 2.1.3: Integrar SAST no CI/CD
- Configurar SonarQube em projetos de outros contextos (financeiro, educacional, etc.)
- Integrar SonarQube em workflows de desenvolvimento

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Screenshot do dashboard do SonarQube com resultados
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
**Pré-requisitos**: Aula 2.1 (SAST: Static Application Security Testing), Docker instalado
