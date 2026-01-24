---
exercise_id: lesson-2-4-exercise-5-security-policy-as-code
title: "Exercício 2.4.5: Security Policy as Code"
lesson_id: lesson-2-4
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.4.5: Security Policy as Code

## 📋 Enunciado
Crie políticas de segurança como código (OPA, Semgrep rules, custom linters) versionadas no Git.

### Requisitos
1. Políticas definidas em código (YAML/Rego)
2. Versionadas no Git
3. Aplicadas automaticamente no CI
4. Documentadas (por que cada política)

---

## ✅ Solução Completa

### 1. Semgrep Custom Rules

```yaml
# .semgrep/rules/security-policies.yml
rules:
  # Política 1: Proibir senhas hardcoded
  - id: no-hardcoded-passwords
    pattern-either:
      - pattern: password = "..."
      - pattern: PASSWORD = "..."
      - pattern: secret = "..."
    message: |
      ❌ POLÍTICA VIOLADA: Senha hardcoded detectada
      
      Por quê: Credenciais no código podem vazar via Git/logs
      Como corrigir: Use variáveis de ambiente ou secret manager
      
      Correto:
        const password = process.env.DB_PASSWORD;
      
      Documentação: docs/policies/P001-no-hardcoded-secrets.md
    severity: ERROR
    languages: [javascript, typescript, python]
    metadata:
      policy_id: P001
      category: secrets-management
      cwe: CWE-798
  
  # Política 2: SQL deve usar prepared statements
  - id: enforce-prepared-statements
    patterns:
      - pattern: db.query($QUERY)
      - pattern-not: db.query("...", [...])
      - metavariable-regex:
          metavariable: $QUERY
          regex: .*\+.*
    message: |
      ❌ POLÍTICA VIOLADA: SQL sem prepared statement
      
      Por quê: Concatenação de strings = SQL Injection
      Como corrigir: Use placeholders (?, $1, etc)
      
      Errado:
        db.query("SELECT * FROM users WHERE id = " + userId);
      
      Correto:
        db.query("SELECT * FROM users WHERE id = ?", [userId]);
      
      Documentação: docs/policies/P002-sql-injection-prevention.md
    severity: ERROR
    languages: [javascript, typescript]
    metadata:
      policy_id: P002
      category: sql-injection
      cwe: CWE-89
  
  # Política 3: Autenticação obrigatória em rotas sensíveis
  - id: require-auth-middleware
    patterns:
      - pattern: |
          app.post("/api/$ENDPOINT", $HANDLER)
      - pattern-not: |
          app.post("/api/$ENDPOINT", authMiddleware, $HANDLER)
      - metavariable-regex:
          metavariable: $ENDPOINT
          regex: (users|admin|payments|transactions).*
    message: |
      ⚠️ POLÍTICA VIOLADA: Endpoint sensível sem autenticação
      
      Por quê: Endpoints de /admin, /payments precisam auth
      Como corrigir: Adicione middleware de autenticação
      
      Correto:
        app.post("/api/users", authMiddleware, createUser);
      
      Documentação: docs/policies/P003-auth-required.md
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      policy_id: P003
      category: authentication
      cwe: CWE-306
  
  # Política 4: Logging de operações sensíveis
  - id: require-audit-log
    patterns:
      - pattern: |
          function $FUNC(...) {
            ...
            $DB.delete(...)
            ...
          }
      - pattern-not: |
          function $FUNC(...) {
            ...
            logger.audit(...)
            ...
            $DB.delete(...)
            ...
          }
    message: |
      ⚠️ POLÍTICA VIOLADA: Operação sensível sem audit log
      
      Por quê: Deleções/updates críticos precisam rastreabilidade
      Como corrigir: Adicione logger.audit() antes da operação
      
      Correto:
        logger.audit({ action: 'DELETE', resource: 'user', id });
        await db.users.delete(id);
      
      Documentação: docs/policies/P004-audit-logging.md
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      policy_id: P004
      category: audit-logging
```

### 2. OPA (Open Policy Agent) Policies

```rego
# policies/security.rego
package security

# Política: Imagens Docker devem ser de registries aprovados
deny[msg] {
  input.kind == "Deployment"
  image := input.spec.template.spec.containers[_].image
  not startswith(image, "docker.io/approved/")
  not startswith(image, "ghcr.io/myorg/")
  msg := sprintf("Imagem não aprovada: %v. Use registries: docker.io/approved/ ou ghcr.io/myorg/", [image])
}

# Política: Proibir privileged containers
deny[msg] {
  input.kind == "Pod"
  input.spec.containers[_].securityContext.privileged == true
  msg := "Container privilegiado detectado. Política P005: Proibido por risco de escape."
}

# Política: Secrets não podem estar em ConfigMaps
deny[msg] {
  input.kind == "ConfigMap"
  key := input.data[_]
  contains(lower(key), "password")
  msg := sprintf("ConfigMap contém 'password': %v. Use Secrets, não ConfigMaps.", [key])
}
```

### 3. GitHub Actions Enforcement

```yaml
# .github/workflows/policy-check.yml
name: Security Policy Check

on: [push, pull_request]

jobs:
  semgrep-policies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Semgrep Custom Policies
        run: |
          semgrep scan \
            --config=.semgrep/rules/security-policies.yml \
            --error \
            --json > policy-violations.json
      
      - name: Report Violations
        if: failure()
        run: |
          jq -r '.results[] | "❌ \(.extra.message) - \(.path):\(.start.line)"' \
            policy-violations.json
  
  opa-policies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa
      
      - name: Test Kubernetes manifests against policies
        run: |
          for manifest in k8s/*.yml; do
            ./opa eval -d policies/security.rego -i $manifest \
              'data.security.deny' --format pretty
          done
```

### 4. Documentação das Políticas

```markdown
# docs/policies/README.md

## 📋 Políticas de Segurança - Índice

| ID   | Título                          | Severidade | Categoria          |
|------|---------------------------------|------------|--------------------|
| P001 | No Hardcoded Secrets            | ERROR      | Secrets Management |
| P002 | SQL Injection Prevention        | ERROR      | Injection          |
| P003 | Auth Required (Sensitive Routes)| WARNING    | Authentication     |
| P004 | Audit Logging (Critical Ops)    | WARNING    | Logging            |
| P005 | No Privileged Containers        | ERROR      | Container Security |

---

## P001: No Hardcoded Secrets

**Descrição**: Proibir credenciais hardcoded no código-fonte

**Por quê**:
- Credenciais no Git = vazamento via histórico (mesmo após remoção)
- Logs/dumps de memória podem expor secrets
- Dificulta rotação de credenciais

**Como detectar**: Semgrep rule `no-hardcoded-passwords`

**Como corrigir**:
```javascript
// ❌ Errado
const password = "MySuperSecret123";

// ✅ Correto
const password = process.env.DB_PASSWORD;
```

**Exceções**: Nenhuma (zero-tolerance)

**Compliance**: LGPD Art. 46, PCI-DSS 8.2.1

---

## P002: SQL Injection Prevention

**Descrição**: Queries SQL devem usar prepared statements

**Por quê**:
- SQL Injection é #1 em OWASP Top 10
- Permite acesso não autorizado a dados
- Pode levar a vazamento completo do banco

**Como detectar**: Semgrep rule `enforce-prepared-statements`

**Como corrigir**:
```javascript
// ❌ Errado
db.query("SELECT * FROM users WHERE id = " + userId);

// ✅ Correto
db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

**Exceções**: Queries dinâmicas (DDL) com sanitização explícita

**Compliance**: OWASP Top 10 A03:2021

---

(... documentar todas as políticas ...)
```

### 5. Pre-commit Hook (Local Enforcement)

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "🔒 Verificando políticas de segurança..."

# Run Semgrep policies
semgrep scan --config=.semgrep/rules/security-policies.yml --error --quiet

if [ $? -ne 0 ]; then
  echo "❌ Políticas violadas. Corrija antes de commitar."
  echo "📖 Veja docs/policies/README.md"
  exit 1
fi

echo "✅ Políticas OK"
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **Policy as Code**: Políticas versionadas, testadas, revisadas como código
2. **Shift-Left**: Detectar violações localmente (pre-commit) e no CI
3. **Self-Service**: Desenvolvedores entendem e corrigem políticas
4. **Auditabilidade**: Histórico de mudanças de políticas no Git

### Erros Comuns

**Erro 1: "Políticas muito genéricas (muitos false positives)"**
- **Feedback**: "Políticas precisam de contexto. Ex: 'password =' detecta `password = hash(...)` (falso positivo). Use `pattern-not` para excluir casos válidos. Teste políticas em codebase real antes de ativar enforcement."

**Erro 2: "Não documentou o 'por quê' das políticas"**
- **Feedback**: "Dev vê 'Política P001 violada' mas não entende razão. Documente: 1) Por que a política existe, 2) Risco se não seguir, 3) Como corrigir (exemplo concreto), 4) Onde pedir exceção. Transparência gera adesão."

**Erro 3: "Políticas não versionadas (YAML local, não no Git)"**
- **Feedback**: "Políticas devem estar no Git: 1) Rastreabilidade (quem mudou, quando, por quê), 2) Revisão (PR para mudar política), 3) Reprodutibilidade (CI usa mesma versão). Políticas locais = inconsistência entre ambientes."

**Erro 4: "Enforcement só no CI (não pre-commit)"**
- **Feedback**: "Dev comita → push → CI falha → frustrante. Adicione pre-commit hook: feedback imediato (antes de push). Instale com husky/lefthook. Dev corrige localmente = experiência melhor."

### Feedback Construtivo

**Para políticas profissionais:**
> "Excelente Policy as Code! Políticas em Semgrep/OPA, versionadas, documentadas, enforced no CI e pre-commit. Isso é governança de segurança madura. Próximo nível: 1) Métricas de violações, 2) Processo de exceção rastreado, 3) Revisão trimestral de políticas."

**Para políticas básicas:**
> "Boas políticas! Configuradas no Semgrep. Para profissionalizar: 1) Documente cada política (por quê, como corrigir), 2) Versione no Git (.semgrep/rules/), 3) Adicione pre-commit hook (feedback local), 4) Comunique ao time (não surpresa). Funciona, agora adoção."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
