---
layout: lesson
title: "Aula 4.3: Container Security e Kubernetes"
slug: container-security-kubernetes
module: module-4
lesson_id: lesson-4-3
duration: "90 minutos"
level: "Avançado"
prerequisites: ["lesson-4-2"]
exercises: []
image: "assets/images/podcasts/4.3-Container_Security_Kubernetes.png"
permalink: /modules/seguranca-cicd-devsecops/lessons/container-security-kubernetes/
---

# Aula 4.3: Container Security e Kubernetes

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Entender os principais riscos de segurança em containers
- Aplicar Docker security best practices
- Escanear vulnerabilidades em imagens Docker
- Configurar segurança em Kubernetes (RBAC, Network Policies, Pod Security)
- Implementar runtime protection para containers
- Validar configurações de containers em CI/CD

## 📚 Segurança de Containers Docker

### Principais Riscos de Segurança em Containers

#### 1. Vulnerabilidades em Imagens Base

**Problema**: Imagens base podem conter vulnerabilidades conhecidas.

**Exemplo**:
```dockerfile
# ❌ RUIM: Imagem base desatualizada
FROM node:14  # Vulnerabilidades conhecidas

# ✅ BOM: Imagem base atualizada
FROM node:18-alpine  # Mais recente, menor superfície de ataque
```

#### 2. Secrets em Imagens

**Problema**: Secrets hardcoded em Dockerfiles ou commitados no código.

**Exemplo**:
```dockerfile
# ❌ RUIM: Secret hardcoded
ENV API_KEY=sk-1234567890abcdef

# ✅ BOM: Secret via build arg ou secret manager
ARG API_KEY
ENV API_KEY=${API_KEY}
```

#### 3. Containers Rodando como Root

**Problema**: Containers rodando como usuário root têm privilégios elevados.

**Exemplo**:
```dockerfile
# ❌ RUIM: Container como root
FROM node:18
RUN npm install

# ✅ BOM: Container como usuário não-privilegiado
FROM node:18-alpine
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
USER nodejs
RUN npm install
```

#### 4. Dependências Vulneráveis

**Problema**: Aplicações com dependências vulneráveis (npm, pip, etc).

**Exemplo**:
```dockerfile
# Vulnerabilidades em package.json
RUN npm install  # Instala dependências vulneráveis
```

### Docker Security Best Practices

#### 1. Use Imagens Base Mínimas

```dockerfile
# ✅ BOM: Imagem Alpine (menor, mais segura)
FROM node:18-alpine

# ❌ RUIM: Imagem completa (maior, mais vulnerabilidades)
FROM node:18
```

#### 2. Multi-stage Builds

```dockerfile
# ✅ BOM: Multi-stage build (imagem final menor)
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:18-alpine AS runtime
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
CMD ["node", "dist/index.js"]
```

#### 3. Não Instalar Ferramentas Desnecessárias

```dockerfile
# ❌ RUIM: Instala ferramentas de desenvolvimento
RUN apt-get update && \
    apt-get install -y curl wget vim git

# ✅ BOM: Apenas runtime dependencies
RUN apk add --no-cache nodejs npm
```

#### 4. Escanear Imagens Regularmente

```bash
# Escanear imagem local
trivy image myapp:latest

# Escanear com falha em vulnerabilidades críticas
trivy image --exit-code 1 --severity CRITICAL myapp:latest

# Escanear e gerar relatório
trivy image --format sarif -o trivy-results.sarif myapp:latest
```

### Scanning de Containers em CI/CD

```yaml
container-scan:
  name: Container Security Scan
  runs-on: ubuntu-latest
  steps:
    - name: Build Docker image
      run: docker build -t myapp:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: myapp:${{ github.sha }}
        format: 'sarif'
        output: 'trivy-results.sarif'
        severity: 'CRITICAL,HIGH'
        exit-code: '1'  # Falha se encontrar vulnerabilidades críticas/altas
    
    - name: Upload Trivy results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: trivy-results.sarif
```

---

## ☸️ Segurança em Kubernetes

### Principais Riscos de Segurança em Kubernetes

#### 1. RBAC (Role-Based Access Control) Inadequado

**Problema**: Permissões muito amplas permitem acesso não autorizado.

**Exemplo Ruim**:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["*"]  # ❌ Acesso a todos os recursos
  verbs: ["*"]      # ❌ Todas as operações
```

**Exemplo Bom**:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]  # ✅ Apenas leitura de pods
```

#### 2. Secrets Expostos

**Problema**: Secrets armazenados em plaintext ou commitados no código.

**Solução**: Usar Kubernetes Secrets ou Secret Managers externos.

```yaml
# ✅ BOM: Secret via Kubernetes Secret
apiVersion: v1
kind: Secret
metadata:
  name: api-key
type: Opaque
data:
  api-key: <base64-encoded-value>
```

#### 3. Network Policies Ausentes

**Problema**: Todos os pods podem se comunicar entre si (risco lateral).

**Solução**: Implementar Network Policies.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  # Nenhum tráfego permitido por padrão
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-db
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api
    ports:
    - protocol: TCP
      port: 5432
```

#### 4. Pod Security Standards

**Problema**: Pods rodando com privilégios desnecessários.

**Solução**: Usar Pod Security Standards.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: myapp
  labels:
    pod-security.kubernetes.io/enforce: restricted  # ✅ Máxima segurança
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
  namespace: myapp
spec:
  securityContext:
    runAsNonRoot: true        # ✅ Não roda como root
    runAsUser: 1001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false  # ✅ Sem privilege escalation
      capabilities:
        drop:
        - ALL  # ✅ Remove todas as capabilities
      readOnlyRootFilesystem: true      # ✅ Root filesystem read-only
```

### Scanning de Configurações Kubernetes

#### Ferramentas

1. **Checkov**: Análise de YAML de Kubernetes
2. **Kube-bench**: CIS Benchmark para Kubernetes
3. **Polaris**: Validação de best practices
4. **OPA Gatekeeper**: Policy enforcement

#### Exemplo: Scanning com Checkov

```bash
# Escanear arquivos Kubernetes
checkov -f k8s/deployment.yaml

# Escanear diretório completo
checkov -d k8s/ --framework kubernetes
```

#### Exemplo: CI/CD com Checkov

```yaml
k8s-scan:
  name: Kubernetes Configuration Scan
  runs-on: ubuntu-latest
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Run Checkov
      uses: bridgecrewio/checkov-action@master
      with:
        directory: k8s/
        framework: kubernetes
        output_format: sarif
        output_file_path: checkov-k8s.sarif
    
    - name: Upload results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: checkov-k8s.sarif
```

---

## 🛡️ Runtime Protection

### O que é Runtime Protection?

**Definição**: Monitoramento e proteção de containers em execução (runtime).

**Ferramentas**:
- **Falco**: Runtime security monitoring (CNCF)
- **Aqua Security**: Enterprise runtime protection
- **Sysdig**: Container security e monitoring
- **Twistlock**: Runtime protection (Palo Alto)

### Falco: Runtime Security Monitoring

**Falco** é uma ferramenta open-source de runtime security para containers.

#### Instalação

```bash
# Instalar Falco no Kubernetes
kubectl apply -f https://raw.githubusercontent.com/falcosecurity/falco/master/deploy/falco/rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/falcosecurity/falco/master/deploy/falco/deployment.yaml
```

#### Regras Personalizadas

```yaml
# falco-rules.yaml
- rule: Detect shell in container
  desc: Detect shell spawned in container
  condition: >
    spawned_process and container and
    shell_procs and proc.tty != 0 and
    container_entrypoint
  output: >
    Shell spawned in container (user=%user.name container=%container.name
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty
    container_id=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [container, shell]
```

---

## 💼 Exemplos Práticos CWI

### Caso 1: Pipeline com Container Scanning

```yaml
container-security-pipeline:
  stages:
    - name: Build Image
      steps:
        - docker build -t myapp:$CI_COMMIT_SHA .
    
    - name: Scan Image
      steps:
        - trivy image --exit-code 1 --severity CRITICAL myapp:$CI_COMMIT_SHA
    
    - name: Deploy (if scan passes)
      steps:
        - kubectl set image deployment/myapp myapp=myapp:$CI_COMMIT_SHA
```

### Caso 2: Kubernetes Secure Configuration

```yaml
# deployment-secure.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
      containers:
      - name: app
        image: myapp:latest
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 250m
            memory: 256Mi
```

---

## 📝 Resumo da Aula

### Principais Conceitos

1. **Container Security**: Vulnerabilidades em imagens base, secrets, usuários privilegiados
2. **Docker Best Practices**: Imagens mínimas, multi-stage builds, scanning regular
3. **Kubernetes Security**: RBAC, Network Policies, Pod Security Standards
4. **Runtime Protection**: Monitoramento de containers em execução
5. **Scanning**: Trivy para containers, Checkov para Kubernetes

### Próximos Passos

Na próxima aula (4.4), você aprenderá sobre:
- Gerenciamento seguro de secrets
- Ferramentas de secrets management (Vault, AWS Secrets Manager)
- Detecção de secrets em repositórios
- Rotação automática de secrets

---

## 📚 Recursos Adicionais

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Falco Documentation](https://falco.org/docs/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

---

**Duração da Aula**: 90 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Aula 4.2 (Pipeline de Segurança), conhecimento básico de Docker e Kubernetes
