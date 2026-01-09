# 🔐 Personalização para Segurança em QA - Resumo das Alterações

Este documento resume todas as alterações realizadas para personalizar a plataforma de ensino do tema Angular para **Segurança Aplicada à Qualidade de Software**, com foco em profissionais CWI.

---

## ✅ Alterações Concluídas

### 1. Configuração Principal (_config.yml)

**Alterado de:**
- Título: "Angular Expert"
- Descrição: Treinamento de Angular
- Base URL: /angular

**Alterado para:**
- Título: **"Segurança em QA - CWI"**
- Descrição: **"Segurança Aplicada à Qualidade de Software - Teoria e prática para profissionais de QA em diferentes setores"**
- Base URL: **/seguranca-qa**
- Autor: **CWI Software**

📄 Arquivo: `_config.yml`

---

### 2. Estrutura de Módulos (_data/modules.yml)

Criada estrutura de **5 módulos** progressivos focados em segurança:

#### Módulo 1: Fundamentos de Segurança em QA
- OWASP Top 10
- Shift-Left Security
- Threat Modeling
- Compliance (LGPD, PCI-DSS, SOC2)

#### Módulo 2: Testes de Segurança na Prática
- SAST (SonarQube, Semgrep, Checkmarx)
- DAST (OWASP ZAP, Burp Suite)
- Pentest Básico
- Automação de Testes
- Dependency Scanning (Snyk, Dependabot)

#### Módulo 3: Segurança por Setor
- Segurança no Financeiro (PCI-DSS, Open Banking)
- Segurança no Educacional (LGPD para menores)
- Segurança em Ecommerce (Prevenção de fraudes)
- Segurança em IA (Adversarial attacks, Model poisoning)
- APIs e Microserviços (OWASP API Top 10)

#### Módulo 4: Segurança em CI/CD e DevSecOps
- DevSecOps: Cultura e Práticas
- Pipeline de Segurança Completo
- Container Security e Kubernetes
- Secrets Management
- Monitoramento e Resposta a Incidentes

#### Módulo 5: Casos Práticos CWI
- Caso: Cliente Financeiro (Fintech)
- Caso: Plataforma Educacional (EdTech)
- Caso: Ecommerce de Alta Escala
- Checklist de Segurança para Projetos
- Construindo Carreira em Security QA

📄 Arquivo: `_data/modules.yml`

---

### 3. Estrutura de Aulas (_data/lessons.yml)

Criadas **25 aulas** completas (5 por módulo) com:

✅ Metadata completa (título, slug, duração, nível, pré-requisitos)  
✅ Informações de podcast para cada aula  
✅ Progressão lógica de aprendizado  
✅ Foco em aplicação prática em contextos CWI  

**Destaques:**
- Duração das aulas: 60-120 minutos
- Níveis: Básico → Intermediário → Avançado
- Podcasts de 45-90 minutos cada

📄 Arquivo: `_data/lessons.yml`

---

### 4. Página Inicial (index.md)

**Conteúdo atualizado:**
- ✅ Título: "Segurança Aplicada à Qualidade de Software"
- ✅ Subtítulo com contexto CWI
- ✅ Seção "O que você vai aprender"
- ✅ Seção "Contexto CWI" com setores cobertos
- ✅ Seção "Por que Segurança em QA?"
- ✅ Ícones para cada setor (🏦 Financeiro, 📚 Educacional, 🛒 Ecommerce, 🤖 IA)

📄 Arquivo: `index.md`

---

### 5. Página Sobre (about.md)

**Conteúdo completamente reescrito:**
- ✅ Objetivo claro do curso
- ✅ Metodologia (40% teoria, 60% prática)
- ✅ Estrutura dos 5 módulos
- ✅ Recursos (25 aulas, podcasts, exercícios, casos de estudo, checklist)
- ✅ Público-alvo (QAs da CWI)
- ✅ Pré-requisitos
- ✅ Competências desenvolvidas
- ✅ Contexto CWI com exemplos de clientes

📄 Arquivo: `about.md`

---

### 6. Arquivos de Módulos (modules/*/index.md)

Criados/atualizados **5 arquivos de módulos** com:

✅ Descrição detalhada do módulo  
✅ Objetivos de aprendizado  
✅ Ferramentas abordadas  
✅ Estrutura das aulas  
✅ Competências desenvolvidas  
✅ Recursos adicionais (links OWASP, documentação, ferramentas)  
✅ Conexão com próximos módulos  
✅ Dicas de estudo/implementação  

**Arquivos criados:**
- `modules/module-1/index.md` - Fundamentos de Segurança em QA
- `modules/module-2/index.md` - Testes de Segurança na Prática
- `modules/module-3/index.md` - Segurança por Setor
- `modules/module-4/index.md` - Segurança em CI/CD e DevSecOps
- `modules/module-5/index.md` - Casos Práticos CWI

---

### 7. Exemplo de Aula (modules/module-1/lessons/lesson-1-1.md)

Criada **aula exemplo completa** com estrutura profissional:

✅ Objetivos de aprendizado  
✅ Conteúdo teórico detalhado  
✅ Tabelas comparativas (QA Tradicional vs Security QA)  
✅ Diagramas ASCII (CIA Triad)  
✅ Exemplos de código práticos  
✅ Cenários reais CWI (Financeiro, Educacional, Ecommerce)  
✅ Exercícios práticos com respostas  
✅ Material complementar (leituras, vídeos, ferramentas)  
✅ Próximos passos  

📄 Arquivo: `modules/module-1/lessons/lesson-1-1.md`

---

## 📊 Estrutura Completa do Curso

```
Segurança Aplicada à Qualidade de Software
│
├── Módulo 1: Fundamentos de Segurança em QA (8h)
│   ├── 1.1 Introdução à Segurança em QA (60 min)
│   ├── 1.2 OWASP Top 10 (90 min)
│   ├── 1.3 Shift-Left Security (60 min)
│   ├── 1.4 Threat Modeling (90 min)
│   └── 1.5 Compliance e Regulamentações (90 min)
│
├── Módulo 2: Testes de Segurança na Prática (8h)
│   ├── 2.1 SAST: Testes Estáticos (90 min)
│   ├── 2.2 DAST: Testes Dinâmicos (90 min)
│   ├── 2.3 Pentest Básico (120 min)
│   ├── 2.4 Automação de Testes de Segurança (120 min)
│   └── 2.5 Dependency Scanning e SCA (90 min)
│
├── Módulo 3: Segurança por Setor (8h)
│   ├── 3.1 Segurança no Setor Financeiro (90 min)
│   ├── 3.2 Segurança no Setor Educacional (90 min)
│   ├── 3.3 Segurança em Ecommerce (90 min)
│   ├── 3.4 Segurança em Aplicações de IA (120 min)
│   └── 3.5 APIs e Microserviços (90 min)
│
├── Módulo 4: Segurança em CI/CD e DevSecOps (8h)
│   ├── 4.1 DevSecOps: Cultura e Práticas (90 min)
│   ├── 4.2 Pipeline de Segurança (120 min)
│   ├── 4.3 Container Security e Kubernetes (90 min)
│   ├── 4.4 Secrets Management (90 min)
│   └── 4.5 Monitoramento e Resposta a Incidentes (90 min)
│
└── Módulo 5: Casos Práticos CWI (8h)
    ├── 5.1 Caso: Cliente Financeiro (120 min)
    ├── 5.2 Caso: Plataforma Educacional (120 min)
    ├── 5.3 Caso: Ecommerce de Alta Escala (120 min)
    ├── 5.4 Checklist de Segurança (90 min)
    └── 5.5 Carreira em Security QA (90 min)

TOTAL: 40 horas de conteúdo
```

---

## 🎯 Próximos Passos Recomendados

### 1. Mídia (Podcasts e Vídeos)

Você precisará criar/substituir:

- **25 arquivos de podcast** (.m4a) em `assets/podcasts/`
  - Nomenclatura: `1.1-Nome_Aula.m4a`, `2.1-Nome_Aula.m4a`, etc.
  
- **25 imagens de capa** (.png) em `assets/images/podcasts/`
  - Nomenclatura: `1.1-Nome_Aula.png`, `2.1-Nome_Aula.png`, etc.

- **(Opcional) 25 vídeos** (.mp4) em `assets/videos/`

### 2. Exercícios

Atualizar arquivos de exercícios em:
- `modules/module-1/lessons/exercises/`
- `modules/module-2/lessons/exercises/`
- `modules/module-3/lessons/exercises/`
- `modules/module-4/lessons/exercises/` (atualmente vazio, precisa criar)
- `modules/module-5/lessons/exercises/` (atualmente vazio, precisa criar)

### 3. Conteúdo das Aulas

Criar as **24 aulas restantes** seguindo o modelo de `lesson-1-1.md`:
- Objetivos de aprendizado
- Conteúdo teórico detalhado
- Exemplos práticos
- Cenários CWI
- Exercícios
- Material complementar

### 4. Dados Adicionais

Atualizar se necessário:
- `_data/exercises.yml` - Lista de exercícios vinculados a aulas
- `_data/videos.yml` - Metadados dos vídeos (se usar vídeos)
- `_data/podcasts.yml` - Metadados dos podcasts (se diferente do lessons.yml)

### 5. Estilos (Opcional)

Personalizar cores e tema em:
- `_sass/_colors.scss` - Cores do tema
- `_sass/_variables.scss` - Variáveis de estilo

Sugestão de cores para tema de segurança:
```scss
$primary-color: #1a472a;  // Verde escuro (segurança)
$secondary-color: #2d6a4f; // Verde médio
$accent-color: #40916c;    // Verde claro
$danger-color: #d62828;    // Vermelho (vulnerabilidades)
$warning-color: #f77f00;   // Laranja (alertas)
```

### 6. Testes

Antes de publicar:

```bash
# 1. Testar localmente
cd crescidos-qualidade
bundle exec jekyll serve

# 2. Acessar
http://localhost:4000

# 3. Verificar
# - Navegação entre módulos
# - Links de aulas
# - Breadcrumbs
# - Podcasts (se já tiver mídia)
# - Responsividade mobile
```

### 7. Deploy

Quando pronto para publicar:

```bash
# 1. Build de produção
JEKYLL_ENV=production bundle exec jekyll build

# 2. Commit e push
git add .
git commit -m "feat: personalização para Segurança em QA CWI"
git push origin main

# 3. Configurar GitHub Pages (se usar)
# Settings > Pages > Source: main branch
```

---

## 📚 Recursos Incluídos

### Frameworks e Metodologias
- ✅ OWASP Top 10
- ✅ OWASP API Security Top 10
- ✅ STRIDE Threat Modeling
- ✅ CIA Triad
- ✅ DevSecOps

### Ferramentas Mencionadas
- **SAST**: SonarQube, Semgrep, Checkmarx, Bandit, Brakeman
- **DAST**: OWASP ZAP, Burp Suite, Acunetix, Nikto
- **SCA**: Snyk, Dependabot, OWASP Dependency-Check
- **Pentest**: Metasploit, Nmap, SQLMap, Hydra
- **Container**: Trivy, Clair, Aqua Security
- **Secrets**: HashiCorp Vault, AWS Secrets Manager, GitGuardian
- **IaC**: Checkov, TFSec, Terrascan
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins

### Compliance e Regulamentações
- ✅ LGPD (Lei Geral de Proteção de Dados)
- ✅ PCI-DSS (Payment Card Industry)
- ✅ SOC 2 (Service Organization Control)
- ✅ ISO 27001
- ✅ COPPA (Children's Online Privacy)
- ✅ FERPA (Education Privacy)

### Setores Cobertos
- 🏦 Financeiro (Fintech, Open Banking, Investimentos)
- 📚 Educacional (EdTech, Plataformas de Ensino)
- 🛒 Ecommerce (Marketplace, Pagamentos)
- 🤖 IA (Machine Learning, Recomendação)

---

## 💡 Diferenciadores do Curso

1. **Contextualizado para CWI**: Todos os exemplos são de projetos CWI
2. **Multi-setor**: Aborda 4 setores diferentes com casos práticos
3. **Hands-on**: 60% prática, 40% teoria
4. **Ferramentas Reais**: Usa ferramentas do mercado (SonarQube, ZAP, Snyk)
5. **DevSecOps**: Integração completa com CI/CD
6. **Compliance**: Foco em regulamentações brasileiras (LGPD) e internacionais
7. **Checklist Actionable**: Material que pode ser usado imediatamente
8. **Carreira**: Orientação sobre evolução profissional em Security QA

---

## 🎓 Público-Alvo

- QAs alocados em clientes CWI
- Analistas de Qualidade que querem se especializar em segurança
- QA Engineers em setores regulados
- Profissionais que querem evoluir para Security QA
- Times de QA implementando DevSecOps

---

## 📞 Suporte

Para dúvidas sobre implementação ou sugestões de melhorias:

1. Verifique este documento de resumo
2. Consulte o README.md original para questões técnicas do Jekyll
3. Revise os exemplos de arquivos criados (lesson-1-1.md)

---

## ✨ Status do Projeto

| Item | Status |
|------|--------|
| Configuração (_config.yml) | ✅ Completo |
| Estrutura de Módulos | ✅ Completo |
| Estrutura de Aulas (25) | ✅ Completo |
| Página Inicial | ✅ Completo |
| Página Sobre | ✅ Completo |
| Índices de Módulos (5) | ✅ Completo |
| Aula Exemplo (1.1) | ✅ Completo |
| Demais Aulas (24) | 🔄 Pendente |
| Exercícios | 🔄 Pendente |
| Podcasts/Vídeos | 🔄 Pendente |
| Imagens | 🔄 Pendente |
| Testes Locais | 🔄 Pendente |

---

**Criado em:** 8 de Janeiro de 2026  
**Plataforma:** Jekyll 4.3+  
**Tema Original:** Angular Expert 5 Dias  
**Novo Tema:** Segurança Aplicada à Qualidade de Software - CWI
