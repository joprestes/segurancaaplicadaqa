---
layout: lesson
title: "Aula 1.3: Shift-Left Security - Segurança desde o Início"
slug: shift-left-security
module: module-1
lesson_id: lesson-1-3
duration: "60 minutos"
level: "Básico"
prerequisites: ["lesson-1-2"]
exercises:
  - lesson-1-3-exercise-1-security-requirements
  - lesson-1-3-exercise-2-threat-modeling-early
  - lesson-1-3-exercise-3-devqa-security-collab
  - lesson-1-3-exercise-4-shift-left-checklist
video:
  file: "assets/videos/Seguranca_Shift-Left-lesson-1-3.mp4"
  title: "Shift-Left Security na Prática"
  thumbnail: "assets/images/info-grafico-lesson-1-3.png"
  description: "Entenda como integrar segurança desde as fases iniciais do desenvolvimento. Discutimos requisitos de segurança, threat modeling, e como QA pode atuar preventivamente."
  duration: "45-60 minutos"
permalink: /modules/fundamentos-seguranca-qa/lessons/shift-left-security/
---

# Aula 1.3: Shift-Left Security - Segurança desde o Início

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Entender o conceito de Shift-Left Security e sua importância
- Identificar oportunidades de integrar segurança em cada fase do SDLC
- Aplicar security requirements desde a fase de requisitos
- Colaborar efetivamente com Dev e Security em segurança preventiva
- Implementar práticas de Shift-Left Security em projetos reais

## 📚 Introdução ao Shift-Left Security

### O que é Shift-Left Security?

**Shift-Left Security** é uma abordagem que move atividades de segurança para o início do ciclo de desenvolvimento de software (SDLC - Software Development Life Cycle), ao invés de tratá-las apenas no final ou em produção.

#### 🎭 Analogia: Construção vs Manutenção

Imagine construir uma casa:

**Abordagem Tradicional (Segurança no Final)**:
- Você constrói a casa toda
- Depois descobre que não tem sistema de segurança
- Tenta adicionar alarmes, cercas, portas reforçadas depois
- É caro, difícil e nunca fica perfeito ❌

**Abordagem Shift-Left (Segurança desde o Início)**:
- Você planeja segurança desde o projeto da casa
- Instala sistema de segurança durante a construção
- Integra segurança no design
- É mais barato, eficiente e efetivo ✅

Na segurança de software, Shift-Left significa pensar em segurança desde a fase de requisitos, não apenas em testes ou produção.

### Por que Shift-Left Security é Importante?

#### O Custo das Vulnerabilidades por Fase

```
┌─────────────────────────────────────────────────────────┐
│  CUSTO DE CORRIGIR VULNERABILIDADES POR FASE           │
│                                                         │
│  Requisitos    Design    Desenvolvimento  Testes  Prod │
│     │            │            │            │       │   │
│     $1          $10         $100        $1,000  $10,000│
│                                                         │
│  Quanto mais cedo identificar, mais barato corrigir!  │
└─────────────────────────────────────────────────────────┘
```

**Dados Reais**:
- Vulnerabilidade encontrada em **requisitos**: $1 para corrigir
- Vulnerabilidade encontrada em **design**: $10 para corrigir
- Vulnerabilidade encontrada em **desenvolvimento**: $100 para corrigir
- Vulnerabilidade encontrada em **testes**: $1,000 para corrigir
- Vulnerabilidade encontrada em **produção**: $10,000+ para corrigir

**Fonte**: IBM System Sciences Institute

#### Benefícios do Shift-Left Security

| Benefício | Descrição | Impacto |
|-----------|-----------|---------|
| **Redução de Custos** | Corrigir cedo é mais barato | 10-100x mais econômico |
| **Menos Retrabalho** | Evita refatoração tardia | Economia de tempo |
| **Melhor Qualidade** | Segurança integrada no design | Produtos mais seguros |
| **Compliance** | Atende requisitos desde o início | Menos riscos regulatórios |
| **Cultura de Segurança** | Time pensa em segurança | Mudança cultural positiva |

---

## 🔄 SDLC Tradicional vs SDLC com Shift-Left Security

### SDLC Tradicional (Segurança no Final)

```
┌─────────────────────────────────────────────────────────┐
│  SDLC TRADICIONAL                                       │
│                                                         │
│  Requisitos → Design → Desenvolvimento → Testes → Prod │
│     │          │           │            │        │     │
│     │          │           │            │        │     │
│     └──────────┴───────────┴────────────┴────────┘     │
│                    Segurança aqui (tarde demais!)       │
└─────────────────────────────────────────────────────────┘
```

**Problemas**:
- Vulnerabilidades descobertas tarde
- Correções caras e complexas
- Retrabalho significativo
- Risco de não corrigir tudo

### SDLC com Shift-Left Security

```
┌─────────────────────────────────────────────────────────┐
│  SDLC COM SHIFT-LEFT SECURITY                          │
│                                                         │
│  Requisitos → Design → Desenvolvimento → Testes → Prod │
│     🔒          🔒          🔒           🔒       🔒   │
│                                                         │
│  Segurança integrada em TODAS as fases!                │
└─────────────────────────────────────────────────────────┘
```

**Vantagens**:
- Segurança desde o início
- Correções baratas e simples
- Menos retrabalho
- Produtos mais seguros

![Infográfico: Shift-Left Security - Segurança em Cada Fase do SDLC]({{ '/assets/images/info-grafico-lesson-1-3.png' | relative_url }})

---

## 📋 Segurança em Cada Fase do SDLC

### Fase 1: Requisitos

#### O que fazer nesta fase?

**Security Requirements** devem ser definidos junto com requisitos funcionais:

**Exemplos de Security Requirements**:
- Autenticação obrigatória para operações sensíveis
- Dados de cartão devem ser criptografados (PCI-DSS)
- Dados de menores devem ter proteção especial (LGPD)
- Rate limiting em APIs públicas
- Logs de auditoria para operações críticas

#### Template de Security Requirements

```markdown
## Security Requirement SR-001: Autenticação Forte

**Descrição**: Sistema deve implementar autenticação forte para acesso a dados sensíveis.

**Criticidade**: Alta

**Requisitos Específicos**:
- Senhas devem ter mínimo de 12 caracteres
- MFA obrigatório para operações financeiras
- Sessões devem expirar após 30 minutos de inatividade
- Rate limiting: máximo 5 tentativas de login por minuto

**Compliance**: PCI-DSS, LGPD

**Validação**: Testes de autenticação, revisão de código
```

#### Papel do QA nesta Fase

**Como QA pode contribuir**:
- ✅ Participar de reuniões de requisitos
- ✅ Questionar requisitos de segurança ausentes
- ✅ Validar que security requirements são testáveis
- ✅ Criar casos de teste baseados em requisitos de segurança

**Exemplo Prático**:
```markdown
**Requisito Funcional**: "Sistema deve permitir transferência entre contas"

**Security Requirements que QA deve questionar**:
- Como validar que usuário é dono da conta origem?
- Qual limite de transferência por dia?
- Como prevenir fraude?
- Quais logs são necessários para auditoria?
```

---

### Fase 2: Design

#### O que fazer nesta fase?

**Threat Modeling** deve ser realizado durante o design:

**Atividades de Segurança no Design**:
- Identificar ameaças potenciais
- Modelar arquitetura de segurança
- Definir controles de segurança
- Validar design contra requisitos de segurança

#### Diagrama: Arquitetura com Segurança

```
┌─────────────────────────────────────────────────────────┐
│  ARQUITETURA COM SEGURANÇA INTEGRADA                  │
│                                                         │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐   │
│  │  Cliente │──────│   API    │──────│  Banco   │   │
│  │          │ HTTPS│ Gateway  │      │  Dados   │   │
│  └──────────┘      │  (Auth)  │      │ (Encrypt)│   │
│                    └──────────┘      └──────────┘   │
│                         │                            │
│                         ▼                            │
│                    ┌──────────┐                     │
│                    │  Logging │                     │
│                    │  & Audit │                     │
│                    └──────────┘                     │
│                                                         │
│  Segurança integrada em cada camada!                  │
└─────────────────────────────────────────────────────────┘
```

#### Papel do QA nesta Fase

**Como QA pode contribuir**:
- ✅ Participar de sessões de threat modeling
- ✅ Validar que controles de segurança estão no design
- ✅ Questionar pontos de falha potenciais
- ✅ Criar casos de teste baseados em ameaças identificadas

---

### Fase 3: Desenvolvimento

#### O que fazer nesta fase?

**Secure Coding Practices** devem ser aplicadas durante desenvolvimento:

**Práticas de Segurança no Código**:
- Code reviews focados em segurança
- Uso de bibliotecas seguras
- Validação de entrada
- Tratamento seguro de erros
- Logging de segurança

#### Exemplo: Code Review de Segurança

```python
# ❌ CÓDIGO VULNERÁVEL - Code Review deve identificar
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = db.get_user(user_id)  # Sem validação de acesso
    return jsonify(user)

# ✅ CÓDIGO SEGURO - Após code review
@app.route('/api/users/<user_id>')
@require_auth
def get_user(user_id):
    current_user_id = session['user_id']
    
    # Validação de acesso (security requirement)
    if int(user_id) != current_user_id:
        return jsonify({'error': 'Forbidden'}), 403
    
    user = db.get_user(user_id)
    return jsonify(user)
```

#### Papel do QA nesta Fase

**Como QA pode contribuir**:
- ✅ Realizar code reviews focados em segurança
- ✅ Validar implementação de security requirements
- ✅ Testar código durante desenvolvimento (TDD de segurança)
- ✅ Verificar uso de bibliotecas seguras

---

### Fase 4: Testes

#### O que fazer nesta fase?

**Security Testing** deve ser parte dos testes:

**Tipos de Testes de Segurança**:
- Testes de autenticação e autorização
- Testes de injection (SQL, NoSQL, XSS)
- Testes de criptografia
- Testes de rate limiting
- Testes de validação de entrada

#### Exemplo: Teste de Segurança

```python
def test_broken_access_control_prevention():
    """Testa que usuários não acessam recursos de outros"""
    
    # Login como usuário 1
    token1 = login_user('user1@example.com', 'pass123')
    
    # Tentar acessar dados do usuário 2
    response = client.get(
        '/api/users/2',
        headers={'Authorization': f'Bearer {token1}'}
    )
    
    # Deve retornar 403 Forbidden
    assert response.status_code == 403
```

#### Papel do QA nesta Fase

**Como QA pode contribuir**:
- ✅ Criar testes de segurança baseados em OWASP Top 10
- ✅ Executar testes de segurança automatizados
- ✅ Validar correções de vulnerabilidades
- ✅ Documentar vulnerabilidades encontradas

---

### Fase 5: Produção

#### O que fazer nesta fase?

**Security Monitoring** deve estar ativo em produção:

**Atividades de Segurança em Produção**:
- Monitoramento de logs de segurança
- Detecção de anomalias
- Resposta a incidentes
- Atualizações de segurança

#### Papel do QA nesta Fase

**Como QA pode contribuir**:
- ✅ Validar que monitoramento está funcionando
- ✅ Testar resposta a incidentes
- ✅ Validar que logs de segurança estão corretos
- ✅ Participar de post-mortem de incidentes

---

## 🤝 Colaboração Dev/QA/Security

### Modelo de Colaboração

```
┌─────────────────────────────────────────────────────────┐
│  COLABORAÇÃO DEV/QA/SECURITY                           │
│                                                         │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐    │
│  │   Dev    │◄────►│    QA    │◄────►│ Security │    │
│  │          │      │          │      │          │    │
│  │ - Código │      │ - Testes │      │ - Policy │    │
│  │ - Review │      │ - Valida │      │ - Threat │    │
│  └──────────┘      └──────────┘      └──────────┘    │
│       │                  │                  │         │
│       └──────────────────┴──────────────────┘         │
│                    Colaboração                         │
└─────────────────────────────────────────────────────────┘
```

### Responsabilidades por Papel

| Papel | Responsabilidades em Segurança |
|-------|-------------------------------|
| **Dev** | Implementar security requirements, secure coding, code reviews |
| **QA** | Testes de segurança, validação de requisitos, documentação |
| **Security** | Políticas, threat modeling, treinamento, incident response |

### Como QA Pode Facilitar Colaboração

**Estratégias**:
1. **Comunicação Proativa**: Informar Dev sobre vulnerabilidades encontradas
2. **Educação**: Compartilhar conhecimento de segurança com Dev
3. **Ferramentas**: Usar ferramentas que facilitam colaboração
4. **Documentação**: Documentar vulnerabilidades e correções claramente

---

## 💼 Casos Práticos CWI

> **Nota**: Os casos abaixo são exemplos hipotéticos criados para fins educacionais, ilustrando como os conceitos podem ser aplicados.

### Caso Hipotético 1: Projeto Financeiro - Open Banking

**Contexto**:
Projeto hipotético de Open Banking para cliente financeiro. Segurança crítica desde o início.

**Aplicação de Shift-Left Security**:

**Fase de Requisitos**:
- Security requirements definidos: autenticação forte, rate limiting, logs de auditoria
- Compliance PCI-DSS e regulamentações bancárias incluídas

**Fase de Design**:
- Threat modeling realizado: identificadas ameaças de acesso não autorizado
- Arquitetura com API Gateway para autenticação centralizada

**Fase de Desenvolvimento**:
- Code reviews focados em segurança
- Validação de acesso em todos os endpoints

**Fase de Testes**:
- Testes automatizados de segurança
- Validação de rate limiting
- Testes de autenticação e autorização

**Resultado**:
- Zero vulnerabilidades críticas em produção
- Compliance mantido
- Tempo de desenvolvimento não aumentou significativamente

**Lição Aprendida**:
- Shift-Left Security não aumenta tempo, apenas reorganiza atividades
- Investimento inicial em segurança economiza tempo depois

---

### Caso Hipotético 2: Plataforma Educacional - LGPD

**Contexto**:
Plataforma educacional com dados de menores. Requisitos rigorosos de LGPD.

**Aplicação de Shift-Left Security**:

**Fase de Requisitos**:
- Security requirements específicos para dados de menores
- Requisitos de privacidade e consentimento

**Fase de Design**:
- Arquitetura com isolamento de dados
- Controles de acesso baseados em relacionamento aluno-turma

**Fase de Desenvolvimento**:
- Implementação de controles de privacidade
- Validação de consentimento

**Fase de Testes**:
- Testes de isolamento de dados
- Validação de controles de privacidade

**Resultado**:
- Compliance LGPD desde o início
- Dados de menores protegidos adequadamente
- Menos retrabalho em auditorias

---

### Caso Hipotético 3: Ecommerce - Prevenção de Fraude

**Contexto**:
Plataforma de ecommerce de alta escala. Prevenção de fraude crítica.

**Aplicação de Shift-Left Security**:

**Fase de Requisitos**:
- Security requirements para prevenção de fraude
- Validação de regras de negócio

**Fase de Design**:
- Arquitetura com validação de regras em múltiplas camadas
- Rate limiting e monitoramento

**Fase de Desenvolvimento**:
- Implementação de validações de negócio
- Logging de transações suspeitas

**Fase de Testes**:
- Testes de cenários de fraude
- Validação de regras de negócio

**Resultado**:
- Fraudes detectadas e prevenidas
- Regras de negócio validadas adequadamente
- Sistema robusto contra abusos

---

## ✅ Checklist de Implementação Shift-Left Security

### Fase de Requisitos
- [ ] Security requirements definidos junto com requisitos funcionais
- [ ] Requisitos de compliance incluídos (LGPD, PCI-DSS, etc.)
- [ ] Requisitos são testáveis e mensuráveis
- [ ] QA participa de definição de requisitos

### Fase de Design
- [ ] Threat modeling realizado
- [ ] Arquitetura de segurança definida
- [ ] Controles de segurança no design
- [ ] QA participa de sessões de design

### Fase de Desenvolvimento
- [ ] Code reviews focados em segurança
- [ ] Secure coding practices aplicadas
- [ ] Bibliotecas seguras utilizadas
- [ ] QA realiza code reviews de segurança

### Fase de Testes
- [ ] Testes de segurança incluídos no plano de testes
- [ ] Testes automatizados de segurança
- [ ] Validação de security requirements
- [ ] Documentação de vulnerabilidades

### Fase de Produção
- [ ] Monitoramento de segurança ativo
- [ ] Logs de segurança configurados
- [ ] Processo de resposta a incidentes
- [ ] QA valida monitoramento

---

## 🛠️ Ferramentas para Shift-Left Security

### Ferramentas por Fase

| Fase | Ferramentas |
|------|-------------|
| **Requisitos** | Jira Security Requirements, Confluence Templates |
| **Design** | Microsoft Threat Modeling Tool, OWASP Threat Dragon |
| **Desenvolvimento** | SonarQube, Checkmarx, Semgrep, GitLab Security |
| **Testes** | OWASP ZAP, Burp Suite, Snyk, Dependabot |
| **Produção** | ELK Stack, Splunk, SIEM tools |

### Integração no CI/CD

**Pipeline com Segurança Integrada**:
```yaml
# .gitlab-ci.yml exemplo
stages:
  - build
  - security-scan
  - test
  - deploy

security-scan:
  stage: security-scan
  script:
    - sonar-scanner
    - snyk test
    - semgrep --config=auto
  only:
    - merge_requests
```

---

## 📊 Métricas de Sucesso

### Métricas para Medir Shift-Left Security

| Métrica | Descrição | Meta |
|---------|-----------|------|
| **Vulnerabilidades em Produção** | Número de vulnerabilidades encontradas em produção | < 5 por release |
| **Tempo de Correção** | Tempo médio para corrigir vulnerabilidade | < 2 dias |
| **Cobertura de Testes de Segurança** | % de security requirements cobertos por testes | > 80% |
| **Code Review de Segurança** | % de PRs revisados por segurança | 100% |

---

## 🎯 Próximos Passos

Após dominar Shift-Left Security, você estará preparado para:

- **Aula 1.4**: Threat Modeling - Identificar ameaças proativamente
- **Aula 1.5**: Compliance e Regulamentações - LGPD, PCI-DSS, SOC2
- **Módulo 2**: Testes de Segurança na Prática - Ferramentas e técnicas

---

**Duração da Aula**: 60 minutos  
**Nível**: Básico  
**Pré-requisitos**: Aula 1.2 (OWASP Top 10)
