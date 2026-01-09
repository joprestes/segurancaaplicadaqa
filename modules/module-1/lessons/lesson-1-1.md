---
layout: lesson
title: "Aula 1.1: Introdução à Segurança em QA"
slug: introducao-seguranca-qa
module: module-1
lesson_id: lesson-1-1
duration: "60 minutos"
level: "Básico"
prerequisites: []
exercises: []
podcast:
  file: "assets/podcasts/1.1-Introducao_Seguranca_QA.m4a"
  image: "assets/images/podcasts/1.1-Introducao_Seguranca_QA.png"
  title: "Introdução à Segurança em QA"
  description: "Compreenda o papel crítico da segurança na qualidade de software. Discutimos por que segurança não é apenas responsabilidade de DevOps, mas parte essencial do processo de QA desde o início do desenvolvimento."
  duration: "45-60 minutos"
permalink: /modules/fundamentos-seguranca-qa/lessons/introducao-seguranca-qa/
---

# Aula 1.1: Introdução à Segurança em QA

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Compreender o papel da segurança no processo de QA
- Diferenciar QA tradicional de Security QA
- Entender a tríade CIA (Confidencialidade, Integridade, Disponibilidade)
- Reconhecer por que segurança é responsabilidade de todos
- Identificar quando segurança deve ser considerada no ciclo de desenvolvimento

## 📚 Conteúdo

### 1. Por que Segurança em QA?

#### O Custo de Vulnerabilidades

Em 2023, o custo médio de uma violação de dados foi de **US$ 4,45 milhões** (IBM Security). Vulnerabilidades encontradas em produção custam em média **30x mais** para corrigir do que se identificadas em desenvolvimento.

**Exemplos reais de impacto:**

- **Setor Financeiro**: Vazamento de dados de cartões = multas PCI-DSS + perda de confiança
- **Educacional**: Exposição de dados de menores = multas LGPD + processo judicial
- **Ecommerce**: Fraudes não detectadas = prejuízo financeiro direto
- **IA**: Model poisoning = decisões incorretas em produção

#### O Papel Único do QA

Como profissional de QA, você está em posição única para:

✅ **Pensar como usuário E como atacante** - Você conhece os fluxos, entende os edge cases  
✅ **Identificar vulnerabilidades cedo** - Testes acontecem antes de produção  
✅ **Validar correções** - Você verifica se a vulnerabilidade foi realmente corrigida  
✅ **Criar testes de regressão** - Garante que vulnerabilidades não retornem  

### 2. QA Tradicional vs Security QA

| Aspecto | QA Tradicional | Security QA |
|---------|---------------|-------------|
| **Foco** | Funcionalidade correta | Funcionalidade segura |
| **Mindset** | "O sistema faz o que deve?" | "O sistema impede o que não deve?" |
| **Testes** | Casos de uso válidos | Casos de uso maliciosos |
| **Cobertura** | Happy path + edge cases | Attack vectors + exploits |
| **Validação** | Output esperado | Sem vazamento/exploits |
| **Ferramentas** | Selenium, JUnit, Postman | ZAP, Burp Suite, SonarQube |

**Importante**: Security QA não substitui QA tradicional, **complementa**.

### 3. A Tríade CIA

Base de toda segurança da informação:

```
┌─────────────────────────────────────────┐
│         CIA TRIAD                       │
│                                         │
│     Confidencialidade                   │
│     ↓                                   │
│     Apenas pessoas autorizadas          │
│     acessam informações                 │
│                                         │
│     Integridade                         │
│     ↓                                   │
│     Informações não são alteradas       │
│     indevidamente                       │
│                                         │
│     Disponibilidade                     │
│     ↓                                   │
│     Sistemas acessíveis quando          │
│     necessário                          │
└─────────────────────────────────────────┘
```

#### Confidencialidade

**Definição**: Informações só são acessíveis a quem tem autorização.

**Exemplos de quebra no contexto CWI**:
- **Financeiro**: Log com número de cartão completo visível
- **Educacional**: API retorna dados de outros alunos sem validação
- **Ecommerce**: Histórico de compras acessível via URL manipulation
- **IA**: Dados de treinamento expostos via inferência

**Como QA testa**:
```bash
# Teste de autorização
GET /api/users/123/orders
Authorization: Bearer <token_usuario_456>

# Esperado: 403 Forbidden
# Vulnerável: 200 OK com dados do usuário 123
```

#### Integridade

**Definição**: Informações não podem ser modificadas de forma não autorizada.

**Exemplos de quebra**:
- **Financeiro**: Modificar valor da transferência interceptando requisição
- **Educacional**: Alterar notas via manipulação de formulário
- **Ecommerce**: Modificar preço de produto no checkout
- **IA**: Poisoning do modelo com dados maliciosos

**Como QA testa**:
```bash
# Teste de integridade
POST /api/orders
{
  "product_id": 123,
  "price": 0.01,  # Preço manipulado
  "quantity": 1
}

# Esperado: Validação server-side rejeita
# Vulnerável: Aceita preço manipulado
```

#### Disponibilidade

**Definição**: Sistemas devem estar disponíveis quando necessário.

**Exemplos de quebra**:
- **Financeiro**: DoS no sistema de pagamentos
- **Educacional**: Plataforma fora em dia de prova
- **Ecommerce**: Site cai na Black Friday
- **IA**: API de inferência sobrecarregada

**Como QA testa**:
```bash
# Teste de rate limiting
for i in {1..1000}; do
  curl -X POST /api/login &
done

# Esperado: Rate limiting bloqueia
# Vulnerável: Sistema fica lento/cai
```

### 4. Segurança é Responsabilidade de Todos

#### O Modelo Tradicional (ERRADO ❌)

```
Dev → QA → Security → Produção
          ↑
      Gargalo
```

**Problemas**:
- Security só vê código no final
- Correções custam caro (arquitetura já definida)
- Atrasos no release
- Conflito entre times

#### O Modelo Moderno (CORRETO ✅)

```
┌─────────────────────────────────────────┐
│  Security by Design                     │
│                                         │
│  Requisitos → Design → Dev → QA         │
│      ↓          ↓       ↓     ↓        │
│   Security  Security  SAST  DAST        │
│   Review    Review          SCA         │
└─────────────────────────────────────────┘
```

**Benefícios**:
- Vulnerabilidades identificadas cedo
- Custo menor de correção
- Releases mais rápidos e seguros
- Colaboração entre times

### 5. Quando Segurança Deve Ser Considerada

#### Fase de Requisitos
- [ ] Requisitos de segurança definidos (autenticação, autorização, criptografia)
- [ ] Compliance identificado (LGPD, PCI-DSS, etc.)
- [ ] Dados sensíveis mapeados

#### Fase de Design
- [ ] Threat modeling realizado
- [ ] Arquitetura de segurança definida
- [ ] Controles de segurança planejados

#### Fase de Desenvolvimento
- [ ] SAST rodando em cada commit
- [ ] Code review com foco em segurança
- [ ] Dependency scanning ativo

#### Fase de QA (SEU PAPEL!)
- [ ] Testes de segurança automatizados
- [ ] DAST em ambiente de teste
- [ ] Validação de correções de vulnerabilidades
- [ ] Testes de autorização e autenticação

#### Fase de Deploy
- [ ] Scanning de containers/infra
- [ ] Secrets não expostos
- [ ] Configurações seguras validadas

#### Fase de Produção
- [ ] Monitoramento de segurança ativo
- [ ] Logs de auditoria configurados
- [ ] Plano de resposta a incidentes pronto

## 💼 Aplicação no Contexto CWI

### Cenário Real 1: Cliente Financeiro

**Situação**: Novo recurso de Open Banking sendo desenvolvido.

**Papel do QA**:
1. Validar que autenticação OAuth2 está correta
2. Testar que APIs só retornam dados do usuário autenticado
3. Verificar rate limiting para prevenir abuse
4. Confirmar logs de auditoria para compliance

### Cenário Real 2: Plataforma Educacional

**Situação**: Feature de mensagens entre alunos.

**Papel do QA**:
1. Testar que XSS não é possível em mensagens
2. Validar que menores só se comunicam com contatos aprovados
3. Verificar que dados sensíveis não vazam em logs
4. Confirmar que LGPD é respeitada (direito ao esquecimento)

### Cenário Real 3: Ecommerce

**Situação**: Novo fluxo de checkout.

**Papel do QA**:
1. Validar que preços não podem ser manipulados no cliente
2. Testar SQL Injection em campos de busca
3. Verificar que dados de cartão são tokenizados (PCI-DSS)
4. Confirmar HTTPS em todas as páginas sensíveis

## 🎯 Exercícios Práticos

### Exercício 1: Identificando Quebras da Tríade CIA

Para cada cenário, identifique se há quebra de Confidencialidade, Integridade ou Disponibilidade:

1. API retorna todos os pedidos quando deveria retornar apenas do usuário logado
2. Usuário consegue modificar o valor de um produto antes do pagamento
3. Sistema fica fora do ar após 100 requisições simultâneas
4. Senha do usuário é enviada por email em texto puro

**Respostas**: [Ver ao final da aula]

### Exercício 2: QA Tradicional vs Security QA

Dado o cenário de uma API de login, liste:
- 3 testes que um QA tradicional faria
- 3 testes adicionais que um Security QA faria

### Exercício 3: Seu Projeto

Pense em um projeto que você está trabalhando atualmente na CWI:
1. Identifique 3 pontos onde segurança poderia ser melhorada
2. Para cada ponto, defina: CIA afetado, risco e mitigação
3. Documente em formato de issue/ticket

## 📖 Material Complementar

### Leitura Recomendada
- [OWASP Testing Guide - Introduction](https://owasp.org/www-project-web-security-testing-guide/)
- [The Security Testing Mindset](https://martinfowler.com/articles/security-mindset.html)
- [CIA Triad Explained](https://www.fortinet.com/resources/cyberglossary/cia-triad)

### Vídeos
- "Security Testing for Beginners" - OWASP (30 min)
- "The Role of QA in DevSecOps" - DevOps Institute (45 min)

### Ferramentas para Explorar
- **OWASP Juice Shop**: Aplicação vulnerável para prática
- **OWASP WebGoat**: Tutoriais interativos de vulnerabilidades
- **HackTheBox**: Plataforma de desafios de segurança

## 🎯 Próximos Passos

Na **Aula 1.2**, você vai mergulhar profundamente nas **OWASP Top 10 vulnerabilidades**. Prepare-se para aprender sobre:
- Injection attacks (SQL, NoSQL, LDAP)
- Broken Authentication
- Sensitive Data Exposure
- E as outras 7 vulnerabilidades críticas

---

## Respostas dos Exercícios

### Exercício 1:
1. **Confidencialidade** - Dados de outros usuários expostos
2. **Integridade** - Dado crítico (preço) modificado indevidamente
3. **Disponibilidade** - Sistema não acessível quando necessário
4. **Confidencialidade** - Senha exposta em canal inseguro

---

**Duração**: 60 minutos  
**Próxima Aula**: OWASP Top 10 e Principais Vulnerabilidades
