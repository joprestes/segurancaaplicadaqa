---
layout: exercise
title: "Exercício 2.2.2: Testes Manuais com Burp Suite"
slug: "burp-suite-manual"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-2-burp-suite-manual/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

## Objetivo

Este exercício tem como objetivo **aprender a usar Burp Suite para testes manuais de segurança**, interceptando e modificando requisições HTTP para encontrar vulnerabilidades.

Ao completar este exercício, você será capaz de:

- Instalar e configurar Burp Suite Community Edition
- Configurar proxy no navegador
- Interceptar e modificar requisições HTTP
- Usar Burp Suite Repeater para testes repetidos
- Usar Burp Suite Intruder para testes automatizados
- Executar scan automatizado com Burp Suite
- Identificar vulnerabilidades através de testes manuais

---

## Descrição

Você vai instalar Burp Suite, configurar como proxy, usar as ferramentas principais (Proxy, Repeater, Intruder, Scanner) para testar manualmente uma aplicação web e encontrar vulnerabilidades.

### Contexto

Testes manuais com Burp Suite são essenciais para encontrar vulnerabilidades complexas que scanners automatizados podem não detectar. Burp Suite é a ferramenta padrão da indústria para testes manuais de segurança web.

### Tarefa Principal

1. Instalar Burp Suite Community Edition
2. Configurar proxy no navegador
3. Interceptar e modificar requisições
4. Usar Repeater para testes repetidos
5. Usar Intruder para testes automatizados
6. Executar scan automatizado
7. Documentar vulnerabilidades encontradas

---

## Requisitos

### Passo 1: Instalar Burp Suite

**1.1. Download e Instalação**

```bash
# macOS
brew install --cask burp-suite-community

# Ou baixar manualmente de:
# https://portswigger.net/burp/communitydownload
```

**1.2. Iniciar Burp Suite**

- Abrir Burp Suite Community Edition
- Aceitar termos de uso
- Escolher "Temporary project" ou criar projeto permanente
- Clicar em "Start Burp"

**1.3. Verificar Configuração Inicial**

- Burp Suite deve iniciar com interface principal
- Verificar que Proxy está ativo na aba "Proxy"
- Verificar que porta padrão é 127.0.0.1:8080

### Passo 2: Configurar Proxy no Navegador

**2.1. Instalar Certificado CA do Burp**

1. No Burp Suite: Proxy → Options → Import / Export CA Certificate
2. Exportar certificado em formato DER
3. Salvar como `burp-cert.der`

**2.2. Instalar Certificado no Navegador**

**Chrome/Edge (macOS)**:
1. Abrir Keychain Access
2. Importar `burp-cert.der`
3. Encontrar "PortSwigger CA" em "login" keychain
4. Clicar duas vezes → Expandir "Trust"
5. Selecionar "Always Trust"

**Chrome/Edge (Linux)**:
```bash
# Converter DER para PEM
openssl x509 -inform DER -in burp-cert.der -out burp-cert.pem

# Instalar no sistema
sudo cp burp-cert.pem /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Firefox**:
1. Preferences → Privacy & Security → Certificates → View Certificates
2. Authorities → Import
3. Selecionar `burp-cert.der`
4. Marcar "Trust this CA to identify websites"

**2.3. Configurar Proxy no Navegador**

**Chrome/Edge (via extensão)**:
- Instalar extensão "Proxy SwitchyOmega" ou similar
- Configurar proxy: 127.0.0.1:8080

**Ou via configurações do sistema**:
- macOS: System Preferences → Network → Advanced → Proxies → Web Proxy (HTTP)
- Linux: Network Settings → Network Proxy → Manual → HTTP Proxy: 127.0.0.1:8080

**2.4. Verificar Proxy Funcionando**

1. Ativar interceptação no Burp: Proxy → Intercept → "Intercept is on"
2. Navegar para qualquer site HTTP
3. Verificar que requisição aparece no Burp Suite
4. Clicar em "Forward" para enviar requisição

### Passo 3: Interceptar e Modificar Requisições

**3.1. Interceptar Requisição de Login**

1. Navegar para aplicação web (ex: http://localhost:3000/login)
2. Preencher formulário de login
3. Clicar em "Login" (não enviar ainda)
4. No Burp Suite, verificar que requisição POST foi interceptada

**3.2. Modificar Requisição**

1. No Burp Suite, na requisição interceptada:
   - Modificar parâmetro `email` para `admin@example.com`
   - Modificar parâmetro `password` para `' OR '1'='1`
2. Clicar em "Forward" para enviar requisição modificada
3. Observar resposta no navegador

**3.3. Analisar Resposta**

- Verificar se login foi bem-sucedido (possível SQL Injection)
- Verificar mensagens de erro (informações úteis)
- Verificar headers de resposta (informações expostas)

### Passo 4: Usar Burp Suite Repeater

**4.1. Enviar Requisição para Repeater**

1. No Proxy, clicar com botão direito na requisição
2. Selecionar "Send to Repeater"
3. Ir para aba "Repeater"

**4.2. Modificar e Reenviar Requisições**

1. Modificar parâmetros na requisição
2. Clicar em "Send" para enviar
3. Analisar resposta
4. Repetir com diferentes payloads

**4.3. Exemplo: Testar SQL Injection**

```http
# Requisição original
POST /api/users HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"id": 1}

# Modificar para testar SQL Injection
POST /api/users HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"id": "1' OR '1'='1"}
```

### Passo 5: Usar Burp Suite Intruder

**5.1. Enviar Requisição para Intruder**

1. No Proxy ou Repeater, clicar com botão direito
2. Selecionar "Send to Intruder"
3. Ir para aba "Intruder"

**5.2. Configurar Payloads**

1. Na aba "Positions":
   - Selecionar parâmetro a ser testado (ex: `id`)
   - Clicar em "Add" para marcar posição
   - Selecionar attack type (ex: "Sniper")

2. Na aba "Payloads":
   - Selecionar "Payload set: 1"
   - Escolher "Payload type: Simple list"
   - Adicionar payloads:
     ```
     1' OR '1'='1
     1; DROP TABLE users--
     admin'--
     ' OR 1=1--
     ```

**5.3. Executar Ataque**

1. Clicar em "Start attack"
2. Observar resultados em tabela
3. Analisar respostas para identificar vulnerabilidades

**5.4. Analisar Resultados**

- Verificar status codes (200 vs 500)
- Verificar tamanho de resposta (diferente = possível vulnerabilidade)
- Verificar conteúdo de resposta (mensagens de erro, dados expostos)

### Passo 6: Executar Scan Automatizado

**6.1. Enviar Requisição para Scanner**

1. No Proxy ou Repeater, clicar com botão direito
2. Selecionar "Scan"
3. Ou ir em "Scanner" → "New scan"

**6.2. Configurar Scan**

1. Selecionar URL alvo
2. Escolher tipo de scan (Active ou Passive)
3. Configurar escopo (apenas URLs específicas)
4. Iniciar scan

**6.3. Analisar Resultados do Scan**

1. Ir para aba "Scanner"
2. Ver lista de vulnerabilidades encontradas
3. Clicar em cada vulnerabilidade para ver detalhes
4. Analisar evidência e recomendações

### Passo 7: Documentar Vulnerabilidades Encontradas

**7.1. Criar Relatório de Vulnerabilidades**

Para cada vulnerabilidade encontrada:

```markdown
## Vulnerabilidade: [Nome]

### Detalhes
- **Severidade**: High / Medium / Low
- **URL**: `http://app.com/api/users`
- **Método**: POST
- **Parâmetro**: `id`
- **CWE**: CWE-89 (SQL Injection)

### Como Encontrei
1. Interceptei requisição POST no Burp Suite
2. Modifiquei parâmetro `id` para `1' OR '1'='1`
3. Enviei requisição modificada
4. Observado: Resposta retornou dados de múltiplos usuários

### Evidência
```http
POST /api/users HTTP/1.1
Host: app.com
Content-Type: application/json

{"id": "1' OR '1'='1"}

Response: 200 OK
[
  {"id": 1, "name": "User 1"},
  {"id": 2, "name": "User 2"},
  {"id": 3, "name": "User 3"}
]
```

### Impacto
[Qual o impacto se explorado?]

### Correção
[Como corrigir?]
```

---

## Dicas

1. **Certificado CA**: Sempre instale certificado CA do Burp para testar HTTPS
2. **Interceptação**: Desative interceptação quando não precisar (pode ser lento)
3. **Repeater**: Use Repeater para testes repetidos e modificações incrementais
4. **Intruder**: Use Intruder para testes automatizados com múltiplos payloads
5. **Scanner**: Scanner automatizado é útil, mas testes manuais encontram mais
6. **Contextos**: Configure contextos no Burp para organizar testes
7. **Comparar respostas**: Compare respostas normais vs modificadas para encontrar diferenças

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] Burp Suite instalado e funcionando
- [ ] Proxy configurado no navegador
- [ ] Certificado CA instalado
- [ ] Requisições sendo interceptadas
- [ ] Requisições modificadas e testadas
- [ ] Repeater usado para testes repetidos
- [ ] Intruder usado para testes automatizados
- [ ] Scan automatizado executado
- [ ] Pelo menos 3 vulnerabilidades encontradas e documentadas

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Exercício 2.2.3: Integrar DAST no CI/CD
- Usar Burp Suite em testes de penetração
- Explorar funcionalidades avançadas do Burp Suite (Extensions, Collaborator)

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Screenshot do Burp Suite com requisições interceptadas
2. Relatório de 3 vulnerabilidades encontradas manualmente
3. Evidência de cada vulnerabilidade (requisições/respostas)
4. Dúvidas ou desafios encontrados

{% include exercise-submission-form.html %}

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Testes manuais em aplicação financeira hipotética

- **Foco especial**: Autenticação, autorização, manipulação de dados financeiros
- **Priorização**: Vulnerabilidades que afetam pagamentos são P1
- **Compliance**: Documentar todas as vulnerabilidades para auditoria PCI-DSS

Aplique os mesmos passos neste contexto hipotético, focando em vulnerabilidades críticas para o setor financeiro.

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 2.2 (DAST), Aplicação web para testar
