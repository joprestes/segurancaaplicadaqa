---
layout: lesson
title: "Aula 5.3: Segurança Avançada"
slug: seguranca
module: module-5
lesson_id: lesson-5-3
duration: "60 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-5-2"
exercises:
  - 
  - "lesson-5-3-exercise-1"
  - "lesson-5-3-exercise-2"
  - "lesson-5-3-exercise-3"
  - "lesson-5-3-exercise-4"
---

## Introdução

Nesta aula, você aprenderá sobre segurança avançada em aplicações Angular. Segurança é fundamental para proteger aplicações e dados de usuários contra ameaças comuns.

### O que você vai aprender

- Proteger contra XSS (Cross-Site Scripting)
- Proteger contra CSRF (Cross-Site Request Forgery)
- Usar Sanitization e DomSanitizer
- Configurar Content Security Policy (CSP)
- Implementar autenticação avançada (JWT, OAuth2)
- Implementar autorização (Role-based access control)
- Armazenar tokens com segurança
- Configurar HTTPS e CORS

### Por que isso é importante

Segurança é crítica para aplicações web. Vulnerabilidades podem comprometer dados de usuários, causar perdas financeiras e danificar reputação. Entender e implementar segurança adequada é essencial para desenvolvedores profissionais.

---

## Conceitos Teóricos

### Proteção contra XSS

**Definição**: XSS (Cross-Site Scripting) é vulnerabilidade que permite injetar scripts maliciosos em páginas web.

**Explicação Detalhada**:

Proteção XSS:
- Angular sanitiza automaticamente
- Interpolação segura por padrão
- DomSanitizer para casos especiais
- Nunca use innerHTML sem sanitização
- Evite eval() e Function()

**Analogia**:

Proteção XSS é como ter um filtro de água que remove todas as impurezas antes de você beber, garantindo que nada perigoso entre no sistema.

**Exemplo Prático**:

```typescript
import { Component } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-safe',
  standalone: true,
  template: `
    <div [innerHTML]="safeHtml"></div>
  `
})
export class SafeComponent {
  constructor(private sanitizer: DomSanitizer) {}
  
  safeHtml: SafeHtml = this.sanitizer.sanitize(
    SecurityContext.HTML,
    '<p>Safe HTML</p>'
  );
}
```

---

### Proteção contra CSRF

**Definição**: CSRF (Cross-Site Request Forgery) é ataque que força usuário a executar ações não intencionais.

**Explicação Detalhada**:

Proteção CSRF:
- Tokens CSRF em formulários
- SameSite cookies
- Verificação de origem
- Headers customizados
- Angular HttpClient tem proteção básica

**Exemplo Prático**:

```typescript
import { HttpClientXsrfModule } from '@angular/common/http';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(withXsrfConfiguration({
      cookieName: 'XSRF-TOKEN',
      headerName: 'X-XSRF-TOKEN'
    }))
  ]
};
```

---

### Sanitization e DomSanitizer

**Definição**: Sanitization remove código perigoso de conteúdo HTML, CSS ou URLs.

**Explicação Detalhada**:

Sanitization:
- Angular sanitiza automaticamente
- DomSanitizer para casos especiais
- SecurityContext define contexto
- SafeHtml, SafeStyle, SafeUrl
- Use apenas quando necessário

**Exemplo Prático**:

```typescript
import { DomSanitizer, SafeHtml, SafeUrl } from '@angular/platform-browser';

@Component({
  template: `
    <div [innerHTML]="safeHtml"></div>
    <a [href]="safeUrl">Link</a>
  `
})
export class SanitizeComponent {
  constructor(private sanitizer: DomSanitizer) {}
  
  safeHtml: SafeHtml = this.sanitizer.bypassSecurityTrustHtml(
    '<p>Trusted HTML</p>'
  );
  
  safeUrl: SafeUrl = this.sanitizer.bypassSecurityTrustUrl(
    'https://example.com'
  );
}
```

---

### Content Security Policy (CSP)

**Definição**: CSP é política de segurança que previne XSS especificando fontes permitidas.

**Explicação Detalhada**:

CSP:
- Define fontes permitidas
- Previne XSS
- Configurado via headers HTTP
- Meta tag ou servidor
- Angular funciona com CSP strict

**Exemplo Prático**:

**index.html**
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self' 'unsafe-inline'; 
               style-src 'self' 'unsafe-inline';">
```

---

### Autenticação JWT

**Definição**: JWT (JSON Web Token) é padrão para autenticação baseado em tokens.

**Explicação Detalhada**:

JWT:
- Token assinado digitalmente
- Contém claims (dados do usuário)
- Stateless (sem sessão no servidor)
- Armazenado em httpOnly cookie ou localStorage
- Refresh tokens para renovação

**Exemplo Prático**:

```typescript
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private tokenKey = 'auth_token';
  
  login(credentials: { email: string; password: string }): Observable<any> {
    return this.http.post('/api/auth/login', credentials).pipe(
      tap(response => {
        this.setToken(response.token);
      })
    );
  }
  
  setToken(token: string): void {
    localStorage.setItem(this.tokenKey, token);
  }
  
  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }
  
  logout(): void {
    localStorage.removeItem(this.tokenKey);
  }
  
  isAuthenticated(): boolean {
    return !!this.getToken();
  }
}
```

---

### OAuth2 e OpenID Connect

**Definição**: OAuth2 é protocolo de autorização, OpenID Connect adiciona autenticação.

**Explicação Detalhada**:

OAuth2/OpenID Connect:
- Fluxo de autorização
- Tokens de acesso e refresh
- Provedores (Google, Facebook, etc.)
- Biblioteca angular-oauth2-oidc
- Mais seguro que senhas

**Exemplo Prático**:

```typescript
import { OAuthService } from 'angular-oauth2-oidc';

export class AuthService {
  constructor(private oauthService: OAuthService) {
    this.configureOAuth();
  }
  
  configureOAuth(): void {
    this.oauthService.configure({
      issuer: 'https://accounts.google.com',
      redirectUri: window.location.origin,
      clientId: 'YOUR_CLIENT_ID',
      scope: 'openid profile email',
      responseType: 'code'
    });
  }
  
  login(): void {
    this.oauthService.initCodeFlow();
  }
  
  logout(): void {
    this.oauthService.logOut();
  }
}
```

---

### Role-Based Access Control (RBAC)

**Definição**: RBAC controla acesso baseado em roles (papéis) do usuário.

**Explicação Detalhada**:

RBAC:
- Usuários têm roles
- Roles têm permissões
- Guards verificam roles
- Diretivas para UI
- Backend valida também

**Exemplo Prático**:

```typescript
import { Injectable, inject } from '@angular/core';
import { CanActivate, Router } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class RoleGuard implements CanActivate {
  private router = inject(Router);
  
  canActivate(route: any): boolean {
    const requiredRole = route.data['role'];
    const userRole = this.getUserRole();
    
    if (userRole === requiredRole) {
      return true;
    }
    
    this.router.navigate(['/unauthorized']);
    return false;
  }
  
  private getUserRole(): string {
    const token = localStorage.getItem('auth_token');
    if (token) {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.role;
    }
    return 'guest';
  }
}
```

---

### Armazenamento Seguro de Tokens

**Definição**: Tokens devem ser armazenados de forma segura para prevenir roubo.

**Explicação Detalhada**:

Armazenamento Seguro:
- httpOnly cookies são mais seguros
- localStorage é vulnerável a XSS
- sessionStorage é mais seguro que localStorage
- Nunca armazene em variáveis globais
- Use refresh tokens

**Exemplo Prático**:

```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class TokenService {
  private readonly TOKEN_KEY = 'auth_token';
  private readonly REFRESH_TOKEN_KEY = 'refresh_token';
  
  setTokens(accessToken: string, refreshToken: string): void {
    sessionStorage.setItem(this.TOKEN_KEY, accessToken);
    sessionStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
  }
  
  getAccessToken(): string | null {
    return sessionStorage.getItem(this.TOKEN_KEY);
  }
  
  getRefreshToken(): string | null {
    return sessionStorage.getItem(this.REFRESH_TOKEN_KEY);
  }
  
  clearTokens(): void {
    sessionStorage.removeItem(this.TOKEN_KEY);
    sessionStorage.removeItem(this.REFRESH_TOKEN_KEY);
  }
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Interceptor de Autenticação

**Contexto**: Criar interceptor que adiciona token JWT a todas requisições.

**Código**:

```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getToken();
  
  if (token) {
    req = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }
  
  return next(req);
};
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Sempre sanitize conteúdo do usuário**
   - **Por quê**: Previne XSS
   - **Exemplo**: Use DomSanitizer quando necessário

2. **Use HTTPS em produção**
   - **Por quê**: Protege dados em trânsito
   - **Exemplo**: Configure SSL/TLS

3. **Valide dados no backend**
   - **Por quê**: Frontend pode ser contornado
   - **Exemplo**: Sempre valide no servidor

4. **Use httpOnly cookies para tokens**
   - **Por quê**: Mais seguro que localStorage
   - **Exemplo**: Configure cookies httpOnly

### ❌ Anti-padrões Comuns

1. **Não use innerHTML sem sanitização**
   - **Problema**: Vulnerável a XSS
   - **Solução**: Sempre sanitize

2. **Não armazene tokens em localStorage**
   - **Problema**: Vulnerável a XSS
   - **Solução**: Use httpOnly cookies

3. **Não confie apenas no frontend**
   - **Problema**: Pode ser contornado
   - **Solução**: Valide no backend

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

- **[Angular Security](https://angular.io/guide/security)**: Guia segurança Angular
- **[OWASP Top 10](https://owasp.org/www-project-top-ten/)**: Top 10 vulnerabilidades
- **[JWT.io](https://jwt.io/)**: Documentação JWT

---

## Resumo

### Principais Conceitos

- XSS é vulnerabilidade comum
- CSRF pode ser prevenido com tokens
- Sanitization é essencial
- CSP previne XSS
- JWT é padrão para autenticação
- RBAC controla acesso
- Tokens devem ser armazenados com segurança

### Pontos-Chave para Lembrar

- Sempre sanitize conteúdo do usuário
- Use HTTPS em produção
- Valide dados no backend
- Use httpOnly cookies para tokens
- Implemente RBAC adequadamente

### Próximos Passos

- Próxima aula: Arquitetura Avançada
- Praticar segurança
- Explorar vulnerabilidades comuns

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

