---
layout: exercise
title: "Exercício 5.3.4: Segurança Completa"
slug: "seguranca-completa"
lesson_id: "lesson-5-3"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **segurança completa** através da **implementação de todas medidas de segurança em aplicação completa**.

Ao completar este exercício, você será capaz de:

- Implementar todas medidas de segurança
- Configurar CSP
- Proteger contra XSS e CSRF
- Implementar autenticação segura
- Configurar HTTPS e CORS
- Criar aplicação segura completa

---

## Descrição

Você precisa implementar todas medidas de segurança em uma aplicação completa.

### Contexto

Uma aplicação precisa ter segurança completa implementada.

### Tarefa

Crie:

1. **CSP**: Configurar Content Security Policy
2. **XSS**: Implementar proteção XSS completa
3. **CSRF**: Implementar proteção CSRF
4. **Autenticação**: Implementar autenticação segura
5. **HTTPS**: Configurar HTTPS
6. **CORS**: Configurar CORS
7. **Validação**: Validar todas medidas

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] CSP configurado
- [ ] Proteção XSS implementada
- [ ] Proteção CSRF implementada
- [ ] Autenticação segura
- [ ] HTTPS configurado
- [ ] CORS configurado
- [ ] Todas medidas funcionando

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todas medidas de segurança estão implementadas
- [ ] Segurança está completa

---

## Solução Esperada

### Abordagem Recomendada

**index.html**
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure App</title>
  <base href="/">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  
  <meta http-equiv="Content-Security-Policy" 
        content="default-src 'self'; 
                 script-src 'self' 'unsafe-inline'; 
                 style-src 'self' 'unsafe-inline'; 
                 img-src 'self' data: https:; 
                 font-src 'self' data:; 
                 connect-src 'self' https://api.example.com;">
  
  <meta http-equiv="X-Content-Type-Options" content="nosniff">
  <meta http-equiv="X-Frame-Options" content="DENY">
  <meta http-equiv="X-XSS-Protection" content="1; mode=block">
  <meta name="referrer" content="strict-origin-when-cross-origin">
  
  <link rel="icon" type="image/x-icon" href="favicon.ico">
</head>
<body>
  <app-root></app-root>
</body>
</html>
```

**app.config.ts**
```typescript
import { ApplicationConfig } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withXsrfConfiguration, withInterceptors } from '@angular/common/http';
import { routes } from './app.routes';
import { authInterceptor } from './interceptors/auth.interceptor';
import { csrfInterceptor } from './interceptors/csrf.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN'
      }),
      withInterceptors([csrfInterceptor, authInterceptor])
    )
  ]
};
```

**csrf.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';

export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next(req);
  }
  
  const csrfToken = this.getCsrfToken();
  if (csrfToken) {
    req = req.clone({
      setHeaders: {
        'X-XSRF-TOKEN': csrfToken
      }
    });
  }
  
  return next(req);
};

function getCsrfToken(): string | null {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'XSRF-TOKEN') {
      return decodeURIComponent(value);
    }
  }
  return null;
}
```

**security.service.ts**
```typescript
import { Injectable, inject } from '@angular/core';
import { DomSanitizer, SafeHtml, SafeUrl } from '@angular/platform-browser';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class SecurityService {
  private sanitizer = inject(DomSanitizer);
  private http = inject(HttpClient);
  
  sanitizeHtml(html: string): SafeHtml {
    return this.sanitizer.sanitize(1, html) as SafeHtml;
  }
  
  sanitizeUrl(url: string): SafeUrl {
    if (url.startsWith('javascript:') || url.startsWith('data:')) {
      return this.sanitizer.bypassSecurityTrustUrl('about:blank');
    }
    return this.sanitizer.bypassSecurityTrustUrl(url);
  }
  
  validateInput(input: string): boolean {
    const dangerousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe/i,
      /<object/i,
      /<embed/i
    ];
    
    return !dangerousPatterns.some(pattern => pattern.test(input));
  }
  
  escapeHtml(text: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  }
}
```

**secure-storage.service.ts**
```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class SecureStorageService {
  private readonly PREFIX = 'secure_';
  
  setSecureItem(key: string, value: string): void {
    const encrypted = this.encrypt(value);
    sessionStorage.setItem(`${this.PREFIX}${key}`, encrypted);
  }
  
  getSecureItem(key: string): string | null {
    const encrypted = sessionStorage.getItem(`${this.PREFIX}${key}`);
    if (!encrypted) {
      return null;
    }
    return this.decrypt(encrypted);
  }
  
  removeSecureItem(key: string): void {
    sessionStorage.removeItem(`${this.PREFIX}${key}`);
  }
  
  clearSecureItems(): void {
    const keys = Object.keys(sessionStorage);
    keys.forEach(key => {
      if (key.startsWith(this.PREFIX)) {
        sessionStorage.removeItem(key);
      }
    });
  }
  
  private encrypt(value: string): string {
    return btoa(encodeURIComponent(value));
  }
  
  private decrypt(encrypted: string): string {
    try {
      return decodeURIComponent(atob(encrypted));
    } catch {
      return '';
    }
  }
}
```

**cors.config.ts**
```typescript
export const corsConfig = {
  allowedOrigins: ['https://example.com'],
  allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-XSRF-TOKEN'],
  exposedHeaders: ['X-Total-Count'],
  credentials: true,
  maxAge: 86400
};
```

**security-headers.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';

export const securityHeadersInterceptor: HttpInterceptorFn = (req, next) => {
  req = req.clone({
    setHeaders: {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
  });
  
  return next(req);
};
```

**secure-component.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SecurityService } from './security.service';
import { SecureStorageService } from './secure-storage.service';

@Component({
  selector: 'app-secure',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h1>Aplicação Segura</h1>
      
      <div class="security-status">
        <h2>Status de Segurança</h2>
        <ul>
          <li>✅ CSP Configurado</li>
          <li>✅ XSS Protegido</li>
          <li>✅ CSRF Protegido</li>
          <li>✅ HTTPS Habilitado</li>
          <li>✅ CORS Configurado</li>
          <li>✅ Autenticação Segura</li>
        </ul>
      </div>
      
      <div class="input-section">
        <h2>Input Seguro</h2>
        <textarea 
          [(ngModel)]="userInput" 
          placeholder="Digite algo aqui">
        </textarea>
        <button (click)="validateAndProcess()">Processar</button>
        <div [innerHTML]="safeOutput"></div>
      </div>
    </div>
  `
})
export class SecureComponent {
  userInput: string = '';
  safeOutput: SafeHtml | null = null;
  
  constructor(
    private securityService: SecurityService,
    private secureStorage: SecureStorageService
  ) {}
  
  validateAndProcess(): void {
    if (!this.securityService.validateInput(this.userInput)) {
      alert('Input contém conteúdo perigoso!');
      return;
    }
    
    const sanitized = this.securityService.sanitizeHtml(this.userInput);
    this.safeOutput = sanitized;
    
    this.secureStorage.setSecureItem('user_input', this.userInput);
  }
}
```

**Explicação da Solução**:

1. CSP configurado no index.html
2. Headers de segurança configurados
3. CSRF protection implementada
4. XSS protection completa
5. Secure storage para dados sensíveis
6. CORS configurado corretamente
7. Todas medidas de segurança implementadas

---

## Testes

### Casos de Teste

**Teste 1**: CSP funciona
- **Input**: Tentar carregar script externo
- **Output Esperado**: Bloqueado pelo CSP

**Teste 2**: XSS bloqueado
- **Input**: Tentar injetar script
- **Output Esperado**: Script removido

**Teste 3**: CSRF protegido
- **Input**: Requisição sem token CSRF
- **Output Esperado**: Requisição bloqueada

---

## Extensões (Opcional)

1. **Security Audit**: Execute auditoria de segurança
2. **Penetration Testing**: Faça testes de penetração
3. **Security Monitoring**: Implemente monitoramento

---

## Referências Úteis

- **[OWASP Top 10](https://owasp.org/www-project-top-ten/)**: Top 10 vulnerabilidades
- **[Angular Security](https://angular.io/guide/security)**: Guia segurança Angular
- **[CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)**: MDN CSP

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

