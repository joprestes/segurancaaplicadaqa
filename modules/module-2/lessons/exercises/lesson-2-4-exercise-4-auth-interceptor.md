---
layout: exercise
title: "Exercício 2.4.4: Auth Interceptor"
slug: "auth-interceptor"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Auth Interceptor** através da **implementação de interceptor que adiciona token de autenticação e trata erros 401**.

Ao completar este exercício, você será capaz de:

- Criar interceptor de autenticação
- Adicionar token em requisições
- Tratar erros 401 (não autorizado)
- Redirecionar para login quando necessário
- Gerenciar tokens de autenticação

---

## Descrição

Você precisa criar um interceptor que adiciona token de autenticação em todas as requisições e trata erros 401 redirecionando para login.

### Contexto

Uma aplicação precisa adicionar token de autenticação automaticamente em todas as requisições e tratar expiração de token.

### Tarefa

Crie:

1. **AuthService**: Serviço que gerencia tokens
2. **Auth Interceptor**: Interceptor que adiciona token
3. **401 Handling**: Tratamento de erros 401
4. **Redirect**: Redirecionamento para login

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] AuthService criado com gerenciamento de token
- [ ] AuthInterceptor adiciona token nas requisições
- [ ] Erros 401 são tratados
- [ ] Redirecionamento para login funciona
- [ ] Token é removido em caso de 401
- [ ] Interceptor funciona corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Segurança está implementada
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**auth.service.ts**
```typescript
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private tokenKey = 'auth_token';
  
  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }
  
  setToken(token: string): void {
    localStorage.setItem(this.tokenKey, token);
  }
  
  removeToken(): void {
    localStorage.removeItem(this.tokenKey);
  }
  
  isAuthenticated(): boolean {
    return !!this.getToken();
  }
}
```

**auth.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  const token = authService.getToken();
  
  let clonedRequest = req;
  
  if (token) {
    clonedRequest = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }
  
  return next(clonedRequest).pipe(
    catchError((error) => {
      if (error.status === 401) {
        authService.removeToken();
        router.navigate(['/login'], {
          queryParams: { returnUrl: router.url }
        });
      }
      return throwError(() => error);
    })
  );
};
```

**main.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';
import { authInterceptor } from './app/interceptors/auth.interceptor';

bootstrapApplication(AppComponent, {
  providers: [
    provideHttpClient(
      withInterceptors([authInterceptor])
    ),
    provideRouter(routes)
  ]
});
```

**login.component.ts**
```typescript
import { Component } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule],
  template: `
    <form (ngSubmit)="login()">
      <h2>Login</h2>
      <input [(ngModel)]="email" placeholder="Email" name="email">
      <input [(ngModel)]="password" type="password" placeholder="Senha" name="password">
      <button type="submit">Entrar</button>
    </form>
  `
})
export class LoginComponent {
  email = '';
  password = '';
  returnUrl = '/';
  
  constructor(
    private authService: AuthService,
    private router: Router,
    private route: ActivatedRoute
  ) {
    this.route.queryParams.subscribe(params => {
      this.returnUrl = params['returnUrl'] || '/';
    });
  }
  
  login(): void {
    if (this.email && this.password) {
      const mockToken = 'mock-jwt-token-' + Date.now();
      this.authService.setToken(mockToken);
      this.router.navigate([this.returnUrl]);
    }
  }
}
```

**Explicação da Solução**:

1. AuthService gerencia token no localStorage
2. authInterceptor adiciona token em todas requisições
3. Token adicionado via setHeaders
4. Erro 401 remove token e redireciona
5. returnUrl preserva destino original
6. Interceptor configurado com withInterceptors

---

## Testes

### Casos de Teste

**Teste 1**: Token é adicionado
- **Input**: Fazer requisição com token
- **Output Esperado**: Header Authorization presente

**Teste 2**: 401 redireciona
- **Input**: Receber erro 401
- **Output Esperado**: Redireciona para /login

**Teste 3**: Token é removido em 401
- **Input**: Receber erro 401
- **Output Esperado**: Token removido do localStorage

---

## Extensões (Opcional)

1. **Token Refresh**: Implemente refresh de token
2. **Token Expiration**: Verifique expiração antes de usar
3. **Multiple Tokens**: Suporte para diferentes tipos de token

---

## Referências Úteis

- **[Auth Interceptors](https://angular.io/guide/http-intercept-requests-and-responses#interceptor-use-cases)**: Guia interceptors de auth
- **[Security](https://angular.io/guide/security)**: Guia segurança Angular

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

