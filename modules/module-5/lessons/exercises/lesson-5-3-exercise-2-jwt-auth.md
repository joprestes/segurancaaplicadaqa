---
layout: exercise
title: "Exercício 5.3.2: Autenticação JWT"
slug: "jwt-auth"
lesson_id: "lesson-5-3"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **autenticação JWT** através da **implementação de autenticação completa com JWT**.

Ao completar este exercício, você será capaz de:

- Implementar login com JWT
- Gerenciar tokens JWT
- Criar interceptor de autenticação
- Implementar logout
- Proteger rotas com guards
- Renovar tokens expirados

---

## Descrição

Você precisa implementar sistema completo de autenticação JWT.

### Contexto

Uma aplicação precisa autenticar usuários usando JWT.

### Tarefa

Crie:

1. **AuthService**: Criar serviço de autenticação
2. **Login**: Implementar login
3. **Interceptor**: Criar interceptor JWT
4. **Guards**: Proteger rotas
5. **Logout**: Implementar logout

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] AuthService criado
- [ ] Login implementado
- [ ] Interceptor JWT criado
- [ ] Guards implementados
- [ ] Logout funciona
- [ ] Tokens gerenciados corretamente

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Autenticação está implementada corretamente
- [ ] Segurança está adequada

---

## Solução Esperada

### Abordagem Recomendada

**auth.service.ts**
```typescript
import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap, catchError, throwError } from 'rxjs';

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  refreshToken: string;
  user: {
    id: number;
    email: string;
    name: string;
  };
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);
  private readonly TOKEN_KEY = 'auth_token';
  private readonly REFRESH_TOKEN_KEY = 'refresh_token';
  
  isAuthenticated = signal(false);
  currentUser = signal<any>(null);
  
  constructor() {
    this.checkAuthStatus();
  }
  
  login(credentials: LoginCredentials): Observable<AuthResponse> {
    return this.http.post<AuthResponse>('/api/auth/login', credentials).pipe(
      tap(response => {
        this.setTokens(response.token, response.refreshToken);
        this.currentUser.set(response.user);
        this.isAuthenticated.set(true);
      }),
      catchError(error => {
        console.error('Login failed:', error);
        return throwError(() => error);
      })
    );
  }
  
  logout(): void {
    this.clearTokens();
    this.currentUser.set(null);
    this.isAuthenticated.set(false);
    this.router.navigate(['/login']);
  }
  
  setTokens(token: string, refreshToken: string): void {
    sessionStorage.setItem(this.TOKEN_KEY, token);
    sessionStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
  }
  
  getToken(): string | null {
    return sessionStorage.getItem(this.TOKEN_KEY);
  }
  
  getRefreshToken(): string | null {
    return sessionStorage.getItem(this.REFRESH_TOKEN_KEY);
  }
  
  clearTokens(): void {
    sessionStorage.removeItem(this.TOKEN_KEY);
    sessionStorage.removeItem(this.REFRESH_TOKEN_KEY);
  }
  
  isTokenExpired(): boolean {
    const token = this.getToken();
    if (!token) {
      return true;
    }
    
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const exp = payload.exp * 1000;
      return Date.now() >= exp;
    } catch {
      return true;
    }
  }
  
  refreshToken(): Observable<AuthResponse> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      return throwError(() => new Error('No refresh token'));
    }
    
    return this.http.post<AuthResponse>('/api/auth/refresh', { refreshToken }).pipe(
      tap(response => {
        this.setTokens(response.token, response.refreshToken);
      })
    );
  }
  
  private checkAuthStatus(): void {
    const token = this.getToken();
    if (token && !this.isTokenExpired()) {
      this.isAuthenticated.set(true);
      this.loadUserFromToken(token);
    }
  }
  
  private loadUserFromToken(token: string): void {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      this.currentUser.set({
        id: payload.sub,
        email: payload.email,
        name: payload.name
      });
    } catch {
      this.logout();
    }
  }
}
```

**auth.interceptor.ts**
```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from './auth.service';
import { Router } from '@angular/router';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  const token = authService.getToken();
  
  if (token && !authService.isTokenExpired()) {
    req = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }
  
  return next(req).pipe(
    catchError(error => {
      if (error.status === 401) {
        const refreshToken = authService.getRefreshToken();
        if (refreshToken) {
          return authService.refreshToken().pipe(
            switchMap(response => {
              const clonedReq = req.clone({
                setHeaders: {
                  Authorization: `Bearer ${response.token}`
                }
              });
              return next(clonedReq);
            }),
            catchError(() => {
              authService.logout();
              router.navigate(['/login']);
              return throwError(() => error);
            })
          );
        } else {
          authService.logout();
          router.navigate(['/login']);
        }
      }
      return throwError(() => error);
    })
  );
};
```

**auth.guard.ts**
```typescript
import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  if (authService.isAuthenticated() && !authService.isTokenExpired()) {
    return true;
  }
  
  router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
  return false;
};
```

**login.component.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  template: `
    <div class="login-container">
      <form [formGroup]="loginForm" (ngSubmit)="onSubmit()">
        <h2>Login</h2>
        
        <div class="form-group">
          <label>Email</label>
          <input 
            type="email" 
            formControlName="email"
            placeholder="seu@email.com">
          @if (loginForm.get('email')?.hasError('required') && loginForm.get('email')?.touched) {
            <span class="error">Email é obrigatório</span>
          }
        </div>
        
        <div class="form-group">
          <label>Senha</label>
          <input 
            type="password" 
            formControlName="password"
            placeholder="Senha">
          @if (loginForm.get('password')?.hasError('required') && loginForm.get('password')?.touched) {
            <span class="error">Senha é obrigatória</span>
          }
        </div>
        
        @if (errorMessage()) {
          <div class="error-message">{{ errorMessage() }}</div>
        }
        
        <button 
          type="submit" 
          [disabled]="loginForm.invalid || loading()">
          {{ loading() ? 'Entrando...' : 'Entrar' }}
        </button>
      </form>
    </div>
  `
})
export class LoginComponent {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  private router = inject(Router);
  
  loading = signal(false);
  errorMessage = signal<string | null>(null);
  
  loginForm = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', Validators.required]
  });
  
  onSubmit(): void {
    if (this.loginForm.invalid) {
      return;
    }
    
    this.loading.set(true);
    this.errorMessage.set(null);
    
    this.authService.login(this.loginForm.value as any).subscribe({
      next: () => {
        this.router.navigate(['/dashboard']);
      },
      error: (error) => {
        this.errorMessage.set(error.error?.message || 'Erro ao fazer login');
        this.loading.set(false);
      }
    });
  }
}
```

**Explicação da Solução**:

1. AuthService gerencia autenticação
2. Tokens armazenados em sessionStorage
3. Interceptor adiciona token às requisições
4. Guard protege rotas
5. Refresh token renova tokens expirados
6. Logout limpa tokens e redireciona

---

## Testes

### Casos de Teste

**Teste 1**: Login funciona
- **Input**: Credenciais válidas
- **Output Esperado**: Token armazenado, usuário autenticado

**Teste 2**: Interceptor funciona
- **Input**: Requisição HTTP
- **Output Esperado**: Token adicionado ao header

**Teste 3**: Guard protege rotas
- **Input**: Acessar rota protegida sem login
- **Output Esperado**: Redirecionado para login

---

## Extensões (Opcional)

1. **Remember Me**: Implemente "Lembrar-me"
2. **Social Login**: Adicione login social
3. **2FA**: Implemente autenticação de dois fatores

---

## Referências Úteis

- **[JWT.io](https://jwt.io/)**: Documentação JWT
- **[HTTP Interceptors](https://angular.io/guide/http-intercept-requests-and-responses)**: Guia interceptors

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

