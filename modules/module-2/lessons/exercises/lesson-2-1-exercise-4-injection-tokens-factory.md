---
layout: exercise
title: "Exercício 2.1.4: InjectionTokens e Factory Providers"
slug: "injection-tokens-factory"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **InjectionTokens e Factory Providers** através da **criação de serviço configurável usando tokens e factory**.

Ao completar este exercício, você será capaz de:

- Criar e usar InjectionTokens
- Implementar factory providers
- Configurar serviços dinamicamente
- Injetar valores primitivos e objetos

---

## Descrição

Você precisa criar um serviço HTTP configurável que usa InjectionToken para URL da API e factory provider para criar instância customizada.

### Contexto

Uma aplicação precisa de serviços configuráveis que podem ter diferentes configurações em diferentes ambientes ou contextos.

### Tarefa

Crie:

1. **InjectionToken**: Para URL da API
2. **Interface**: Para configuração do serviço
3. **Factory Provider**: Para criar serviço com configuração
4. **Serviço Configurável**: Que usa o token
5. **Uso**: Configure em diferentes componentes

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] InjectionToken criado
- [ ] Interface de configuração definida
- [ ] Factory provider implementado
- [ ] Serviço usa token injetado
- [ ] Configuração funciona em diferentes contextos
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Type safety mantido
- [ ] Factory é bem estruturada
- [ ] Código é reutilizável

---

## Solução Esperada

### Abordagem Recomendada

**api-config.ts**
```typescript
import { InjectionToken } from '@angular/core';

export interface ApiConfig {
  baseUrl: string;
  timeout: number;
  retries: number;
  apiKey?: string;
}

export const API_CONFIG = new InjectionToken<ApiConfig>('API_CONFIG');

export const DEFAULT_API_CONFIG: ApiConfig = {
  baseUrl: 'https://api.example.com',
  timeout: 5000,
  retries: 3
};
```

**api.service.ts**
```typescript
import { Injectable, Inject, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API_CONFIG, ApiConfig } from './api-config';

@Injectable({
  providedIn: 'root',
  useFactory: (http: HttpClient, config: ApiConfig) => {
    return new ApiService(http, config);
  },
  deps: [HttpClient, API_CONFIG]
})
export class ApiService {
  constructor(
    private http: HttpClient,
    @Inject(API_CONFIG) private config: ApiConfig
  ) {
    console.log('ApiService criado com config:', this.config);
  }
  
  getBaseUrl(): string {
    return this.config.baseUrl;
  }
  
  getTimeout(): number {
    return this.config.timeout;
  }
  
  get<T>(endpoint: string): Observable<T> {
    const url = `${this.config.baseUrl}${endpoint}`;
    return this.http.get<T>(url);
  }
  
  post<T>(endpoint: string, data: any): Observable<T> {
    const url = `${this.config.baseUrl}${endpoint}`;
    return this.http.post<T>(url, data);
  }
}
```

**app.config.ts**
```typescript
import { ApplicationConfig, provideZoneJsChangeDetection } from '@angular/core';
import { provideHttpClient } from '@angular/common/http';
import { API_CONFIG, DEFAULT_API_CONFIG } from './api-config';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneJsChangeDetection({ eventCoalescing: true }),
    provideHttpClient(),
    {
      provide: API_CONFIG,
      useValue: DEFAULT_API_CONFIG
    }
  ]
};
```

**feature.component.ts**
```typescript
import { Component } from '@angular/core';
import { ApiService } from './api.service';
import { API_CONFIG, ApiConfig } from './api-config';

@Component({
  selector: 'app-feature',
  standalone: true,
  providers: [
    {
      provide: API_CONFIG,
      useValue: {
        baseUrl: 'https://api.feature.com',
        timeout: 10000,
        retries: 5,
        apiKey: 'feature-key'
      }
    }
  ],
  template: `
    <div>
      <h2>Feature Component</h2>
      <p>API URL: {{ apiService.getBaseUrl() }}</p>
      <p>Timeout: {{ apiService.getTimeout() }}ms</p>
    </div>
  `
})
export class FeatureComponent {
  apiService = inject(ApiService);
}
```

**Explicação da Solução**:

1. InjectionToken criado para type safety
2. Interface define estrutura de configuração
3. Factory provider cria serviço com dependências
4. Serviço injeta configuração via token
5. Diferentes componentes podem ter configurações diferentes
6. Configuração global via app.config

---

## Testes

### Casos de Teste

**Teste 1**: Configuração padrão funciona
- **Input**: Usar serviço sem providers customizados
- **Output Esperado**: Configuração padrão aplicada

**Teste 2**: Configuração customizada funciona
- **Input**: Provider customizado no componente
- **Output Esperado**: Configuração customizada aplicada

**Teste 3**: Factory cria instância correta
- **Input**: Serviço injetado
- **Output Esperado**: Instância criada com configuração correta

---

## Extensões (Opcional)

1. **Múltiplos Ambientes**: Configure para dev, staging, prod
2. **Validação**: Adicione validação de configuração
3. **Hot Reload**: Suporte para mudança de configuração em runtime

---

## Referências Úteis

- **[InjectionToken](https://angular.io/api/core/InjectionToken)**: Documentação oficial
- **[Factory Providers](https://angular.io/guide/dependency-injection-providers#factory-providers)**: Guia de factory providers

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

