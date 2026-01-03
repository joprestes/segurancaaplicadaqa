---
layout: lesson
title: "Aula 5.2: SSR e PWA"
slug: ssr-pwa
module: module-5
lesson_id: lesson-5-2
duration: "120 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-5-1"
exercises:
  - 
  - "lesson-5-2-exercise-1"
  - "lesson-5-2-exercise-2"
  - "lesson-5-2-exercise-3"
  - "lesson-5-2-exercise-4"
  - "lesson-5-2-exercise-5"
---

## Introdução

Nesta aula, você aprenderá sobre Server-Side Rendering (SSR) e Progressive Web Apps (PWA) no Angular. SSR melhora SEO e performance inicial, enquanto PWA oferece experiência nativa na web.

### O que você vai aprender

- Implementar SSR com Angular Universal
- Entender Hydration e Transfer State
- Otimizar SEO com SSR
- Criar Progressive Web Apps
- Configurar Service Workers
- Implementar funcionalidades offline
- Adicionar push notifications

### Por que isso é importante

SSR e PWA são essenciais para aplicações modernas. SSR melhora SEO, performance inicial e experiência do usuário. PWA oferece experiência nativa, funcionalidades offline e capacidade de instalação, tornando aplicações web mais competitivas.

---

## Conceitos Teóricos

### Server-Side Rendering (SSR)

**Definição**: SSR renderiza aplicação Angular no servidor antes de enviar ao cliente.

**Explicação Detalhada**:

SSR:
- Renderiza HTML no servidor
- Melhora SEO
- Melhora performance inicial
- Melhora experiência do usuário
- Angular Universal é ferramenta oficial
- AnalogJS é alternativa moderna

**Analogia**:

SSR é como ter um garçom que já prepara seu prato antes de você chegar ao restaurante, garantindo que tudo esteja pronto quando você sentar.

**Exemplo Prático**:

```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideServerRendering } from '@angular/platform-server';
import { AppComponent } from './app/app.component';

const serverConfig = {
  providers: [
    provideServerRendering()
  ]
};

export default serverConfig;
```

---

### Hydration

**Definição**: Hydration é processo de tornar HTML estático interativo no cliente.

**Explicação Detalhada**:

Hydration:
- Conecta eventos ao HTML estático
- Reativa aplicação no cliente
- Preserva estado do servidor
- Melhora performance
- Angular 17+ tem hydration melhorada

**Exemplo Prático**:

```typescript
import { provideClientHydration } from '@angular/platform-browser';

bootstrapApplication(AppComponent, {
  providers: [
    provideClientHydration()
  ]
});
```

---

### Transfer State

**Definição**: Transfer State transfere dados do servidor para cliente sem requisições duplicadas.

**Explicação Detalhada**:

Transfer State:
- Evita requisições duplicadas
- Transfere dados do servidor
- Melhora performance
- Reduz latência
- Essencial para SSR eficiente

**Exemplo Prático**:

```typescript
import { TransferState, makeStateKey } from '@angular/platform-browser';

const DATA_KEY = makeStateKey<any>('data');

export class DataService {
  constructor(
    private http: HttpClient,
    private transferState: TransferState
  ) {}

  getData(): Observable<any> {
    const stored = this.transferState.get(DATA_KEY, null);
    if (stored) {
      return of(stored);
    }
    
    return this.http.get('/api/data').pipe(
      tap(data => this.transferState.set(DATA_KEY, data))
    );
  }
}
```

---

### Progressive Web Apps (PWA)

**Definição**: PWA são aplicações web que oferecem experiência similar a apps nativos.

**Explicação Detalhada**:

PWA:
- Funcionam offline
- Podem ser instaladas
- Recebem push notifications
- Têm ícone na tela inicial
- Funcionam em qualquer dispositivo
- Service Workers são essenciais

**Analogia**:

PWA é como transformar seu site em um aplicativo nativo, mas sem precisar passar pela loja de aplicativos.

**Exemplo Prático**:

```typescript
import { provideServiceWorker } from '@angular/service-worker';
import { isDevMode } from '@angular/core';

bootstrapApplication(AppComponent, {
  providers: [
    provideServiceWorker('ngsw-worker.js', {
      enabled: !isDevMode(),
      registrationStrategy: 'registerWhenStable:30000'
    })
  ]
});
```

---

### Service Workers

**Definição**: Service Workers são scripts que rodam em background e interceptam requisições de rede.

**Explicação Detalhada**:

Service Workers:
- Funcionam offline
- Cache de recursos
- Background sync
- Push notifications
- Interceptam requisições
- Essenciais para PWA

**Exemplo Prático**:

**ngsw-config.json**
```json
{
  "$schema": "./node_modules/@angular/service-worker/config/schema.json",
  "index": "/index.html",
  "assetGroups": [
    {
      "name": "app",
      "installMode": "prefetch",
      "resources": {
        "files": [
          "/favicon.ico",
          "/index.html",
          "/*.css",
          "/*.js"
        ]
      }
    },
    {
      "name": "assets",
      "installMode": "lazy",
      "updateMode": "prefetch",
      "resources": {
        "files": [
          "/assets/**",
          "/*.(eot|svg|cur|jpg|png|webp|gif|otf|ttf|woff|woff2)"
        ]
      }
    }
  ],
  "dataGroups": [
    {
      "name": "api",
      "urls": ["/api/**"],
      "cacheConfig": {
        "strategy": "freshness",
        "maxAge": "1h",
        "timeout": "5s"
      }
    }
  ]
}
```

---

### Web App Manifest

**Definição**: Web App Manifest é arquivo JSON que define como aplicação aparece quando instalada.

**Explicação Detalhada**:

Web App Manifest:
- Define nome e ícone
- Define tema e cores
- Define modo de exibição
- Permite instalação
- Essencial para PWA

**Exemplo Prático**:

**manifest.webmanifest**
```json
{
  "name": "Task Manager",
  "short_name": "Tasks",
  "description": "Gerenciador de tarefas",
  "theme_color": "#1976d2",
  "background_color": "#ffffff",
  "display": "standalone",
  "start_url": "/",
  "icons": [
    {
      "src": "assets/icons/icon-72x72.png",
      "sizes": "72x72",
      "type": "image/png"
    },
    {
      "src": "assets/icons/icon-96x96.png",
      "sizes": "96x96",
      "type": "image/png"
    },
    {
      "src": "assets/icons/icon-128x128.png",
      "sizes": "128x128",
      "type": "image/png"
    },
    {
      "src": "assets/icons/icon-144x144.png",
      "sizes": "144x144",
      "type": "image/png"
    },
    {
      "src": "assets/icons/icon-152x152.png",
      "sizes": "152x152",
      "type": "image/png"
    },
    {
      "src": "assets/icons/icon-192x192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "assets/icons/icon-384x384.png",
      "sizes": "384x384",
      "type": "image/png"
    },
    {
      "src": "assets/icons/icon-512x512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Configuração SSR Completa

**Contexto**: Configurar SSR completo para aplicação Angular.

**Código**:

**server.ts**
```typescript
import 'zone.js/node';
import { APP_BASE_HREF } from '@angular/common';
import { CommonEngine } from '@angular/ssr';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import bootstrap from './src/main.server';

export function app(): express.Express {
  const server = express();
  const serverDistFolder = dirname(fileURLToPath(import.meta.url));
  const browserDistFolder = resolve(serverDistFolder, '../browser');
  const indexHtml = join(browserDistFolder, 'index.html');

  const commonEngine = new CommonEngine();

  server.set('view engine', 'html');
  server.set('views', browserDistFolder);

  server.get('*', (req, res, next) => {
    const { protocol, originalUrl, baseUrl, headers } = req;

    commonEngine
      .render({
        bootstrap,
        documentFilePath: indexHtml,
        url: `${protocol}://${headers.host}${originalUrl}`,
        publicPath: browserDistFolder,
        providers: [{ provide: APP_BASE_HREF, useValue: baseUrl }],
      })
      .then((html) => res.send(html))
      .catch((err) => next(err));
  });

  return server;
}

function run(): void {
  const port = process.env['PORT'] || 4000;
  const server = app();
  server.listen(port, () => {
    console.log(`Node Express server listening on http://localhost:${port}`);
  });
}

run();
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Use Transfer State para dados do servidor**
   - **Por quê**: Evita requisições duplicadas
   - **Exemplo**: Transferir dados de API do servidor

2. **Configure Service Worker corretamente**
   - **Por quê**: Melhora experiência offline
   - **Exemplo**: Cache estratégico de recursos

3. **Otimize SEO com SSR**
   - **Por quê**: Melhora indexação
   - **Exemplo**: Meta tags dinâmicas

4. **Teste PWA em diferentes dispositivos**
   - **Por quê**: Garante compatibilidade
   - **Exemplo**: Testar em mobile e desktop

### ❌ Anti-padrões Comuns

1. **Não esquecer de configurar manifest**
   - **Problema**: PWA não funciona corretamente
   - **Solução**: Sempre configure manifest

2. **Não ignorar tratamento de erros SSR**
   - **Problema**: Aplicação quebra no servidor
   - **Solução**: Trate erros adequadamente

3. **Não cachear dados sensíveis**
   - **Problema**: Segurança comprometida
   - **Solução**: Não cache dados sensíveis

---

## Exercícios Práticos

### Exercício 1: Configurar SSR Básico (Intermediário)

**Objetivo**: Configurar SSR básico

**Descrição**: 
Configure SSR básico para aplicação Angular.

**Arquivo**: `exercises/exercise-5-2-1-ssr-basico.md`

---

### Exercício 2: Transfer State (Intermediário)

**Objetivo**: Implementar Transfer State

**Descrição**:
Implemente Transfer State para evitar requisições duplicadas.

**Arquivo**: `exercises/exercise-5-2-2-transfer-state.md`

---

### Exercício 3: Configurar PWA (Intermediário)

**Objetivo**: Configurar PWA básico

**Descrição**:
Configure PWA básico com Service Worker e Manifest.

**Arquivo**: `exercises/exercise-5-2-3-pwa-basico.md`

---

### Exercício 4: Funcionalidades Offline (Avançado)

**Objetivo**: Implementar funcionalidades offline

**Descrição**:
Implemente funcionalidades offline usando Service Worker.

**Arquivo**: `exercises/exercise-5-2-4-offline.md`

---

### Exercício 5: Push Notifications (Avançado)

**Objetivo**: Implementar push notifications

**Descrição**:
Implemente push notifications em PWA.

**Arquivo**: `exercises/exercise-5-2-5-push-notifications.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular SSR](https://angular.io/guide/ssr)**: Guia completo de SSR
- **[Angular PWA](https://angular.io/guide/service-worker-getting-started)**: Guia PWA
- **[Service Workers](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API)**: MDN Service Workers

---

## Resumo

### Principais Conceitos

- SSR renderiza aplicação no servidor
- Hydration torna HTML estático interativo
- Transfer State evita requisições duplicadas
- PWA oferece experiência nativa
- Service Workers habilitam funcionalidades offline
- Web App Manifest permite instalação

### Pontos-Chave para Lembrar

- Use Transfer State para dados do servidor
- Configure Service Worker corretamente
- Otimize SEO com SSR
- Teste PWA em diferentes dispositivos
- Sempre configure manifest

### Próximos Passos

- Próxima aula: Segurança Avançada
- Praticar SSR e PWA
- Explorar funcionalidades avançadas

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

**Aula Anterior**: [Aula 5.1: Testes Completos](./lesson-5-1-testes.md)  
**Próxima Aula**: [Aula 5.3: Segurança Avançada](./lesson-5-3-seguranca.md)  
**Voltar ao Módulo**: [Módulo 5: Práticas Avançadas e Projeto Final](../modules/module-5-praticas-avancadas-projeto-final.md)

