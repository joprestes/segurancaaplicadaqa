---
layout: exercise
title: "Exercício 5.2.1: Configurar SSR Básico"
slug: "ssr-basico"
lesson_id: "lesson-5-2"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **SSR básico** através da **configuração de SSR básico para aplicação Angular**.

Ao completar este exercício, você será capaz de:

- Configurar SSR no Angular
- Entender estrutura SSR
- Criar servidor Express para SSR
- Renderizar aplicação no servidor
- Verificar SSR funcionando

---

## Descrição

Você precisa configurar SSR básico para uma aplicação Angular existente.

### Contexto

Uma aplicação precisa ter SSR para melhorar SEO e performance inicial.

### Tarefa

Crie:

1. **Configuração**: Configurar SSR no projeto
2. **Servidor**: Criar servidor Express
3. **Build**: Configurar build SSR
4. **Teste**: Verificar SSR funcionando

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] SSR configurado
- [ ] Servidor Express criado
- [ ] Build SSR configurado
- [ ] SSR funciona corretamente
- [ ] HTML renderizado no servidor

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] SSR está configurado corretamente
- [ ] Aplicação funciona com SSR

---

## Solução Esperada

### Abordagem Recomendada

**angular.json**
```json
{
  "projects": {
    "my-app": {
      "architect": {
        "build": {
          "builder": "@angular-devkit/build-angular:application",
          "options": {
            "outputPath": "dist/browser",
            "index": "src/index.html",
            "main": "src/main.ts",
            "server": "src/main.server.ts"
          }
        },
        "serve-ssr": {
          "builder": "@angular-devkit/build-angular:dev-server",
          "configurations": {
            "production": {
              "buildTarget": "my-app:build:production",
              "serverTarget": "my-app:server:production"
            }
          }
        },
        "server": {
          "builder": "@angular-devkit/build-angular:server",
          "options": {
            "outputPath": "dist/server",
            "main": "server.ts"
          }
        }
      }
    }
  }
}
```

**main.server.ts**
```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { config } from './app/app.config.server';

const bootstrap = () => bootstrapApplication(AppComponent, config);

export default bootstrap;
```

**app.config.server.ts**
```typescript
import { ApplicationConfig, mergeApplicationConfig } from '@angular/core';
import { provideServerRendering } from '@angular/platform-server';
import { appConfig } from './app.config';

const serverConfig: ApplicationConfig = {
  providers: [
    provideServerRendering()
  ]
};

export const config = mergeApplicationConfig(appConfig, serverConfig);
```

**server.ts**
```typescript
import 'zone.js/node';
import { APP_BASE_HREF } from '@angular/common';
import { CommonEngine } from '@angular/ssr';
import express from 'express';
import { existsSync } from 'fs';
import { join } from 'path';
import bootstrap from './src/main.server';

export function app(): express.Express {
  const server = express();
  const distFolder = join(process.cwd(), 'dist/browser');
  const indexHtml = existsSync(join(distFolder, 'index.original.html'))
    ? join(distFolder, 'index.original.html')
    : join(distFolder, 'index.html');

  const commonEngine = new CommonEngine();

  server.set('view engine', 'html');
  server.set('views', distFolder);

  server.get('*', (req, res, next) => {
    const { protocol, originalUrl, baseUrl, headers } = req;

    commonEngine
      .render({
        bootstrap,
        documentFilePath: indexHtml,
        url: `${protocol}://${headers.host}${originalUrl}`,
        publicPath: distFolder,
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

**package.json**
```json
{
  "scripts": {
    "build:ssr": "ng build && ng run my-app:server",
    "serve:ssr": "node dist/server/server.js"
  },
  "dependencies": {
    "@angular/ssr": "^18.0.0",
    "express": "^4.18.0"
  }
}
```

**Explicação da Solução**:

1. angular.json configurado para SSR
2. main.server.ts criado para bootstrap SSR
3. app.config.server.ts configura SSR providers
4. server.ts cria servidor Express
5. CommonEngine renderiza aplicação
6. Build e serve scripts configurados

---

## Testes

### Casos de Teste

**Teste 1**: SSR funciona
- **Input**: Acessar aplicação via SSR
- **Output Esperado**: HTML renderizado no servidor

**Teste 2**: Aplicação funciona
- **Input**: Interagir com aplicação
- **Output Esperado**: Aplicação funciona normalmente

**Teste 3**: SEO melhorado
- **Input**: Verificar HTML fonte
- **Output Esperado**: Conteúdo visível no HTML

---

## Extensões (Opcional)

1. **Hydration**: Configure hydration
2. **Transfer State**: Adicione Transfer State
3. **Error Handling**: Adicione tratamento de erros

---

## Referências Úteis

- **[Angular SSR](https://angular.io/guide/ssr)**: Guia SSR Angular
- **[CommonEngine](https://angular.io/api/platform-server/CommonEngine)**: Documentação CommonEngine

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

