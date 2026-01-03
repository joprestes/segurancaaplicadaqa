---
layout: exercise
title: "Exercício 5.2.3: Configurar PWA Básico"
slug: "pwa-basico"
lesson_id: "lesson-5-2"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **PWA básico** através da **configuração de PWA básico com Service Worker e Manifest**.

Ao completar este exercício, você será capaz de:

- Configurar PWA no Angular
- Criar Service Worker
- Configurar Web App Manifest
- Habilitar instalação
- Verificar PWA funcionando

---

## Descrição

Você precisa configurar PWA básico para uma aplicação Angular.

### Contexto

Uma aplicação precisa ser instalável e funcionar offline.

### Tarefa

Crie:

1. **Service Worker**: Configurar Service Worker
2. **Manifest**: Criar Web App Manifest
3. **Ícones**: Adicionar ícones
4. **Configuração**: Configurar PWA
5. **Teste**: Verificar PWA funcionando

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Service Worker configurado
- [ ] Manifest criado
- [ ] Ícones adicionados
- [ ] PWA instalável
- [ ] Funciona offline básico

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] PWA está configurado corretamente
- [ ] Aplicação é instalável

---

## Solução Esperada

### Abordagem Recomendada

**ng add @angular/pwa**
```bash
ng add @angular/pwa --project my-app
```

**app.config.ts**
```typescript
import { ApplicationConfig, isDevMode } from '@angular/core';
import { provideServiceWorker } from '@angular/service-worker';

export const appConfig: ApplicationConfig = {
  providers: [
    provideServiceWorker('ngsw-worker.js', {
      enabled: !isDevMode(),
      registrationStrategy: 'registerWhenStable:30000'
    })
  ]
};
```

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
  ]
}
```

**manifest.webmanifest**
```json
{
  "name": "Task Manager",
  "short_name": "Tasks",
  "description": "Gerenciador de tarefas PWA",
  "theme_color": "#1976d2",
  "background_color": "#ffffff",
  "display": "standalone",
  "orientation": "portrait",
  "start_url": "/",
  "scope": "/",
  "icons": [
    {
      "src": "assets/icons/icon-72x72.png",
      "sizes": "72x72",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "assets/icons/icon-96x96.png",
      "sizes": "96x96",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "assets/icons/icon-128x128.png",
      "sizes": "128x128",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "assets/icons/icon-144x144.png",
      "sizes": "144x144",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "assets/icons/icon-152x152.png",
      "sizes": "152x152",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "assets/icons/icon-192x192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "assets/icons/icon-384x384.png",
      "sizes": "384x384",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "assets/icons/icon-512x512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "any maskable"
    }
  ]
}
```

**index.html**
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Task Manager</title>
  <base href="/">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
  <link rel="manifest" href="manifest.webmanifest">
  <meta name="theme-color" content="#1976d2">
</head>
<body>
  <app-root></app-root>
</body>
</html>
```

**Explicação da Solução**:

1. @angular/pwa adicionado ao projeto
2. provideServiceWorker configurado
3. ngsw-config.json define cache strategy
4. manifest.webmanifest define PWA metadata
5. Ícones adicionados em múltiplos tamanhos
6. PWA instalável e funciona offline

---

## Testes

### Casos de Teste

**Teste 1**: PWA instalável
- **Input**: Tentar instalar PWA
- **Output Esperado**: PWA pode ser instalado

**Teste 2**: Offline funciona
- **Input**: Desconectar internet
- **Output Esperado**: Aplicação funciona offline

**Teste 3**: Service Worker registrado
- **Input**: Verificar DevTools
- **Output Esperado**: Service Worker ativo

---

## Extensões (Opcional)

1. **Offline Page**: Adicione página offline customizada
2. **Update Notification**: Notifique sobre atualizações
3. **Background Sync**: Implemente background sync

---

## Referências Úteis

- **[Angular PWA](https://angular.io/guide/service-worker-getting-started)**: Guia PWA Angular
- **[Web App Manifest](https://developer.mozilla.org/en-US/docs/Web/Manifest)**: MDN Manifest

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

