---
layout: exercise
title: "Exercício 5.1.6: Testes E2E"
slug: "testes-e2e"
lesson_id: "lesson-5-1"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **testes E2E** através da **configuração de Cypress ou Playwright e criação de testes E2E para fluxos críticos**.

Ao completar este exercício, você será capaz de:

- Configurar Cypress ou Playwright
- Escrever testes E2E
- Testar fluxos completos do usuário
- Verificar comportamento real da aplicação
- Criar testes robustos e confiáveis

---

## Descrição

Você precisa configurar Cypress ou Playwright e criar testes E2E para uma aplicação de gerenciamento de tarefas.

### Contexto

Uma aplicação precisa ter testes E2E para garantir que fluxos críticos funcionam do ponto de vista do usuário.

### Tarefa

Crie:

1. **Configuração**: Configurar Cypress ou Playwright
2. **Testes**: Escrever testes E2E para fluxos críticos
3. **Execução**: Executar testes E2E
4. **Documentação**: Documentar testes

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Cypress ou Playwright configurado
- [ ] Testes E2E escritos
- [ ] Fluxos críticos testados
- [ ] Testes executam com sucesso
- [ ] Documentação criada

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Testes estão completos
- [ ] Testes são robustos

---

## Solução Esperada

### Abordagem Recomendada

**cypress.config.ts**
```typescript
import { defineConfig } from 'cypress';

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:4200',
    setupNodeEvents(on, config) {
    },
    specPattern: 'cypress/e2e/**/*.cy.ts',
    supportFile: 'cypress/support/e2e.ts'
  },
  component: {
    devServer: {
      framework: 'angular',
      bundler: 'webpack'
    },
    specPattern: '**/*.cy.ts'
  }
});
```

**cypress/e2e/tasks.cy.ts**
```typescript
describe('Task Manager E2E', () => {
  beforeEach(() => {
    cy.visit('/');
  });

  it('should display task list', () => {
    cy.get('[data-cy="task-list"]').should('be.visible');
  });

  it('should create a new task', () => {
    cy.get('[data-cy="task-input"]').type('Nova tarefa');
    cy.get('[data-cy="add-button"]').click();
    
    cy.get('[data-cy="task-list"]').should('contain', 'Nova tarefa');
    cy.get('[data-cy="task-item"]').should('have.length.at.least', 1);
  });

  it('should toggle task completion', () => {
    cy.get('[data-cy="task-checkbox"]').first().check();
    cy.get('[data-cy="task-item"]').first().should('have.class', 'completed');
    
    cy.get('[data-cy="task-checkbox"]').first().uncheck();
    cy.get('[data-cy="task-item"]').first().should('not.have.class', 'completed');
  });

  it('should delete a task', () => {
    const initialCount = cy.get('[data-cy="task-item"]').its('length');
    
    cy.get('[data-cy="delete-button"]').first().click();
    
    cy.get('[data-cy="task-item"]').should('have.length', initialCount - 1);
  });

  it('should filter tasks', () => {
    cy.get('[data-cy="filter-all"]').click();
    cy.get('[data-cy="task-item"]').should('be.visible');
    
    cy.get('[data-cy="filter-active"]').click();
    cy.get('[data-cy="task-item"]').should('not.have.class', 'completed');
    
    cy.get('[data-cy="filter-completed"]').click();
    cy.get('[data-cy="task-item"]').should('have.class', 'completed');
  });

  it('should navigate through the app', () => {
    cy.get('[data-cy="nav-home"]').click();
    cy.url().should('include', '/home');
    
    cy.get('[data-cy="nav-tasks"]').click();
    cy.url().should('include', '/tasks');
    
    cy.get('[data-cy="nav-about"]').click();
    cy.url().should('include', '/about');
  });

  it('should handle form validation', () => {
    cy.get('[data-cy="add-button"]').click();
    cy.get('[data-cy="task-input"]').should('have.class', 'ng-invalid');
    
    cy.get('[data-cy="task-input"]').type('Valid task');
    cy.get('[data-cy="task-input"]').should('not.have.class', 'ng-invalid');
  });
});
```

**playwright.config.ts**
```typescript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:4200',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
  webServer: {
    command: 'npm start',
    url: 'http://localhost:4200',
    reuseExistingServer: !process.env.CI,
  },
});
```

**e2e/tasks.spec.ts** (Playwright)
```typescript
import { test, expect } from '@playwright/test';

test.describe('Task Manager E2E', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should display task list', async ({ page }) => {
    await expect(page.locator('[data-cy="task-list"]')).toBeVisible();
  });

  test('should create a new task', async ({ page }) => {
    await page.fill('[data-cy="task-input"]', 'Nova tarefa');
    await page.click('[data-cy="add-button"]');
    
    await expect(page.locator('[data-cy="task-list"]')).toContainText('Nova tarefa');
    await expect(page.locator('[data-cy="task-item"]')).toHaveCount(1);
  });

  test('should toggle task completion', async ({ page }) => {
    const checkbox = page.locator('[data-cy="task-checkbox"]').first();
    const taskItem = page.locator('[data-cy="task-item"]').first();
    
    await checkbox.check();
    await expect(taskItem).toHaveClass(/completed/);
    
    await checkbox.uncheck();
    await expect(taskItem).not.toHaveClass(/completed/);
  });

  test('should delete a task', async ({ page }) => {
    const initialCount = await page.locator('[data-cy="task-item"]').count();
    
    await page.click('[data-cy="delete-button"]').first();
    
    await expect(page.locator('[data-cy="task-item"]')).toHaveCount(initialCount - 1);
  });
});
```

**package.json**
```json
{
  "scripts": {
    "e2e": "cypress open",
    "e2e:headless": "cypress run",
    "e2e:playwright": "playwright test",
    "e2e:playwright:ui": "playwright test --ui"
  },
  "devDependencies": {
    "cypress": "^13.0.0",
    "@playwright/test": "^1.40.0"
  }
}
```

**Explicação da Solução**:

1. Cypress ou Playwright configurado
2. Testes E2E escritos para fluxos críticos
3. data-cy attributes usados para seletores estáveis
4. Testes verificam comportamento do usuário
5. Múltiplos navegadores testados (Playwright)
6. Testes robustos e confiáveis

---

## Testes

### Casos de Teste

**Teste 1**: Criar tarefa funciona
- **Input**: Criar tarefa via UI
- **Output Esperado**: Tarefa criada e exibida

**Teste 2**: Toggle funciona
- **Input**: Marcar/desmarcar tarefa
- **Output Esperado**: Estado atualizado

**Teste 3**: Delete funciona
- **Input**: Deletar tarefa
- **Output Esperado**: Tarefa removida

---

## Extensões (Opcional)

1. **Visual Testing**: Adicione testes visuais
2. **Performance Testing**: Teste performance E2E
3. **Cross-browser**: Teste em múltiplos navegadores

---

## Referências Úteis

- **[Cypress](https://docs.cypress.io/)**: Documentação Cypress
- **[Playwright](https://playwright.dev/)**: Documentação Playwright
- **[E2E Testing](https://angular.io/guide/testing#end-to-end-testing)**: Guia E2E Angular

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

