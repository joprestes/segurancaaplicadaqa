---
layout: exercise
title: "Exercício 1.2.4: Organizar com Módulos ES6"
slug: "modulos-es6"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **organização de código com módulos ES6** através da **separação de código em arquivos modulares**.

Ao completar este exercício, você será capaz de:

- Organizar código em múltiplos arquivos
- Usar `export` e `import` corretamente
- Criar barrel exports para facilitar imports
- Entender estrutura de módulos em projetos Angular
- Aplicar boas práticas de organização de código

---

## Descrição

Você precisa reorganizar seu código TypeScript em módulos separados, seguindo boas práticas de organização. O código deve ser separado em arquivos lógicos e importado onde necessário.

### Contexto

Um projeto Angular cresceu e precisa ser organizado em módulos. O código atual está tudo em um arquivo e precisa ser separado para facilitar manutenção.

### Tarefa

Organize o código nos seguintes arquivos:

1. **`types.ts`**: Exporte todas as interfaces e tipos (`Product`, `Category`, `CreateProduct`)

2. **`services.ts`**: Exporte a classe `ProductService` e importe tipos de `types.ts`

3. **`utils.ts`**: Exporte as funções utilitárias genéricas (`getById`, `filter`, `map`, `findFirst`)

4. **`index.ts`**: Crie barrel export que re-exporta tudo de forma organizada

5. **`app.ts`**: Arquivo principal que importa e usa tudo dos outros módulos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Arquivo `types.ts` criado com exports de interfaces e tipos
- [ ] Arquivo `services.ts` criado com export da classe e imports corretos
- [ ] Arquivo `utils.ts` criado com exports de funções e imports necessários
- [ ] Arquivo `index.ts` criado como barrel export
- [ ] Arquivo `app.ts` importa e usa código dos outros módulos
- [ ] Todos os imports/exports estão corretos
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Arquivos estão organizados logicamente
- [ ] Imports são explícitos e organizados
- [ ] Barrel exports facilitam uso do código
- [ ] Código é legível e bem organizado

---

## Dicas

### Dica 1: Export Named

Para exportar múltiplas coisas de um arquivo:
```typescript
export interface Product { /* ... */ }
export type CreateProduct = /* ... */
```

### Dica 2: Export Default

Para exportar uma coisa principal:
```typescript
export default class ProductService { /* ... */ }
```

### Dica 3: Import Named

Para importar exports nomeados:
```typescript
import { Product, Category } from './types';
```

### Dica 4: Barrel Exports

Para criar barrel export:
```typescript
export * from './types';
export * from './services';
export * from './utils';
```

### Dica 5: Import com Alias

Se houver conflito de nomes:
```typescript
import { Product as ProductType } from './types';
```

---

## Solução Esperada

### Abordagem Recomendada

**types.ts**
```typescript
export interface Category {
  id: number;
  name: string;
}

export interface Product {
  id: number;
  name: string;
  price: number;
  description: string;
  category: Category;
  stock: number;
  available: boolean;
}

export type CreateProduct = Omit<Product, 'id'>;
```

**services.ts**
```typescript
import { Product, CreateProduct } from './types';

export class ProductService {
  private products: Product[] = [];
  private nextId: number = 1;

  addProduct(productData: CreateProduct): Product {
    const newProduct: Product = {
      ...productData,
      id: this.nextId++
    };
    this.products.push(newProduct);
    return newProduct;
  }

  getAllProducts(): Product[] {
    return [...this.products];
  }

  getProductById(id: number): Product | undefined {
    return this.products.find(product => product.id === id);
  }
}
```

**utils.ts**
```typescript
export interface Identifiable {
  id: number;
}

export function getById<T extends Identifiable>(items: T[], id: number): T | undefined {
  return items.find(item => item.id === id);
}

export function filter<T>(items: T[], predicate: (item: T) => boolean): T[] {
  return items.filter(predicate);
}

export function map<T, R>(items: T[], transform: (item: T) => R): R[] {
  return items.map(transform);
}

export function findFirst<T>(items: T[], predicate: (item: T) => boolean): T | undefined {
  return items.find(predicate);
}
```

**index.ts** (Barrel Export)
```typescript
export * from './types';
export * from './services';
export * from './utils';
```

**app.ts**
```typescript
import { ProductService, Product, CreateProduct, getById } from './index';

const service = new ProductService();

const newProduct: CreateProduct = {
  name: "Notebook",
  price: 2500,
  description: "Notebook gamer",
  category: { id: 1, name: "Eletrônicos" },
  stock: 10,
  available: true
};

const product = service.addProduct(newProduct);
const allProducts = service.getAllProducts();
const found = getById(allProducts, product.id);

console.log(found);
```

**Explicação da Solução**:

1. `types.ts` centraliza todas as definições de tipos
2. `services.ts` contém lógica de negócio e importa tipos
3. `utils.ts` contém funções utilitárias reutilizáveis
4. `index.ts` facilita imports com barrel export
5. `app.ts` demonstra uso de todos os módulos

**Decisões de Design**:

- Separação por responsabilidade (types, services, utils)
- Barrel export facilita imports externos
- Imports explícitos melhoram legibilidade
- Estrutura escalável para projetos maiores

---

## Testes

### Casos de Teste

**Teste 1**: Importar tipos de types.ts
- **Input**: 
```typescript
import { Product, Category } from './types';
const product: Product = { /* ... */ };
```
- **Output Esperado**: Deve compilar sem erros

**Teste 2**: Importar serviço e usar
- **Input**: 
```typescript
import { ProductService } from './services';
const service = new ProductService();
```
- **Output Esperado**: Deve compilar e funcionar

**Teste 3**: Usar barrel export
- **Input**: 
```typescript
import { Product, ProductService, getById } from './index';
```
- **Output Esperado**: Deve importar tudo corretamente

**Teste 4**: Usar funções utilitárias
- **Input**: 
```typescript
import { filter, map } from './utils';
const numbers = [1, 2, 3];
const doubled = map(numbers, n => n * 2);
```
- **Output Esperado**: Deve funcionar corretamente

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Criar Subpastas**: Organize em pastas `types/`, `services/`, `utils/`
2. **Adicionar Barrel Exports**: Crie `index.ts` em cada pasta
3. **Criar Módulo de Constantes**: Separe constantes em `constants.ts`
4. **Adicionar Validação**: Crie módulo `validators.ts` com funções de validação

---

## Referências Úteis

- **[ES6 Modules](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules)**: Guia sobre módulos ES6
- **[TypeScript Modules](https://www.typescriptlang.org/docs/handbook/modules.html)**: Documentação TypeScript sobre módulos
- **[Barrel Exports Pattern](https://basarat.gitbook.io/typescript/main-1/barrel)**: Padrão de barrel exports

---

## Checklist de Qualidade

Antes de considerar este exercício completo:

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais e edge cases
- [x] Referências úteis estão incluídas

