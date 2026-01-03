---
layout: exercise
title: "Exercício 1.2.2: Implementar Classes com TypeScript"
slug: "classes-typescript"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **criação de classes TypeScript** através da **implementação de um serviço para gerenciar produtos**.

Ao completar este exercício, você será capaz de:

- Criar classes TypeScript com propriedades tipadas
- Implementar construtores com parâmetros tipados
- Criar métodos com tipos de retorno explícitos
- Aplicar modificadores de acesso (public, private)
- Gerenciar estado interno de forma type-safe

---

## Descrição

Você precisa criar uma classe `ProductService` que gerencia uma lista de produtos. O serviço deve permitir adicionar, listar e buscar produtos de forma type-safe.

### Contexto

Um sistema de loja online precisa de um serviço para gerenciar produtos. O serviço deve manter uma lista interna de produtos e fornecer métodos para manipular essa lista.

### Tarefa

Crie uma classe `ProductService` com:

1. **Propriedade privada**: `products` do tipo `Product[]` (array de produtos)
2. **Método `addProduct`**: Recebe um `CreateProduct` e retorna um `Product` com id gerado
3. **Método `getAllProducts`**: Retorna todos os produtos
4. **Método `getProductById`**: Recebe um `id` (number) e retorna `Product | undefined`
5. **Método `updateProduct`**: Recebe `id` e dados parciais, retorna `Product | undefined`
6. **Método `deleteProduct`**: Recebe `id` e retorna `boolean`

Use as interfaces criadas no exercício anterior (`Product`, `CreateProduct`).

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Classe `ProductService` criada com propriedade privada `products`
- [ ] Método `addProduct` implementado com geração automática de id
- [ ] Método `getAllProducts` retorna cópia do array (não referência)
- [ ] Método `getProductById` implementado com busca por id
- [ ] Método `updateProduct` permite atualização parcial
- [ ] Método `deleteProduct` remove produto e retorna sucesso/falha
- [ ] Todos os métodos têm tipos explícitos de parâmetros e retorno

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Propriedades privadas usam modificador `private`
- [ ] Métodos públicos têm tipos explícitos
- [ ] Código é legível e bem organizado
- [ ] Não há uso de `any`

---

## Dicas

### Dica 1: Estrutura de Classe

Uma classe TypeScript segue esta estrutura:
```typescript
class NomeDaClasse {
  private propriedade: tipo;
  
  constructor(parametros: tipos) {
    this.propriedade = valor;
  }
  
  metodo(parametro: tipo): tipoRetorno {
    // implementação
  }
}
```

### Dica 2: Geração de ID

Para gerar IDs únicos, você pode usar o tamanho do array + 1:
```typescript
const newId = this.items.length + 1;
```

### Dica 3: Atualização Parcial

Use `Partial` utility type para permitir atualização parcial:
```typescript
updateProduct(id: number, updates: Partial<Product>): Product | undefined
```

### Dica 4: Retornar Cópia do Array

Para evitar mutação externa, retorne uma cópia:
```typescript
return [...this.products];
```

---

## Solução Esperada

### Abordagem Recomendada

```typescript
import { Product, CreateProduct } from './types';

class ProductService {
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

  updateProduct(id: number, updates: Partial<Omit<Product, 'id'>>): Product | undefined {
    const productIndex = this.products.findIndex(p => p.id === id);
    
    if (productIndex === -1) {
      return undefined;
    }

    this.products[productIndex] = {
      ...this.products[productIndex],
      ...updates
    };

    return this.products[productIndex];
  }

  deleteProduct(id: number): boolean {
    const initialLength = this.products.length;
    this.products = this.products.filter(product => product.id !== id);
    return this.products.length < initialLength;
  }
}
```

**Explicação da Solução**:

1. `private products` mantém a lista interna protegida
2. `nextId` garante IDs únicos sequenciais
3. `addProduct` cria novo produto com id gerado
4. `getAllProducts` retorna cópia para evitar mutação externa
5. `getProductById` usa `find` para buscar por id
6. `updateProduct` permite atualização parcial usando `Partial` e spread
7. `deleteProduct` remove produto e retorna se foi removido

**Decisões de Design**:

- Usei `nextId` separado para melhor controle de IDs
- `getAllProducts` retorna cópia para encapsulamento
- `updateProduct` usa `Partial` para flexibilidade
- `deleteProduct` retorna boolean para feedback claro

---

## Testes

### Casos de Teste

**Teste 1**: Adicionar produto e recuperar
- **Input**: 
```typescript
const service = new ProductService();
const product = service.addProduct({
  name: "Notebook",
  price: 2500,
  description: "Notebook gamer",
  category: { id: 1, name: "Eletrônicos" },
  stock: 10,
  available: true
});
const retrieved = service.getProductById(product.id);
```
- **Output Esperado**: `retrieved` deve ser igual a `product`

**Teste 2**: Listar todos os produtos
- **Input**: 
```typescript
service.addProduct({ /* produto 1 */ });
service.addProduct({ /* produto 2 */ });
const all = service.getAllProducts();
```
- **Output Esperado**: `all.length` deve ser 2

**Teste 3** (Edge Case): Buscar produto inexistente
- **Input**: 
```typescript
const notFound = service.getProductById(999);
```
- **Output Esperado**: `notFound` deve ser `undefined`

**Teste 4**: Atualizar produto existente
- **Input**: 
```typescript
const product = service.addProduct({ /* produto */ });
const updated = service.updateProduct(product.id, { price: 3000 });
```
- **Output Esperado**: `updated?.price` deve ser 3000

**Teste 5**: Deletar produto
- **Input**: 
```typescript
const product = service.addProduct({ /* produto */ });
const deleted = service.deleteProduct(product.id);
const found = service.getProductById(product.id);
```
- **Output Esperado**: `deleted` deve ser `true`, `found` deve ser `undefined`

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar Validação**: Valide que preço e estoque sejam positivos antes de adicionar
2. **Busca por Nome**: Adicione método `searchByName(name: string): Product[]`
3. **Filtrar por Categoria**: Adicione método `getProductsByCategory(categoryId: number): Product[]`
4. **Contar Produtos**: Adicione método `getProductCount(): number`

---

## Referências Úteis

- **[TypeScript Classes](https://www.typescriptlang.org/docs/handbook/2/classes.html)**: Documentação oficial sobre classes
- **[TypeScript Access Modifiers](https://www.typescriptlang.org/docs/handbook/2/classes.html#member-visibility)**: Modificadores de acesso
- **[Partial Utility Type](https://www.typescriptlang.org/docs/handbook/utility-types.html#partialtype)**: Documentação do Partial

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

