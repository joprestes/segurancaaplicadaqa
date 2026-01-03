---
layout: exercise
title: "Exercício 1.2.1: Criar Interfaces e Tipos"
slug: "interfaces-tipos"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **criação de interfaces e tipos** através da **definição de estruturas de dados para um sistema de produtos**.

Ao completar este exercício, você será capaz de:

- Criar interfaces TypeScript para estruturas de dados
- Usar tipos primitivos e tipos customizados
- Entender a diferença entre `interface` e `type`
- Aplicar type safety em estruturas de dados

---

## Descrição

Você precisa criar um sistema de tipos para uma loja online. O sistema deve representar produtos com suas características e categorias.

### Contexto

Uma loja online precisa de um sistema tipado para gerenciar seus produtos. Cada produto tem informações específicas que devem ser validadas em tempo de compilação.

### Tarefa

Crie interfaces e tipos TypeScript para representar:

1. **Produto**: Deve ter id (number), nome (string), preço (number), descrição (string), categoria (Category), estoque (number), e disponível (boolean)

2. **Categoria**: Deve ter id (number) e nome (string)

3. **Tipo para criar produto**: Um tipo que permite criar produto sem o id (já que será gerado automaticamente)

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Criar interface `Category` com propriedades `id` e `name`
- [ ] Criar interface `Product` com todas as propriedades especificadas
- [ ] Criar tipo `CreateProduct` que omite o `id` de `Product`
- [ ] Todas as propriedades devem ter tipos explícitos
- [ ] Código deve compilar sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Nomes de interfaces seguem convenção PascalCase
- [ ] Tipos são específicos (não usa `any`)
- [ ] Código é legível e bem organizado

---

## Dicas

### Dica 1: Estrutura Básica de Interface

Uma interface TypeScript segue esta estrutura:
```typescript
interface NomeDaInterface {
  propriedade1: tipo;
  propriedade2: tipo;
}
```

### Dica 2: Usando Utility Types

Para criar um tipo que omite propriedades, você pode usar `Omit`:
```typescript
type NovoType = Omit<TipoOriginal, 'propriedadeParaOmitir'>;
```

### Dica 3: Tipos Opcionais

Se uma propriedade pode não existir, use `?`:
```typescript
interface Exemplo {
  obrigatoria: string;
  opcional?: number;
}
```

---

## Solução Esperada

### Abordagem Recomendada

```typescript
interface Category {
  id: number;
  name: string;
}

interface Product {
  id: number;
  name: string;
  price: number;
  description: string;
  category: Category;
  stock: number;
  available: boolean;
}

type CreateProduct = Omit<Product, 'id'>;
```

**Explicação da Solução**:

1. `Category` define a estrutura de uma categoria com id e nome
2. `Product` define a estrutura completa de um produto, incluindo uma categoria
3. `CreateProduct` usa `Omit` para criar um tipo que permite criar produto sem id
4. Todos os tipos são explícitos e específicos

**Decisões de Design**:

- Usei `interface` para estruturas que podem ser estendidas
- `Category` é uma interface separada para reutilização
- `CreateProduct` usa `Omit` utility type para flexibilidade
- Todas as propriedades são obrigatórias exceto quando especificado

---

## Testes

### Casos de Teste

**Teste 1**: Criar uma categoria válida
- **Input**: 
```typescript
const category: Category = {
  id: 1,
  name: "Eletrônicos"
};
```
- **Output Esperado**: Deve compilar sem erros

**Teste 2**: Criar um produto válido
- **Input**: 
```typescript
const product: Product = {
  id: 1,
  name: "Notebook",
  price: 2500.00,
  description: "Notebook gamer",
  category: { id: 1, name: "Eletrônicos" },
  stock: 10,
  available: true
};
```
- **Output Esperado**: Deve compilar sem erros

**Teste 3** (Edge Case): Criar produto sem id usando CreateProduct
- **Input**: 
```typescript
const newProduct: CreateProduct = {
  name: "Mouse",
  price: 50.00,
  description: "Mouse sem fio",
  category: { id: 1, name: "Eletrônicos" },
  stock: 20,
  available: true
};
```
- **Output Esperado**: Deve compilar sem erros (sem propriedade `id`)

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar Validação**: Crie tipos que garantam que preço e estoque sejam números positivos
2. **Criar Tipo Union**: Crie um tipo `ProductStatus` que pode ser "available" | "out_of_stock" | "discontinued"
3. **Adicionar Timestamps**: Adicione propriedades `createdAt` e `updatedAt` do tipo `Date`

---

## Referências Úteis

- **[TypeScript Interfaces](https://www.typescriptlang.org/docs/handbook/2/objects.html)**: Documentação oficial sobre interfaces
- **[TypeScript Utility Types](https://www.typescriptlang.org/docs/handbook/utility-types.html)**: Lista de utility types disponíveis
- **[Omit Utility Type](https://www.typescriptlang.org/docs/handbook/utility-types.html#omittype-keys)**: Documentação do Omit

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

