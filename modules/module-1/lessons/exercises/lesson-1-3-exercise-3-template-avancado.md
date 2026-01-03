---
layout: exercise
title: "Exercício 1.3.3: Componente com Template Avançado"
slug: "template-avancado"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **templates avançados** através da **criação de um componente de perfil de usuário com múltiplas funcionalidades**.

Ao completar este exercício, você será capaz de:

- Usar interpolação avançada
- Aplicar property binding em diferentes contextos
- Implementar event binding complexo
- Usar diretivas estruturais (*ngIf, *ngFor)
- Combinar múltiplas técnicas de template

---

## Descrição

Você precisa criar um componente `UserProfileComponent` que exibe um perfil completo de usuário usando todas as técnicas de template aprendidas. O componente deve ser interativo e dinâmico.

### Contexto

Uma aplicação precisa de um componente de perfil de usuário que exibe informações pessoais, estatísticas e permite interações. O componente deve demonstrar uso avançado de templates Angular.

### Tarefa

Crie um componente `UserProfileComponent` com:

1. **Dados do Usuário**: Interface `User` com nome, email, avatar, bio, idade, cidade
2. **Estatísticas**: Array de estatísticas (posts, seguidores, seguindo)
3. **Interpolação**: Exibir todos os dados do usuário
4. **Property Binding**: Binding de imagem, classes condicionais, atributos
5. **Event Binding**: Botões para editar perfil, seguir/deixar de seguir
6. **Diretivas**: *ngIf para mostrar/ocultar seções, *ngFor para estatísticas
7. **Two-Way Binding**: Campo de busca (se aplicável)

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Interface `User` definida com todas as propriedades
- [ ] Template usa interpolação para exibir dados
- [ ] Property binding usado para imagem e classes
- [ ] Event binding implementado em botões
- [ ] Diretiva *ngIf usada para lógica condicional
- [ ] Diretiva *ngFor usada para listar estatísticas
- [ ] Componente é interativo e funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Template é bem estruturado e legível
- [ ] Todas as técnicas de template são aplicadas
- [ ] Código é organizado e mantível
- [ ] Componente é reutilizável

---

## Dicas

### Dica 1: Interface User

```typescript
interface User {
  id: number;
  name: string;
  email: string;
  avatar: string;
  bio: string;
  age: number;
  city: string;
  isFollowing: boolean;
}
```

### Dica 2: Property Binding de Imagem

```html
<img [src]="user.avatar" [alt]="user.name">
```

### Dica 3: Classes Condicionais

```html
<button [class.following]="user.isFollowing">
  {{ user.isFollowing ? 'Seguindo' : 'Seguir' }}
</button>
```

### Dica 4: *ngFor para Estatísticas

```html
<div *ngFor="let stat of statistics">
  <span>{{ stat.label }}: {{ stat.value }}</span>
</div>
```

### Dica 5: *ngIf Condicional

```html
<div *ngIf="user.bio">
  <p>{{ user.bio }}</p>
</div>
```

---

## Solução Esperada

### Abordagem Recomendada

**user-profile.component.ts**
```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';

interface User {
  id: number;
  name: string;
  email: string;
  avatar: string;
  bio: string;
  age: number;
  city: string;
  isFollowing: boolean;
}

interface Statistic {
  label: string;
  value: number;
  icon: string;
}

@Component({
  selector: 'app-user-profile',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './user-profile.component.html',
  styleUrls: ['./user-profile.component.css']
})
export class UserProfileComponent {
  @Input() user!: User;
  @Output() followToggle = new EventEmitter<User>();
  @Output() editProfile = new EventEmitter<User>();

  statistics: Statistic[] = [
    { label: 'Posts', value: 0, icon: '📝' },
    { label: 'Seguidores', value: 0, icon: '👥' },
    { label: 'Seguindo', value: 0, icon: '➕' }
  ];

  onFollowToggle(): void {
    this.user.isFollowing = !this.user.isFollowing;
    this.followToggle.emit(this.user);
  }

  onEditProfile(): void {
    this.editProfile.emit(this.user);
  }

  getAgeText(): string {
    return `${this.user.age} anos`;
  }

  getLocationText(): string {
    return `📍 ${this.user.city}`;
  }
}
```

**user-profile.component.html**
```html
<div class="user-profile">
  <div class="profile-header">
    <img 
      [src]="user.avatar" 
      [alt]="user.name"
      class="avatar"
      [class.online]="user.isFollowing">
    
    <div class="profile-info">
      <h2>{{ user.name }}</h2>
      <p class="email">{{ user.email }}</p>
      <p class="location">{{ getLocationText() }}</p>
      <p class="age">{{ getAgeText() }}</p>
    </div>

    <div class="profile-actions">
      <button 
        [class.btn-following]="user.isFollowing"
        [class.btn-follow]="!user.isFollowing"
        (click)="onFollowToggle()">
        {{ user.isFollowing ? 'Seguindo' : 'Seguir' }}
      </button>
      
      <button 
        class="btn-edit"
        (click)="onEditProfile()">
        Editar Perfil
      </button>
    </div>
  </div>

  <div class="profile-bio" *ngIf="user.bio">
    <h3>Sobre</h3>
    <p>{{ user.bio }}</p>
  </div>

  <div class="profile-statistics">
    <div 
      *ngFor="let stat of statistics" 
      class="stat-item"
      [attr.data-label]="stat.label">
      <span class="stat-icon">{{ stat.icon }}</span>
      <span class="stat-label">{{ stat.label }}</span>
      <span class="stat-value">{{ stat.value }}</span>
    </div>
  </div>
</div>
```

**user-profile.component.css**
```css
.user-profile {
  max-width: 600px;
  margin: 0 auto;
  padding: 2rem;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
}

.profile-header {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.avatar {
  width: 100px;
  height: 100px;
  border-radius: 50%;
  object-fit: cover;
  border: 3px solid #1976d2;
}

.avatar.online {
  border-color: #4caf50;
}

.profile-info h2 {
  margin: 0 0 0.5rem 0;
  color: #333;
}

.email {
  color: #666;
  margin: 0.25rem 0;
}

.location, .age {
  color: #888;
  font-size: 0.9rem;
  margin: 0.25rem 0;
}

.profile-actions {
  display: flex;
  gap: 1rem;
  margin-left: auto;
}

.btn-follow, .btn-following {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
}

.btn-follow {
  background-color: #1976d2;
  color: white;
}

.btn-following {
  background-color: #4caf50;
  color: white;
}

.btn-edit {
  padding: 8px 16px;
  background-color: #f5f5f5;
  border: 1px solid #ddd;
  border-radius: 4px;
  cursor: pointer;
}

.profile-bio {
  margin-bottom: 2rem;
  padding: 1rem;
  background-color: #f9f9f9;
  border-radius: 4px;
}

.profile-statistics {
  display: flex;
  justify-content: space-around;
  gap: 1rem;
}

.stat-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 1rem;
  background-color: #f5f5f5;
  border-radius: 4px;
  flex: 1;
}

.stat-icon {
  font-size: 1.5rem;
  margin-bottom: 0.5rem;
}

.stat-label {
  font-size: 0.875rem;
  color: #666;
  margin-bottom: 0.25rem;
}

.stat-value {
  font-size: 1.25rem;
  font-weight: bold;
  color: #333;
}
```

**Explicação da Solução**:

1. Interface `User` define estrutura de dados
2. Interpolação exibe dados do usuário
3. Property binding usado para imagem, classes e atributos
4. Event binding em botões chama métodos
5. *ngIf mostra bio apenas se existir
6. *ngFor lista estatísticas dinamicamente
7. Métodos helper formatam dados para exibição

**Decisões de Design**:

- Classes condicionais baseadas em estado
- Métodos helper melhoram legibilidade do template
- Estrutura HTML semântica
- Estilos responsivos e organizados

---

## Testes

### Casos de Teste

**Teste 1**: Dados do usuário são exibidos
- **Input**: Componente com `user` definido
- **Output Esperado**: Nome, email, avatar, bio devem aparecer

**Teste 2**: Botão de seguir muda estado
- **Input**: Clicar em botão "Seguir"
- **Output Esperado**: Botão deve mudar para "Seguindo" e classe deve mudar

**Teste 3**: Bio só aparece se existir
- **Input**: `user.bio` vazio
- **Output Esperado**: Seção de bio não deve aparecer (*ngIf)

**Teste 4**: Estatísticas são listadas
- **Input**: Array `statistics` com 3 itens
- **Output Esperado**: 3 itens devem aparecer na lista (*ngFor)

**Teste 5**: Eventos são emitidos
- **Input**: Clicar em botões
- **Output Esperado**: Eventos devem ser emitidos (verificar no console)

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **Adicionar Two-Way Binding**: Campo de busca com `[(ngModel)]`
2. **Adicionar Fotos**: Galeria de fotos do usuário com *ngFor
3. **Adicionar Formatação**: Pipes para formatar números e datas
4. **Adicionar Animações**: Transições CSS para mudanças de estado

---

## Referências Úteis

- **[Template Syntax](https://angular.io/guide/template-syntax)**: Guia completo de sintaxe de templates
- **[Property Binding](https://angular.io/guide/property-binding)**: Documentação de property binding
- **[Event Binding](https://angular.io/guide/event-binding)**: Documentação de event binding
- **[Structural Directives](https://angular.io/guide/structural-directives)**: Diretivas estruturais

---

## Checklist de Qualidade

Antes de considerar este exercício completo:

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

