---
layout: exercise
title: "Exercício 2.5.3: Comunicação via Serviços"
slug: "comunicacao-servicos"
lesson_id: "lesson-2-5"
module: "module-2"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **comunicação via serviços** através da **implementação de comunicação entre componentes irmãos usando BehaviorSubject**.

Ao completar este exercício, você será capaz de:

- Criar serviço de comunicação
- Usar BehaviorSubject para estado compartilhado
- Implementar comunicação entre componentes irmãos
- Gerenciar subscriptions adequadamente
- Entender padrão de comunicação via serviços

---

## Descrição

Você precisa criar um sistema de mensagens onde componentes irmãos podem enviar e receber mensagens através de um serviço.

### Contexto

Uma aplicação precisa de comunicação entre componentes que não têm relação pai-filho direta.

### Tarefa

Crie:

1. **MessageService**: Serviço com BehaviorSubject
2. **SenderComponent**: Componente que envia mensagens
3. **ReceiverComponent**: Componente que recebe mensagens
4. **ParentComponent**: Componente que contém ambos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] MessageService criado com BehaviorSubject
- [ ] Métodos send e receive implementados
- [ ] SenderComponent envia mensagens
- [ ] ReceiverComponent recebe mensagens
- [ ] Subscriptions gerenciadas corretamente
- [ ] Comunicação funciona entre componentes irmãos

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Subscriptions são limpas
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**message.service.ts**
```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export interface Message {
  id: number;
  text: string;
  timestamp: Date;
  sender: string;
}

@Injectable({
  providedIn: 'root'
})
export class MessageService {
  private messages$ = new BehaviorSubject<Message[]>([]);
  private messageId = 0;
  
  sendMessage(text: string, sender: string): void {
    const message: Message = {
      id: ++this.messageId,
      text,
      timestamp: new Date(),
      sender
    };
    
    const currentMessages = this.messages$.value;
    this.messages$.next([...currentMessages, message]);
  }
  
  getMessages(): Observable<Message[]> {
    return this.messages$.asObservable();
  }
  
  clearMessages(): void {
    this.messages$.next([]);
  }
}
```

**sender.component.ts**
```typescript
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { MessageService } from './message.service';

@Component({
  selector: 'app-sender',
  standalone: true,
  imports: [FormsModule, CommonModule],
{% raw %}
  template: `
    <div class="sender">
      <h3>Enviar Mensagem</h3>
      <input [(ngModel)]="messageText" placeholder="Digite sua mensagem" name="message">
      <button (click)="sendMessage()" [disabled]="!messageText.trim()">
        Enviar
      </button>
      <button (click)="clearMessages()">Limpar Todas</button>
    </div>
  `,
  styles: [`
{% endraw %}
    .sender {
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      margin-bottom: 1rem;
    }
    
    input {
      width: 100%;
      padding: 0.5rem;
      margin-bottom: 0.5rem;
    }
    
    button {
      margin-right: 0.5rem;
    }
  `]
})
export class SenderComponent {
  messageText: string = '';
  
  constructor(private messageService: MessageService) {}
  
  sendMessage(): void {
    if (this.messageText.trim()) {
      this.messageService.sendMessage(this.messageText, 'Sender');
      this.messageText = '';
    }
  }
  
  clearMessages(): void {
    this.messageService.clearMessages();
  }
}
```

**receiver.component.ts**
{% raw %}
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { MessageService, Message } from './message.service';

@Component({
  selector: 'app-receiver',
  standalone: true,
  imports: [CommonModule],
{% raw %}
  template: `
    <div class="receiver">
      <h3>Mensagens Recebidas</h3>
      @if (messages.length === 0) {
        <p>Nenhuma mensagem ainda</p>
      } @else {
        <ul>
          @for (message of messages; track message.id) {
            <li>
              <strong>{{ message.sender }}:</strong> {{ message.text }}
              <small>{{ message.timestamp | date:'short' }}</small>
            </li>
          }
        </ul>
      }
    </div>
  `,
  styles: [`
{% endraw %}
    .receiver {
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    
    ul {
      list-style: none;
      padding: 0;
    }
    
    li {
      padding: 0.5rem;
      margin-bottom: 0.5rem;
      background-color: #f9f9f9;
      border-radius: 4px;
    }
    
    small {
      display: block;
      color: #666;
      font-size: 0.875rem;
    }
  `]
})
export class ReceiverComponent implements OnInit, OnDestroy {
  messages: Message[] = [];
  private subscription?: Subscription;
  
  constructor(private messageService: MessageService) {}
  
  ngOnInit(): void {
    this.subscription = this.messageService.getMessages().subscribe(
      messages => {
        this.messages = messages;
      }
    );
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
}
```
{% endraw %}

**parent.component.ts**
```typescript
import { Component } from '@angular/core';
import { SenderComponent } from './sender.component';
import { ReceiverComponent } from './receiver.component';

@Component({
  selector: 'app-parent',
  standalone: true,
  imports: [SenderComponent, ReceiverComponent],
{% raw %}
  template: `
    <div>
      <h2>Comunicação via Serviço</h2>
      <app-sender></app-sender>
      <app-receiver></app-receiver>
    </div>
  `
{% endraw %}
})
export class ParentComponent {}
```

**Explicação da Solução**:

1. MessageService usa BehaviorSubject para estado compartilhado
2. sendMessage adiciona nova mensagem ao estado
3. getMessages retorna Observable para subscribers
4. SenderComponent envia mensagens via serviço
5. ReceiverComponent recebe mensagens via subscription
6. Subscription é gerenciada adequadamente
7. Componentes irmãos se comunicam sem relação direta

---

## Testes

### Casos de Teste

**Teste 1**: Envio funciona
- **Input**: Enviar mensagem do Sender
- **Output Esperado**: Mensagem aparece no Receiver

**Teste 2**: Múltiplos receivers funcionam
- **Input**: Criar múltiplos receivers
- **Output Esperado**: Todos recebem mensagens

**Teste 3**: Limpar funciona
- **Input**: Clicar em "Limpar Todas"
- **Output Esperado**: Todas mensagens são removidas

---

## Extensões (Opcional)

1. **Filtros**: Adicione filtros por sender
2. **Persistência**: Salve mensagens no localStorage
3. **Múltiplos Senders**: Suporte para múltiplos senders

---

## Referências Úteis

- **[Component Communication](https://angular.io/guide/component-interaction#parent-and-children-communicate-via-a-service)**: Guia comunicação via serviço
- **[BehaviorSubject](https://rxjs.dev/api/index/class/BehaviorSubject)**: Documentação BehaviorSubject

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

