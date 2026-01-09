---
layout: exercise
title: "Exercício 1.5.2: Validação PCI-DSS"
slug: "pci-dss-validacao"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Intermediário"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-5-exercise-2-pci-dss-validacao/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/compliance-regulamentacoes/
---

## Objetivo

Este exercício tem como objetivo **validar compliance PCI-DSS** através da criação de testes e validação dos 12 requisitos PCI-DSS.

Ao completar este exercício, você será capaz de:

- Entender os 12 requisitos PCI-DSS
- Criar testes de validação PCI-DSS
- Validar controles de segurança de pagamentos
- Preparar evidências para auditoria PCI-DSS

---

## Descrição

Você precisa validar que uma aplicação de ecommerce está em conformidade com PCI-DSS, focando nos requisitos relacionados a dados de cartão de crédito.

### Contexto

PCI-DSS exige controles rigorosos para proteger dados de cartão. Como QA, você precisa validar que esses controles estão implementados e funcionando.

---

## Requisitos

### Parte 1: Entender Requisitos PCI-DSS

Revise os 12 requisitos PCI-DSS:

**Grupo 1: Construir e Manter Rede Segura**
- Requisito 1: Instalar e manter firewall
- Requisito 2: Não usar senhas padrão

**Grupo 2: Proteger Dados do Portador**
- Requisito 3: Proteger dados armazenados
- Requisito 4: Criptografar dados em trânsito

**Grupo 3: Manter Programa de Gestão de Vulnerabilidades**
- Requisito 5: Usar e atualizar antivírus
- Requisito 6: Desenvolver e manter sistemas seguros

**Grupo 4: Implementar Medidas de Controle de Acesso**
- Requisito 7: Restringir acesso por necessidade de negócio
- Requisito 8: Identificar e autenticar acesso
- Requisito 9: Restringir acesso físico a dados

**Grupo 5: Monitorar e Testar Redes**
- Requisito 10: Rastrear e monitorar acesso
- Requisito 11: Testar regularmente sistemas

**Grupo 6: Manter Política de Segurança**
- Requisito 12: Manter política que aborde segurança

---

### Parte 2: Criar Testes de Validação

Crie testes para validar cada requisito:

**Template de Teste**:
```markdown
## Requisito PCI-DSS [Número]: [Nome]

### Objetivo
[O que este requisito protege]

### Controles Esperados
- [ ] Controle 1: [Descrição]
- [ ] Controle 2: [Descrição]

### Casos de Teste
1. **Teste**: [Nome do teste]
   - **Passos**: [Passos para executar]
   - **Resultado Esperado**: [O que deve acontecer]
   - **Evidência**: [Como documentar]

2. **Teste**: [Nome do teste]
   - **Passos**: [Passos para executar]
   - **Resultado Esperado**: [O que deve acontecer]
   - **Evidência**: [Como documentar]
```

---

### Parte 3: Validar Requisitos Críticos

Foque nos requisitos mais críticos para QA:

**Requisito 3: Proteger Dados Armazenados**

**Tarefas**:
- [ ] Validar que dados de cartão não são armazenados em texto plano
- [ ] Validar que apenas últimos 4 dígitos são exibidos
- [ ] Validar que CVV nunca é armazenado
- [ ] Validar que tokenização está implementada
- [ ] Validar que dados estão criptografados

**Casos de Teste**:
- Teste: Tentar armazenar número completo de cartão → Deve falhar ou tokenizar
- Teste: Exibir dados de cartão → Apenas últimos 4 dígitos devem aparecer
- Teste: Buscar CVV no banco de dados → Não deve existir
- Teste: Validar tokenização → Dados devem ser substituídos por tokens

---

**Requisito 4: Criptografar Dados em Trânsito**

**Tarefas**:
- [ ] Validar que TLS 1.2+ está sendo usado
- [ ] Validar que certificados SSL são válidos
- [ ] Validar que dados não trafegam em HTTP
- [ ] Validar que conexões são seguras

**Casos de Teste**:
- Teste: Acessar endpoint de pagamento via HTTP → Deve redirecionar para HTTPS
- Teste: Verificar versão TLS → Deve ser 1.2 ou superior
- Teste: Validar certificado SSL → Deve ser válido e não expirado
- Teste: Interceptar tráfego → Dados devem estar criptografados

---

**Requisito 7: Restringir Acesso**

**Tarefas**:
- [ ] Validar que acesso a dados de cartão é restrito
- [ ] Validar que apenas usuários autorizados têm acesso
- [ ] Validar que princípio do menor privilégio está aplicado
- [ ] Validar que acesso é baseado em necessidade de negócio

**Casos de Teste**:
- Teste: Usuário comum tentar acessar dados de cartão → Deve ser negado
- Teste: Admin acessar dados de cartão → Deve ter acesso autorizado
- Teste: Validar logs de acesso → Acesso deve ser registrado
- Teste: Validar controle de acesso → Apenas roles autorizados têm acesso

---

**Requisito 10: Rastrear e Monitorar Acesso**

**Tarefas**:
- [ ] Validar que logs de acesso estão sendo registrados
- [ ] Validar que logs são imutáveis
- [ ] Validar que logs são revisados regularmente
- [ ] Validar que alertas são configurados

**Casos de Teste**:
- Teste: Acessar dados de cartão → Log deve ser registrado
- Teste: Tentar modificar log → Deve falhar (imutável)
- Teste: Validar formato de log → Deve conter informações necessárias
- Teste: Validar retenção de logs → Logs devem ser mantidos por período adequado

---

### Parte 4: Criar Plano de Validação

Crie plano completo de validação:

**Tarefas**:
- [ ] Listar todos os requisitos PCI-DSS
- [ ] Criar testes para cada requisito
- [ ] Priorizar testes críticos
- [ ] Documentar evidências necessárias
- [ ] Criar cronograma de validação

**Template de Plano**:
```markdown
# Plano de Validação PCI-DSS

## Fase 1: Requisitos Críticos (Semana 1)
- Requisito 3: Proteger dados armazenados
- Requisito 4: Criptografar dados em trânsito
- Requisito 7: Restringir acesso

## Fase 2: Requisitos de Segurança (Semana 2)
- Requisito 1: Firewall
- Requisito 2: Senhas padrão
- Requisito 5: Antivírus
- Requisito 6: Sistemas seguros

## Fase 3: Monitoramento (Semana 3)
- Requisito 10: Logs
- Requisito 11: Testes regulares
- Requisito 12: Política de segurança

## Evidências
- [ ] Screenshots de testes
- [ ] Logs de acesso
- [ ] Configurações de segurança
- [ ] Documentação de controles
```

---

## Contexto CWI

### Caso Real: Validação PCI-DSS em Fintech

Em um projeto fintech da CWI, validamos compliance PCI-DSS:

**Estratégia**:
- Foco nos requisitos críticos primeiro
- Testes automatizados quando possível
- Evidências coletadas sistematicamente
- Validação contínua

**Resultado**:
- Compliance PCI-DSS validado
- Evidências prontas para auditoria
- Não conformidades corrigidas
- Certificação PCI-DSS obtida

---

## Dicas

1. **Foque no crítico**: Dados de cartão são prioridade
2. **Documente evidências**: Facilita auditoria
3. **Automatize quando possível**: Testes repetitivos
4. **Colabore**: Envolva time de segurança
5. **Revise regularmente**: PCI-DSS evolui

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.5.3: Controles SOC2
- Exercício 1.5.4: Compliance por Setor
- Validar compliance PCI-DSS em projetos reais

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Exercício 1.5.1 (Checklist LGPD)
