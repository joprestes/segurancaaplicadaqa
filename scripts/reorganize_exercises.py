#!/usr/bin/env python3
"""
Script para reorganizar exercises.yml - Reduzir exercícios para 3-5 por aula
"""
import yaml
import sys

# IDs dos exercícios a REMOVER
EXERCICIOS_REMOVER = [
    # Aula 2.1 - Remover 1
    'lesson-2-1-exercise-5-compare-sast-tools',
    
    # Aula 2.4 - Remover 5
    'lesson-2-4-exercise-2-dependabot-setup',
    'lesson-2-4-exercise-5-secret-scanning',
    'lesson-2-4-exercise-6-full-pipeline',
    'lesson-2-4-exercise-7-dashboard-metrics',
    'lesson-2-4-exercise-8-pipeline-debugging',
    
    # Aula 2.5 - Remover 5
    'lesson-2-5-exercise-2-dependabot-config',
    'lesson-2-5-exercise-4-license-compliance',
    'lesson-2-5-exercise-5-dependency-update-strategy',
    'lesson-2-5-exercise-7-supply-chain-security',
    'lesson-2-5-exercise-9-tool-cost-benefit',
]

# Renumeração de exercícios (old_id -> new_id)
RENUMERAR = {
    # Aula 2.1
    'lesson-2-1-exercise-6-security-vs-delivery': 'lesson-2-1-exercise-5-security-vs-delivery',
    
    # Aula 2.4
    'lesson-2-4-exercise-3-dast-cicd': 'lesson-2-4-exercise-2-dast-cicd',
    'lesson-2-4-exercise-4-quality-gates': 'lesson-2-4-exercise-3-quality-gates',
    'lesson-2-4-exercise-9-pipeline-optimization': 'lesson-2-4-exercise-4-pipeline-optimization',
    'lesson-2-4-exercise-10-security-policy': 'lesson-2-4-exercise-5-security-policy',
    
    # Aula 2.5
    'lesson-2-5-exercise-3-npm-audit': 'lesson-2-5-exercise-2-npm-audit',
    'lesson-2-5-exercise-6-sbom-generation': 'lesson-2-5-exercise-3-sbom-generation',
    'lesson-2-5-exercise-8-cve-war-room': 'lesson-2-5-exercise-4-cve-war-room',
    'lesson-2-5-exercise-10-no-patch-available': 'lesson-2-5-exercise-5-no-patch-available',
}

def main():
    arquivo = '_data/exercises.yml'
    
    # Carregar YAML
    with open(arquivo, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    if 'exercises' not in data or not isinstance(data['exercises'], list):
        print("❌ Formato inválido - esperado 'exercises' como lista")
        sys.exit(1)
    
    exercicios_originais = len(data['exercises'])
    
    # Filtrar exercícios (remover os da lista)
    data['exercises'] = [
        ex for ex in data['exercises']
        if ex.get('id') not in EXERCICIOS_REMOVER
    ]
    
    exercicios_apos_remocao = len(data['exercises'])
    removidos = exercicios_originais - exercicios_apos_remocao
    
    # Renumerar exercícios
    renumerados = 0
    for ex in data['exercises']:
        old_id = ex.get('id')
        if old_id in RENUMERAR:
            new_id = RENUMERAR[old_id]
            ex['id'] = new_id
            
            # Atualizar title (trocar número)
            if 'title' in ex:
                # Extrair número antigo e novo
                old_num = old_id.split('exercise-')[1].split('-')[0]
                new_num = new_id.split('exercise-')[1].split('-')[0]
                ex['title'] = ex['title'].replace(f'2.{old_num.split("-")[0]}.{old_num}:', f'2.{new_num.split("-")[0]}.{new_num}:')
            
            # Atualizar slug se necessário
            if 'slug' in ex:
                # Slug geralmente não tem número, manter igual
                pass
            
            # Atualizar URL
            if 'url' in ex:
                ex['url'] = ex['url'].replace(old_id, new_id)
            
            # Atualizar order
            if 'order' in ex:
                new_order = int(new_num) if new_num.isdigit() else ex['order']
                ex['order'] = new_order
            
            renumerados += 1
    
    # Salvar YAML
    with open(arquivo, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    print(f"✅ Arquivo atualizado: {arquivo}")
    print(f"📊 Exercícios removidos: {removidos}")
    print(f"🔢 Exercícios renumerados: {renumerados}")
    print(f"📝 Total de exercícios: {exercicios_apos_remocao}")
    
    # Contar exercícios por aula
    print("\n📊 Contagem por aula:")
    for lesson_id in ['lesson-2-1', 'lesson-2-2', 'lesson-2-3', 'lesson-2-4', 'lesson-2-5']:
        count = sum(1 for ex in data['exercises'] if ex.get('lesson_id') == lesson_id and 'intro' not in ex.get('id', ''))
        print(f"  {lesson_id}: {count} exercícios")

if __name__ == '__main__':
    main()
