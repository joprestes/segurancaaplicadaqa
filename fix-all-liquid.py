#!/usr/bin/env python3
import re
from pathlib import Path

def protect_code_blocks(content):
    lines = content.split('\n')
    result = []
    in_code_block = False
    code_block_start = -1
    code_block_lang = None
    code_block_lines = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        if line.strip().startswith('```'):
            if in_code_block:
                code_block_content = '\n'.join(code_block_lines)
                if '{{' in code_block_content and ('|' in code_block_content or '?' in code_block_content or '===' in code_block_content or '||' in code_block_content):
                    result.append('{% raw %}')
                    result.append(f'```{code_block_lang}')
                    result.extend(code_block_lines)
                    result.append('```')
                    result.append('{% endraw %}')
                else:
                    result.append(f'```{code_block_lang}')
                    result.extend(code_block_lines)
                    result.append('```')
                
                in_code_block = False
                code_block_start = -1
                code_block_lang = None
                code_block_lines = []
            else:
                in_code_block = True
                code_block_start = i
                match = re.match(r'```(\w*)', line)
                code_block_lang = match.group(1) if match else ''
            i += 1
            continue
        
        if in_code_block:
            code_block_lines.append(line)
        else:
            if re.search(r'\{\{.*\|.*\}\}', line) or re.search(r'\{\{.*\?.*:.*\}\}', line) or re.search(r'\{\{.*===.*\}\}', line) or re.search(r'\{\{.*\|\|.*\}\}', line) or re.search(r'\{\{.*\+.*\}\}', line):
                if not (line.strip().startswith('{% raw %}') or line.strip().startswith('{% endraw %}')):
                    if not any('{% raw %}' in l for l in result[-5:]):
                        result.append('{% raw %}')
                    result.append(line)
                    if i + 1 >= len(lines) or not (re.search(r'\{\{.*\|.*\}\}', lines[i+1]) or re.search(r'\{\{.*\?.*:.*\}\}', lines[i+1]) or re.search(r'\{\{.*===.*\}\}', lines[i+1]) or re.search(r'\{\{.*\|\|.*\}\}', lines[i+1]) or re.search(r'\{\{.*\+.*\}\}', lines[i+1])):
                        result.append('{% endraw %}')
                else:
                    result.append(line)
            else:
                if any('{% raw %}' in l for l in result[-5:]) and not any('{% endraw %}' in l for l in result[-5:]):
                    if not (re.search(r'\{\{.*\|.*\}\}', line) or re.search(r'\{\{.*\?.*:.*\}\}', line) or re.search(r'\{\{.*===.*\}\}', line) or re.search(r'\{\{.*\|\|.*\}\}', line) or re.search(r'\{\{.*\+.*\}\}', line)):
                        result.append('{% endraw %}')
                result.append(line)
        
        i += 1
    
    if in_code_block:
        code_block_content = '\n'.join(code_block_lines)
        if '{{' in code_block_content:
            result.append('{% raw %}')
            result.append(f'```{code_block_lang}')
            result.extend(code_block_lines)
            result.append('```')
            result.append('{% endraw %}')
        else:
            result.append(f'```{code_block_lang}')
            result.extend(code_block_lines)
            result.append('```')
    
    final_content = '\n'.join(result)
    
    final_content = re.sub(r'\{% raw %\}\s*\{% raw %\}', '{% raw %}', final_content)
    final_content = re.sub(r'\{% endraw %\}\s*\{% endraw %\}', '{% endraw %}', final_content)
    
    return final_content

def process_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if '{{' in content:
            new_content = protect_code_blocks(content)
            if new_content != content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"Fixed: {file_path}")
                return True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    return False

def main():
    base_dir = Path(__file__).parent
    modules_dir = base_dir / 'modules'
    
    if not modules_dir.exists():
        print(f"Modules directory not found: {modules_dir}")
        return
    
    fixed_count = 0
    for md_file in modules_dir.rglob('*.md'):
        if process_file(md_file):
            fixed_count += 1
    
    print(f"\nTotal files fixed: {fixed_count}")

if __name__ == '__main__':
    main()

