import json

with open('entity_configs.json') as f:
    config = json.load(f)

print(f"Total start_commands: {len(config['start_commands'])}\n")

for i, cmd in enumerate(config['start_commands'], 1):
    entity = cmd.get('entity', '?')
    command = cmd.get('command', '')
    port = '?'
    if '--port' in command:
        port = command.split('--port ')[-1].split()[0]
    print(f"{i}. {entity:15} port={port}")
