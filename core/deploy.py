import subprocess
import sys

# Get arguments
host, port, username, password, directory, appname, gitrepo = sys.argv[1:]

# Step 1: Connect to your server (SSH) with password authentication using plink
plink_command = f'plink -l {username} -pw {password} -P {port} -batch {host}'

# Step 2: Navigate to your Laravel application directory
cd_command = f'cd {directory}'

# List of additional commands to execute
additional_commands = [
    # Add your commands here, one per line
    'echo "Web App Down"',
    f'rm -rf {appname}',
    f'git clone {gitrepo}',
    f'cp -R {appname}/* .',
    f'rm -rf {appname}',
    'COMPOSER_MEMORY_LIMIT=-1 composer2 update',
    'php artisan cache:clear',
    'php artisan up'
]

# Construct the full command
command_lines = [cd_command] + additional_commands + ['exit']
commands_joined = ' && '.join(command_lines)
full_command = f"{plink_command} \"{commands_joined}\""

# Execute the command
subprocess.run(full_command, shell=True)
