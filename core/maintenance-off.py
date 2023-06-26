import subprocess
import sys

# Get arguments
host, port, username, password, directory, appname = sys.argv[1:]

cache_command = 'php artisan cache:clear && php artisan up'
full_command = f"plink -l {username} -pw {password} -P {port} -batch {host} \"cd {directory} && ls && php artisan up && exit\""

# Execute the command
subprocess.run(full_command, shell=True)
