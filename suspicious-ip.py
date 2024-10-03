import re
from collections import defaultdict
from prettytable import PrettyTable

# Archivo de log - Your log file
log_file = './_var_log_nginx_access.log'

# Definir las vulnerabilidades y sus patrones en regex
# Defining vulnerabilities and their patterns in regex

vulnerability_patterns = {
    "Brute Force (login attempts)": r'POST .*(/wp-login.php|/login|/admin)',
    "SQL Injection": r"(SELECT|INSERT|DELETE|UNION|DROP|UPDATE|REPLACE).*",
    "Command Injection": r"(cmd=|;|&&|\|\||cat |ls |wget |curl )",
    "Path Scanning (common paths)": r"GET .*(wp-config.php|/phpmyadmin/|/backup|/env|/config)",
    "Directory Traversal": r'(\.\./)+',
    "Cross-Site Scripting (XSS)": r'<script.*?>|%3Cscript.*?%3E',
    "File Access Attempt (sensitive files)": r'(php\.ini|\.htaccess|\.env|web\.config|nginx\.conf)',
    "Port Scanning (common ports)": r'(:80|:443|:22)',
    "Admin Access Attempt": r'/admin|/administrator|/wp-admin|/wp-login|/login|/dashboard|/cpanel',
    "API Scanning": r'/api|/graphql|/v1|/v2|/json|/rest',
    "File Upload Attempt": r'multipart/form-data|Content-Disposition.*filename',
    "PHP Code Injection": r'\.php\?.*=\$',
    "Malicious Bot Activity": r'(bot|crawler|spider|scanner)',
    "Web Shell Access": r'(cmd|sh|bash|powershell)\.php',
    "Malicious File Upload (theme/plugin)": r'(/themes/|/plugins/|/templates/).*(\.php|\.asp|\.jsp)'
}

# Leer el archivo de log
# Read log file
def read_log_file(log_file):
    with open(log_file, 'r') as file:
        return file.readlines()

# Función para analizar el log y detectar actividad sospechosa
# Function to analyze the log and detect suspicious activity
def analyze_log(log_file):
    log_lines = read_log_file(log_file)
    suspicious_ips = defaultdict(lambda: defaultdict(int))  # Diccionario para contar actividades sospechosas por IP - Dictionary to count suspicious activity by IP

    for line in log_lines:
        for vulnerability, pattern in vulnerability_patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)  # Extraer la IP - extract the IP 
                if ip_match:
                    ip = ip_match.group(0)
                    suspicious_ips[ip][vulnerability] += 1  # Incrementar el contador para la IP y la vulnerabilidad - Increasing the counter for IP and vulnerability

    return suspicious_ips

# Crear la tabla - Create table
table = PrettyTable()

# Agregar encabezados - Add headers
table.field_names = ["IP", "Total activity", "Vulnerability"]

# Mostrar las IPs con actividad sospechosa - Show IPs with suspicious activity
def display_suspicious_ips(suspicious_ips):
    print("IPs table:")
    
    for ip, activities in suspicious_ips.items():
        total_suspect_activities = sum(activities.values())
            
        if total_suspect_activities > 3:  # Si hay más de 3 actividades sospechosas - If there are more than 3 suspicious activities
            vulnerabilities = []
            for vulnerability, count in activities.items():
                vulnerabilities.append(f"{vulnerability} ({count} times)")

            vulnerabilities_str = "\n".join(vulnerabilities)
            table.add_row([ip, total_suspect_activities, vulnerabilities_str,], divider=True)
                


# Ejecutar el análisis y mostrar los resultados 
# Run the analysis and display the results
suspicious_ips = analyze_log(log_file)
display_suspicious_ips(suspicious_ips)
print(table)
