# suspicious-ip-nginx-log
Python script that can detect suspicious activity on your nginx server, from checking your “access” log.

Script de Pyhton que detecta actividad sospechosa en u servidor en nginx, analizando tu log de "access".


Ejemplo de salida / Output example:

IPs table:
+-----------------+----------------+--------------------------------------------------+
|        IP       | Total activity |                  Vulnerability                   |
+-----------------+----------------+--------------------------------------------------+
|   1.1.1.1       |       4        |           Command Injection (2 times)            |
|                 |                |         Malicious Bot Activity (2 times)         |
+-----------------+----------------+--------------------------------------------------+
|  2.2.2.2        |       4        |           Command Injection (4 times)            |
+-----------------+----------------+--------------------------------------------------+
|  3.3.3.3        |       60       |           Command Injection (35 times)           |
|                 |                | File Access Attempt (sensitive files) (20 times) |
|                 |                |          Admin Access Attempt (1 times)          |
|                 |                |              API Scanning (2 times)              |
|                 |                |      Path Scanning (common paths) (2 times)      |
+-----------------+----------------+--------------------------------------------------+
