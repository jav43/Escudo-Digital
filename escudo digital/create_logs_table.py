import sqlite3

# Conectar ao banco de dados
conn = sqlite3.connect('database.db')
c = conn.cursor()

# Criar a tabela access_logs
c.execute('''
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_type TEXT NOT NULL, -- 'client' ou 'doctor'
        user_id INTEGER NOT NULL,
        user_name TEXT NOT NULL,
        email TEXT NOT NULL,
        action TEXT NOT NULL, -- 'login', 'logout', etc.
        timestamp TEXT NOT NULL, -- Data e hora do acesso
        ip_address TEXT -- Endereço IP do usuário
    )
''')

# Confirmar e fechar
conn.commit()
conn.close()

print("Tabela access_logs criada com sucesso!")