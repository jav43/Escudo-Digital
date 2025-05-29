import sqlite3

def update_database():
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            # Verificar se a coluna já existe
            c.execute("PRAGMA table_info(failed_logins)")
            columns = [column[1] for column in c.fetchall()]
            
            if 'user_type' not in columns:
                # Adicionar a nova coluna
                c.execute('''ALTER TABLE failed_logins 
                           ADD COLUMN user_type TEXT DEFAULT 'unknown' ''')
                print("Coluna user_type adicionada com sucesso!")
            else:
                print("Coluna user_type já existe!")
                
            conn.commit()
    except sqlite3.Error as e:
        print(f"Erro ao atualizar o banco de dados: {e}")

if __name__ == '__main__':
    update_database() 