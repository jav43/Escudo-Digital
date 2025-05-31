from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3
from datetime import datetime, timedelta
import re
import os
import holidays

app = Flask(__name__)

# Geração segura de chave secreta (substitua por uma chave fixa segura em produção)
app.config['SECRET_KEY'] = os.urandom(24).hex()  # Gera uma chave aleatória para desenvolvimento
bcrypt = Bcrypt(app)

# Lista de feriados brasileiros
br_holidays = holidays.BR()

# Database initialization
def update_database_structure():
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            # Verificar se a coluna doctor_id existe
            c.execute("PRAGMA table_info(appointments)")
            columns = [column[1] for column in c.fetchall()]
            
            # Se não existir, adicionar a coluna
            if 'doctor_id' not in columns:
                c.execute("""
                    ALTER TABLE appointments
                    ADD COLUMN doctor_id INTEGER REFERENCES doctor(id)
                """)
                conn.commit()
                print("Coluna doctor_id adicionada com sucesso!")
    except sqlite3.Error as e:
        print(f"Erro ao atualizar estrutura do banco: {e}")

def init_db():
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            # Remover a tabela login_attempts antiga se existir
            c.execute("DROP TABLE IF EXISTS login_attempts")
            
            # Criar nova tabela login_attempts com estrutura correta
            c.execute('''CREATE TABLE login_attempts (
                email TEXT PRIMARY KEY,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocked_until TIMESTAMP
            )''')
            
            # Criar tabela de médicos se não existir (sem dropar)
            c.execute('''CREATE TABLE IF NOT EXISTS doctor (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                crm TEXT UNIQUE NOT NULL,
                specialty TEXT NOT NULL,
                active INTEGER DEFAULT 1
            )''')
            
            # Verificar se já existe algum médico cadastrado
            c.execute("SELECT COUNT(*) FROM doctor")
            doctor_count = c.fetchone()[0]
            
            # Inserir médico padrão apenas se não houver nenhum médico
            if doctor_count == 0:
                hashed = bcrypt.generate_password_hash('peres321', rounds=10).decode('utf-8')
                c.execute("""
                    INSERT INTO doctor (username, password, name, crm, specialty, active) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, ('doutor', hashed, 'Dr. Peres', 'CRM/SP 123456', 'Clínico Geral', 1))
            
            # Criar outras tabelas
            c.execute('''CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                phone TEXT,
                cpf TEXT
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER,
                doctor_id INTEGER,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                status TEXT DEFAULT 'Agendado',
                notes TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(id),
                FOREIGN KEY (doctor_id) REFERENCES doctor(id)
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS secretary (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )''')
            
            # Recriar a tabela failed_logins com o campo notes
            c.execute("DROP TABLE IF EXISTS failed_logins")
            c.execute('''CREATE TABLE failed_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                timestamp TEXT,
                ip_address TEXT,
                user_type TEXT,
                notes TEXT
            )''')
            
            # Verificar se já existe uma secretária cadastrada
            c.execute("SELECT COUNT(*) FROM secretary WHERE username = 'secretaria'")
            if c.fetchone()[0] == 0:
                hashed = bcrypt.generate_password_hash('sec123', rounds=10).decode('utf-8')
                c.execute("INSERT INTO secretary (username, password) VALUES (?, ?)", ('secretaria', hashed))
            
            conn.commit()
            print("Banco de dados inicializado com sucesso!")
            
            # Atualizar estrutura do banco se necessário
            update_database_structure()
            
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o banco de dados: {e}")

# Validação personalizada para telefone
def validate_phone(form, field):
    if not re.match(r'^\(\d{2}\) \d{5}-\d{4}$', field.data):
        raise ValidationError('Formato inválido. Use (XX) XXXXX-XXXX')

# Validação personalizada para CPF
def validate_cpf(form, field):
    if field.data:  # CPF é opcional
        cpf = re.sub(r'[^0-9]', '', field.data)
        if not re.match(r'^\d{11}$', cpf):
            raise ValidationError('CPF deve conter 11 dígitos')
        
        # Validação do primeiro dígito verificador
        soma = 0
        for i in range(9):
            soma += int(cpf[i]) * (10 - i)
        resto = soma % 11
        digito1 = 0 if resto < 2 else 11 - resto
        
        if int(cpf[9]) != digito1:
            raise ValidationError('CPF inválido')
        
        # Validação do segundo dígito verificador
        soma = 0
        for i in range(10):
            soma += int(cpf[i]) * (11 - i)
        resto = soma % 11
        digito2 = 0 if resto < 2 else 11 - resto
        
        if int(cpf[10]) != digito2:
            raise ValidationError('CPF inválido')

# Forms
class ClientLoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class ClientRegisterForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    phone = StringField('Telefone', validators=[DataRequired(), validate_phone])
    cpf = StringField('CPF', validators=[validate_cpf])
    submit = SubmitField('Cadastrar')

def is_valid_appointment_date(date):
    """
    Verifica se a data é válida para agendamento:
    - Não pode ser fim de semana
    - Não pode ser feriado
    - Não pode ser data passada
    """
    # Converter string para data se necessário
    if isinstance(date, str):
        date = datetime.strptime(date, '%Y-%m-%d').date()
    elif isinstance(date, datetime):
        date = date.date()
    
    today = datetime.now().date()
    
    # Verificar se é data passada
    if date < today:
        return False, "Não é possível agendar para datas passadas"
    
    # Verificar se é fim de semana (5 = Sábado, 6 = Domingo)
    if date.weekday() >= 5:
        return False, "Não realizamos atendimento aos finais de semana"
    
    # Verificar se é feriado
    if date in br_holidays:
        return False, f"Não realizamos atendimento em feriados ({br_holidays[date]})"
    
    return True, "Data válida para agendamento"

class ScheduleForm(FlaskForm):
    doctor = SelectField('Médico', validators=[DataRequired(message='Selecione um médico')])
    date = DateField('Data', validators=[DataRequired(message='Selecione uma data')])
    time = SelectField('Horário', choices=[
        ('08:00', '08:00'), ('09:00', '09:00'), ('10:00', '10:00'), ('11:00', '11:00'),
        ('13:00', '13:00'), ('14:00', '14:00'), ('15:00', '15:00'), ('16:00', '16:00'),
        ('17:00', '17:00'), ('18:00', '18:00')
    ], validators=[DataRequired(message='Selecione um horário')])

    def validate_date(self, field):
        is_valid, message = is_valid_appointment_date(field.data)
        if not is_valid:
            raise ValidationError(message)

class DoctorLoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class DateRangeForm(FlaskForm):
    start_date = DateField('Data Inicial', validators=[DataRequired()])
    end_date = DateField('Data Final', validators=[DataRequired()])
    submit = SubmitField('Filtrar')

class SecretaryLoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

def validate_crm(form, field):
    # Remove espaços e converte para maiúsculas
    crm = field.data.strip().upper()
    
    # Verifica se está no formato correto (CRM/UF + números)
    if not re.match(r'^CRM/[A-Z]{2}\s*\d{4,6}$', crm):
        raise ValidationError('Formato inválido. Use: CRM/UF + número (ex: CRM/SP 123456)')

class DoctorRegisterForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    name = StringField('Nome Completo', validators=[DataRequired(), Length(min=3, max=100)])
    crm = StringField('CRM', validators=[DataRequired(), validate_crm], 
                     render_kw={"placeholder": "Ex: CRM/SP 123456"})
    specialty = StringField('Especialidade', validators=[DataRequired()])
    submit = SubmitField('Cadastrar Médico')

# Input sanitization
def sanitize_input(text):
    if not text:
        return text
    # Remove caracteres especiais e HTML, mantendo apenas letras, números e pontuação básica
    return re.sub(r'[^a-zA-Z0-9@\s\.\-_\(\)]', '', text)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    form = ClientLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                
                # Primeiro verificar se a conta está bloqueada
                c.execute("""
                    SELECT blocked_until 
                    FROM login_attempts 
                    WHERE email = ?
                """, (email,))
                result = c.fetchone()
                
                if result and result[0]:
                    blocked_until = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
                    if datetime.now() < blocked_until:
                        remaining_seconds = (blocked_until - datetime.now()).total_seconds()
                        remaining_minutes = int(remaining_seconds / 60)
                        remaining_seconds = int(remaining_seconds % 60)
                        
                        if remaining_minutes > 0:
                            time_msg = f"{remaining_minutes} minutos"
                            if remaining_seconds > 0:
                                time_msg += f" e {remaining_seconds} segundos"
                        else:
                            time_msg = f"{remaining_seconds} segundos"
                            
                        flash(f"Conta bloqueada. Tente novamente em {time_msg}.", 'danger')
                        return render_template('client_login.html', form=form)
                
                # Se não está bloqueada, verificar credenciais
                c.execute("SELECT * FROM clients WHERE email = ?", (email,))
                client = c.fetchone()
                
                if client and bcrypt.check_password_hash(client[3], password):
                    # Login bem sucedido
                    record_login_attempt(email, True)
                    session['client_id'] = client[0]
                    flash('Login bem-sucedido!', 'success')
                    return redirect(url_for('client_dashboard'))
                else:
                    # Login falhou
                    # Verificar tentativas antes de registrar a falha
                    can_attempt, message = check_login_attempts(email)
                    if not can_attempt:
                        flash(message, 'danger')
                    else:
                        record_login_attempt(email, False)
                        if message:
                            flash(message, 'warning')  # Mensagem de tentativas em amarelo
                        flash('E-mail ou senha inválidos', 'danger')
                
                # Registrar tentativa falha de login
                c.execute("""
                    INSERT INTO failed_logins (username, timestamp, ip_address, user_type) 
                    VALUES (?, ?, ?, ?)
                """, (email, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                      request.remote_addr, 'client'))
                conn.commit()
                
        except sqlite3.Error as e:
            flash(f'Erro ao acessar o banco de dados: {e}', 'danger')
    return render_template('client_login.html', form=form)

@app.route('/client/register', methods=['GET', 'POST'])
def client_register():
    form = ClientRegisterForm()
    if form.validate_on_submit():
        name = sanitize_input(form.name.data)
        email = sanitize_input(form.email.data)
        phone = sanitize_input(form.phone.data)
        cpf = form.cpf.data  # Não sanitizar CPF, apenas validar
        hashed = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute("INSERT INTO clients (name, email, password, phone, cpf) VALUES (?, ?, ?, ?, ?)",
                          (name, email, hashed, phone, cpf))
                conn.commit()
                flash('Cadastro realizado com sucesso! Faça login.', 'success')
                return redirect(url_for('client_login'))
        except sqlite3.IntegrityError:
            flash('E-mail já cadastrado', 'danger')
    return render_template('client_register.html', form=form)

@app.route('/client/dashboard')
def client_dashboard():
    if 'client_id' not in session:
        return redirect(url_for('client_login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT name, email, phone, cpf FROM clients WHERE id = ?", (session['client_id'],))
        client = c.fetchone()
    return render_template('client_dashboard.html', client=client)

@app.route('/client/schedule', methods=['GET', 'POST'])
def client_schedule():
    if 'client_id' not in session:
        return redirect(url_for('client_login'))
    
    form = ScheduleForm()
    
    # Buscar médicos ativos para o select
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id, name, specialty FROM doctor WHERE active = 1")
            doctors = c.fetchall()
            if not doctors:
                flash('Não há médicos disponíveis para agendamento.', 'warning')
                return redirect(url_for('client_dashboard'))
            form.doctor.choices = [(str(d[0]), f"Dr(a). {d[1]} - {d[2]}") for d in doctors]
    except sqlite3.Error as e:
        print(f"Erro ao buscar médicos: {e}")
        flash('Erro ao carregar lista de médicos.', 'danger')
        return redirect(url_for('client_dashboard'))
    
    if request.method == 'POST':
        print("Dados recebidos do formulário:")
        print(f"Doctor: {request.form.get('doctor')}")
        print(f"Date: {request.form.get('date')}")
        print(f"Time: {request.form.get('time')}")
        
        if form.validate_on_submit():
            try:
                doctor_id = int(form.doctor.data)
                date = form.date.data.strftime('%Y-%m-%d')
                time = form.time.data
                client_id = session['client_id']
                
                print("Dados validados:")
                print(f"Client ID: {client_id}")
                print(f"Doctor ID: {doctor_id}")
                print(f"Date: {date}")
                print(f"Time: {time}")
                
                # Verificar a data
                is_valid, message = is_valid_appointment_date(date)
                if not is_valid:
                    flash(message, 'danger')
                    return render_template('client_schedule.html', form=form)
                
                with sqlite3.connect('database.db') as conn:
                    c = conn.cursor()
                    
                    # Verificar se o médico existe e está ativo
                    c.execute("SELECT id FROM doctor WHERE id = ? AND active = 1", (doctor_id,))
                    if not c.fetchone():
                        flash('Médico não encontrado ou inativo.', 'danger')
                        return render_template('client_schedule.html', form=form)
                    
                    # Verificar disponibilidade do horário
                    c.execute("""
                        SELECT id FROM appointments 
                        WHERE date = ? AND time = ? AND doctor_id = ? AND status = 'Agendado'
                    """, (date, time, doctor_id))
                    
                    if c.fetchone():
                        flash('Horário já reservado para este médico', 'danger')
                        return render_template('client_schedule.html', form=form)
                    
                    try:
                        # Inserir o agendamento
                        c.execute("""
                            INSERT INTO appointments (client_id, doctor_id, date, time, status) 
                            VALUES (?, ?, ?, ?, ?)
                        """, (client_id, doctor_id, date, time, 'Agendado'))
                        
                        # Verificar se o registro foi inserido
                        appointment_id = c.lastrowid
                        print(f"ID do novo agendamento: {appointment_id}")
                        
                        # Confirmar a inserção
                        c.execute("SELECT * FROM appointments WHERE id = ?", (appointment_id,))
                        new_appointment = c.fetchone()
                        print(f"Dados do novo agendamento: {new_appointment}")
                        
                        if new_appointment:
                            conn.commit()
                            flash('Consulta agendada com sucesso!', 'success')
                            return redirect(url_for('client_dashboard'))
                        else:
                            conn.rollback()
                            flash('Erro ao salvar o agendamento.', 'danger')
                            
                    except sqlite3.Error as e:
                        conn.rollback()
                        print(f"Erro ao inserir agendamento: {e}")
                        flash('Erro ao salvar o agendamento no banco de dados.', 'danger')
                        
            except ValueError as e:
                print(f"Erro de validação: {e}")
                flash('Dados inválidos no formulário.', 'danger')
            except Exception as e:
                print(f"Erro inesperado: {e}")
                flash('Ocorreu um erro inesperado. Tente novamente.', 'danger')
        else:
            print("Erros de validação do formulário:")
            for field, errors in form.errors.items():
                print(f"{field}: {', '.join(errors)}")
            flash('Por favor, preencha todos os campos corretamente.', 'danger')
    
    return render_template('client_schedule.html', form=form)

@app.route('/client/history')
def client_history():
    if 'client_id' not in session:
        return redirect(url_for('client_login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT a.date, a.time, a.status, a.notes, c.cpf FROM appointments a JOIN clients c ON a.client_id = c.id WHERE a.client_id = ? ORDER BY a.date DESC",
                  (session['client_id'],))
        appointments_raw = c.fetchall()
    
    # Formatar a data para DD/MM/YYYY
    appointments = []
    for appt in appointments_raw:
        date_str = appt[0]
        formatted_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%d/%m/%Y')
        appointments.append((formatted_date, appt[1], appt[2], appt[3], appt[4]))
    
    return render_template('client_history.html', appointments=appointments)

@app.route('/doctor/login', methods=['GET', 'POST'])
def doctor_login():
    form = DoctorLoginForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM doctor WHERE username = ?", (username,))
                doctor = c.fetchone()
                if doctor:
                    print(f"Médico encontrado: {doctor}")
                    if bcrypt.check_password_hash(doctor[2], password):
                        session['doctor_id'] = doctor[0]
                        flash('Login bem-sucedido!', 'success')
                        return redirect(url_for('doctor_dashboard'))
                    else:
                        print("Senha incorreta")
                else:
                    print("Médico não encontrado")
                
                # Registrar tentativa falha de login
                c.execute("""
                    INSERT INTO failed_logins (username, timestamp, ip_address, user_type) 
                    VALUES (?, ?, ?, ?)
                """, (username, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                      request.remote_addr, 'doctor'))
                conn.commit()
                flash('Usuário ou senha inválidos', 'danger')
        except sqlite3.Error as e:
            flash(f'Erro ao acessar o banco de dados: {e}', 'danger')
    return render_template('doctor_login.html', form=form)

@app.route('/doctor/dashboard')
def doctor_dashboard():
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    return render_template('doctor_dashboard.html')

@app.route('/doctor/daily', methods=['GET', 'POST'])
def doctor_daily():
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    
    form = DateRangeForm()
    appointments = []
    start_date = None
    end_date = None

    if form.validate_on_submit():
        start_date = form.start_date.data.strftime('%Y-%m-%d')
        end_date = form.end_date.data.strftime('%Y-%m-%d')
        if start_date > end_date:
            flash('A data inicial não pode ser posterior à data final.', 'danger')
            start_date, end_date = None, None

    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            if start_date and end_date:
                c.execute('''
                    SELECT appointments.id, appointments.date, appointments.time, 
                           c.name, c.email, c.cpf
                    FROM appointments
                    JOIN clients c ON appointments.client_id = c.id
                    WHERE appointments.date BETWEEN ? AND ? 
                    AND appointments.status = 'Agendado'
                    AND appointments.doctor_id = ?
                    ORDER BY appointments.date, appointments.time
                ''', (start_date, end_date, session['doctor_id']))
            else:
                today = datetime.now().strftime('%Y-%m-%d')
                c.execute('''
                    SELECT appointments.id, appointments.date, appointments.time, 
                           c.name, c.email, c.cpf
                    FROM appointments
                    JOIN clients c ON appointments.client_id = c.id
                    WHERE appointments.status = 'Agendado'
                    AND appointments.doctor_id = ?
                    AND appointments.date >= ?
                    ORDER BY appointments.date, appointments.time
                ''', (session['doctor_id'], today))
            
            appointments_raw = c.fetchall()
            
            # Formatar a data para DD/MM/YYYY
            appointments = []
            for appt in appointments_raw:
                date_str = appt[1]
                formatted_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%d/%m/%Y')
                appointments.append((appt[0], formatted_date, appt[2], appt[3], appt[4], appt[5]))

    except sqlite3.Error as e:
        print(f"Erro ao buscar consultas: {e}")
        flash('Erro ao carregar as consultas', 'danger')
        appointments = []

    return render_template('doctor_daily.html', form=form, appointments=appointments, start_date=start_date, end_date=end_date)

@app.route('/doctor/appointment/edit/<int:appointment_id>', methods=['POST'])
def edit_appointment(appointment_id):
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    
    new_date = request.form.get('date')
    new_time = request.form.get('time')
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            # Verificar se o novo horário está disponível
            c.execute("SELECT id FROM appointments WHERE date = ? AND time = ? AND id != ?", 
                     (new_date, new_time, appointment_id))
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Horário já está ocupado'})
            
            # Atualizar o agendamento
            c.execute("""
                UPDATE appointments 
                SET date = ?, time = ? 
                WHERE id = ?
            """, (new_date, new_time, appointment_id))
            conn.commit()
            return jsonify({'success': True, 'message': 'Agendamento atualizado com sucesso'})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': f'Erro ao atualizar: {str(e)}'})

@app.route('/doctor/appointment/delete/<int:appointment_id>', methods=['POST'])
def delete_appointment(appointment_id):
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("DELETE FROM appointments WHERE id = ?", (appointment_id,))
            conn.commit()
            flash('Agendamento excluído com sucesso', 'success')
    except sqlite3.Error as e:
        flash(f'Erro ao excluir agendamento: {str(e)}', 'danger')
    
    return redirect(url_for('doctor_daily'))

@app.route('/doctor/failed_logins')
def doctor_failed_logins():
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT username, timestamp, ip_address FROM failed_logins ORDER BY timestamp DESC")
        failed_logins = c.fetchall()
    return render_template('doctor_failed_logins.html', failed_logins=failed_logins)

@app.route('/doctor/security_logs')
def security_logs():
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            # Buscar todas as tentativas falhas de login
            c.execute("""
                SELECT username, timestamp, ip_address, user_type 
                FROM failed_logins 
                ORDER BY timestamp DESC
                LIMIT 100
            """)
            failed_attempts = c.fetchall()
            
            # Estatísticas
            # Total de tentativas falhas
            c.execute("SELECT COUNT(*) FROM failed_logins")
            total_failed = c.fetchone()[0]
            
            # IPs únicos suspeitos
            c.execute("SELECT COUNT(DISTINCT ip_address) FROM failed_logins")
            unique_ips = c.fetchone()[0]
            
            # Tentativas nas últimas 24 horas
            c.execute("""
                SELECT COUNT(*) FROM failed_logins 
                WHERE timestamp > datetime('now', '-1 day')
            """)
            last_24h = c.fetchone()[0]
            
            stats = {
                'total_failed': total_failed,
                'unique_ips': unique_ips,
                'last_24h': last_24h
            }
            
            return render_template('security_logs.html', 
                                failed_attempts=failed_attempts,
                                stats=stats)
    except sqlite3.Error as e:
        flash(f'Erro ao acessar os logs: {e}', 'danger')
        return redirect(url_for('doctor_dashboard'))

@app.route('/secretary/login', methods=['GET', 'POST'])
def secretary_login():
    form = SecretaryLoginForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM secretary WHERE username = ?", (username,))
                secretary = c.fetchone()
                if secretary and bcrypt.check_password_hash(secretary[2], password):
                    session['secretary_id'] = secretary[0]
                    flash('Login bem-sucedido!', 'success')
                    return redirect(url_for('secretary_dashboard'))
                
                # Registrar tentativa falha de login
                c.execute("""
                    INSERT INTO failed_logins (username, timestamp, ip_address, user_type) 
                    VALUES (?, ?, ?, ?)
                """, (username, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                      request.remote_addr, 'secretary'))
                conn.commit()
                flash('Usuário ou senha inválidos', 'danger')
        except sqlite3.Error as e:
            flash(f'Erro ao acessar o banco de dados: {e}', 'danger')
    return render_template('secretary_login.html', form=form)

@app.route('/secretary/dashboard')
def secretary_dashboard():
    if 'secretary_id' not in session:
        return redirect(url_for('secretary_login'))
    return render_template('secretary_dashboard.html')

@app.route('/secretary/security_logs')
def secretary_security_logs():
    if 'secretary_id' not in session:
        return redirect(url_for('secretary_login'))
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            # Buscar todas as tentativas falhas de login
            c.execute("""
                SELECT username, timestamp, ip_address, user_type 
                FROM failed_logins 
                ORDER BY timestamp DESC
                LIMIT 100
            """)
            failed_attempts = c.fetchall()
            
            # Estatísticas
            c.execute("SELECT COUNT(*) FROM failed_logins")
            total_failed = c.fetchone()[0]
            
            c.execute("SELECT COUNT(DISTINCT ip_address) FROM failed_logins")
            unique_ips = c.fetchone()[0]
            
            c.execute("""
                SELECT COUNT(*) FROM failed_logins 
                WHERE timestamp > datetime('now', '-1 day')
            """)
            last_24h = c.fetchone()[0]
            
            # Buscar contas bloqueadas
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute("""
                SELECT email, attempts, last_attempt, blocked_until
                FROM login_attempts
                WHERE attempts >= 3 
                OR (blocked_until IS NOT NULL AND blocked_until > ?)
                ORDER BY last_attempt DESC
            """, (current_time,))
            blocked_accounts_raw = c.fetchall()
            
            # Formatar dados das contas bloqueadas
            blocked_accounts = []
            current_time = datetime.now()
            
            for account in blocked_accounts_raw:
                is_blocked = False
                if account[3]:  # Se tem blocked_until
                    blocked_time = datetime.strptime(account[3], '%Y-%m-%d %H:%M:%S')
                    is_blocked = current_time < blocked_time
                
                blocked_accounts.append({
                    'email': account[0],
                    'attempts': account[1],
                    'last_attempt': datetime.strptime(account[2], '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y %H:%M:%S'),
                    'blocked_until': datetime.strptime(account[3], '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y %H:%M:%S') if account[3] else 'N/A',
                    'is_blocked': is_blocked
                })
            
            stats = {
                'total_failed': total_failed,
                'unique_ips': unique_ips,
                'last_24h': last_24h
            }
            
            return render_template('secretary_security_logs.html', 
                                failed_attempts=failed_attempts,
                                blocked_accounts=blocked_accounts,
                                stats=stats)
    except sqlite3.Error as e:
        flash(f'Erro ao acessar os logs: {e}', 'danger')
        return redirect(url_for('secretary_dashboard'))

@app.route('/secretary/doctors', methods=['GET'])
def secretary_doctors():
    if 'secretary_id' not in session:
        return redirect(url_for('secretary_login'))
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id, name, username, crm, specialty, active FROM doctor ORDER BY name")
            doctors = c.fetchall()
            return render_template('secretary_doctors.html', doctors=doctors)
    except sqlite3.Error as e:
        flash(f'Erro ao carregar médicos: {e}', 'danger')
        return redirect(url_for('secretary_dashboard'))

@app.route('/secretary/doctor/register', methods=['GET', 'POST'])
def secretary_doctor_register():
    if 'secretary_id' not in session:
        return redirect(url_for('secretary_login'))
    
    form = DoctorRegisterForm()
    if form.validate_on_submit():
        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                # Verificar se o CRM já existe
                c.execute("SELECT id FROM doctor WHERE crm = ?", (form.crm.data,))
                if c.fetchone():
                    flash('CRM já cadastrado', 'danger')
                    return render_template('secretary_doctor_register.html', form=form)
                
                # Verificar se o username já existe
                c.execute("SELECT id FROM doctor WHERE username = ?", (form.username.data,))
                if c.fetchone():
                    flash('Nome de usuário já existe', 'danger')
                    return render_template('secretary_doctor_register.html', form=form)
                
                hashed = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                c.execute("""
                    INSERT INTO doctor (username, password, name, crm, specialty) 
                    VALUES (?, ?, ?, ?, ?)
                """, (form.username.data, hashed, form.name.data, form.crm.data, form.specialty.data))
                conn.commit()
                flash('Médico cadastrado com sucesso!', 'success')
                return redirect(url_for('secretary_doctors'))
        except sqlite3.Error as e:
            flash(f'Erro ao cadastrar médico: {e}', 'danger')
    
    return render_template('secretary_doctor_register.html', form=form)

@app.route('/secretary/doctor/toggle/<int:doctor_id>', methods=['POST'])
def secretary_doctor_toggle(doctor_id):
    if 'secretary_id' not in session:
        return redirect(url_for('secretary_login'))
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("UPDATE doctor SET active = CASE WHEN active = 1 THEN 0 ELSE 1 END WHERE id = ?", (doctor_id,))
            conn.commit()
            flash('Status do médico atualizado com sucesso!', 'success')
    except sqlite3.Error as e:
        flash(f'Erro ao atualizar status do médico: {e}', 'danger')
    
    return redirect(url_for('secretary_doctors'))

@app.route('/logout')
def logout():
    session.pop('client_id', None)
    session.pop('doctor_id', None)
    session.pop('secretary_id', None)
    flash('Desconectado com sucesso', 'success')
    return redirect(url_for('index'))

@app.route('/doctor/patient_history')
def doctor_patient_history():
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            # Primeiro, vamos verificar o ID do médico logado
            print(f"ID do médico logado: {session['doctor_id']}")
            
            # Buscar apenas os agendamentos do médico logado
            query = """
                SELECT 
                    c.name as patient_name,
                    c.cpf,
                    appointments.date,
                    appointments.time,
                    appointments.status,
                    appointments.notes,
                    appointments.id as appointment_id,
                    appointments.doctor_id
                FROM appointments
                JOIN clients c ON appointments.client_id = c.id
                WHERE appointments.doctor_id = ?
                ORDER BY appointments.date DESC, appointments.time DESC
            """
            c.execute(query, (session['doctor_id'],))
            appointments = c.fetchall()
            
            # Debug: imprimir os resultados
            print(f"Total de consultas encontradas: {len(appointments)}")
            for appt in appointments:
                print(f"Consulta: {appt}")
            
            # Formatar as datas para o padrão brasileiro
            formatted_appointments = []
            for appt in appointments:
                date_obj = datetime.strptime(appt[2], '%Y-%m-%d')
                formatted_date = date_obj.strftime('%d/%m/%Y')
                formatted_appointments.append({
                    'patient_name': appt[0],
                    'cpf': appt[1],
                    'date': formatted_date,
                    'time': appt[3],
                    'status': appt[4],
                    'notes': appt[5] or '',
                    'patient_id': appt[6],
                    'doctor_id': appt[7]
                })
            
            return render_template('doctor_patient_history.html', appointments=formatted_appointments)
    except sqlite3.Error as e:
        print(f"Erro ao carregar histórico: {e}")
        flash(f'Erro ao carregar histórico: {e}', 'danger')
        return redirect(url_for('doctor_dashboard'))

@app.route('/doctor/update_notes/<int:appointment_id>', methods=['POST'])
def update_appointment_notes(appointment_id):
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    
    notes = request.form.get('notes', '')
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("UPDATE appointments SET notes = ? WHERE id = ?", (notes, appointment_id))
            conn.commit()
            flash('Anotações atualizadas com sucesso!', 'success')
    except sqlite3.Error as e:
        flash(f'Erro ao atualizar anotações: {e}', 'danger')
    
    return redirect(url_for('doctor_patient_history'))

@app.route('/doctor/update_status/<int:appointment_id>', methods=['POST'])
def update_appointment_status(appointment_id):
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    
    status = request.form.get('status', '')
    if status not in ['Agendado', 'Concluído', 'Cancelado']:
        flash('Status inválido!', 'danger')
        return redirect(url_for('doctor_patient_history'))
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("UPDATE appointments SET status = ? WHERE id = ?", (status, appointment_id))
            conn.commit()
            flash('Status atualizado com sucesso!', 'success')
    except sqlite3.Error as e:
        flash(f'Erro ao atualizar status: {e}', 'danger')
    
    return redirect(url_for('doctor_patient_history'))

# Função para verificar tentativas de login
def check_login_attempts(email):
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            # Buscar tentativas do usuário
            c.execute("""
                SELECT attempts, blocked_until, last_attempt
                FROM login_attempts 
                WHERE email = ?
            """, (email,))
            result = c.fetchone()
            
            current_time = datetime.now()
            
            if result:
                attempts, blocked_until, last_attempt = result
                
                # Se estiver bloqueado, verificar se ainda está no período de bloqueio
                if blocked_until:
                    blocked_time = datetime.strptime(blocked_until, '%Y-%m-%d %H:%M:%S')
                    if current_time < blocked_time:
                        remaining_seconds = (blocked_time - current_time).total_seconds()
                        remaining_minutes = int(remaining_seconds / 60)
                        remaining_seconds = int(remaining_seconds % 60)
                        
                        if remaining_minutes > 0:
                            time_msg = f"{remaining_minutes} minutos"
                            if remaining_seconds > 0:
                                time_msg += f" e {remaining_seconds} segundos"
                        else:
                            time_msg = f"{remaining_seconds} segundos"
                        
                        return False, f"Conta bloqueada. Tente novamente em {time_msg}."
                
                # Se já tem 3 ou mais tentativas, bloquear
                if attempts >= 3:
                    blocked_until = current_time + timedelta(minutes=5)
                    c.execute("""
                        UPDATE login_attempts 
                        SET blocked_until = ?,
                            last_attempt = CURRENT_TIMESTAMP
                        WHERE email = ?
                    """, (blocked_until.strftime('%Y-%m-%d %H:%M:%S'), email))
                    conn.commit()
                    return False, "Muitas tentativas. Conta bloqueada por 5 minutos."
                else:
                    # Incrementar tentativas e avisar quantas restam
                    remaining = 3 - attempts
                    c.execute("""
                        UPDATE login_attempts 
                        SET attempts = attempts + 1,
                            last_attempt = CURRENT_TIMESTAMP
                        WHERE email = ?
                    """, (email,))
                    conn.commit()
                    return True, f"Tentativa {attempts + 1} de 3. Restam {remaining - 1} tentativas."
            else:
                # Primeiro registro para este email
                c.execute("""
                    INSERT INTO login_attempts (email, attempts, last_attempt)
                    VALUES (?, 1, CURRENT_TIMESTAMP)
                """, (email,))
                conn.commit()
                return True, "Primeira tentativa. Restam 2 tentativas."
            
    except sqlite3.Error as e:
        print(f"Erro ao verificar tentativas de login: {e}")
        return True, None

# Função para registrar tentativa de login
def record_login_attempt(email, success):
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            c.execute("""
                INSERT INTO login_attempts (email, attempts) 
                VALUES (?, 1)
                ON CONFLICT(email) DO UPDATE SET 
                attempts = CASE 
                    WHEN ? THEN 0  -- Se login bem sucedido, reset tentativas
                    ELSE attempts + 1  -- Se falhou, incrementa tentativas
                END,
                last_attempt = CURRENT_TIMESTAMP
            """, (email, success))
            
            conn.commit()
            
    except sqlite3.Error as e:
        print(f"Erro ao registrar tentativa de login: {e}")

@app.route('/secretary/unlock_account', methods=['POST'])
def unlock_account():
    if 'secretary_id' not in session:
        return redirect(url_for('secretary_login'))
    
    email = request.form.get('email')
    if not email:
        flash('Email não fornecido', 'danger')
        return redirect(url_for('secretary_security_logs'))
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            
            # Primeiro verificar se a conta existe na tabela login_attempts
            c.execute("""
                SELECT attempts, blocked_until 
                FROM login_attempts 
                WHERE email = ?
            """, (email,))
            
            result = c.fetchone()
            
            if not result:
                flash('Conta não encontrada no sistema de bloqueio', 'warning')
                return redirect(url_for('secretary_security_logs'))
            
            attempts, blocked_until = result
            current_time = datetime.now()
            
            # Verificar se a conta está realmente bloqueada
            is_blocked = False
            if blocked_until:
                blocked_time = datetime.strptime(blocked_until, '%Y-%m-%d %H:%M:%S')
                is_blocked = current_time < blocked_time
            
            if not is_blocked and attempts < 3:
                flash('Esta conta não está bloqueada', 'warning')
                return redirect(url_for('secretary_security_logs'))
            
            # Se chegou aqui, a conta está bloqueada. Vamos desbloqueá-la
            c.execute("""
                UPDATE login_attempts 
                SET attempts = 0,
                    blocked_until = NULL,
                    last_attempt = CURRENT_TIMESTAMP
                WHERE email = ?
            """, (email,))
            
            # Registrar ação no log
            c.execute("""
                INSERT INTO failed_logins (username, timestamp, ip_address, user_type, notes) 
                VALUES (?, ?, ?, ?, ?)
            """, (
                email,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                request.remote_addr,
                'secretary',
                'Conta desbloqueada pela secretária'
            ))
            
            conn.commit()
            flash(f'Conta {email} desbloqueada com sucesso!', 'success')
                
    except sqlite3.Error as e:
        flash(f'Erro ao desbloquear conta: {e}', 'danger')
    
    return redirect(url_for('secretary_security_logs'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)