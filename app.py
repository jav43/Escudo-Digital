from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3
from datetime import datetime, timedelta
import re
import os

app = Flask(__name__)

# Geração segura de chave secreta (substitua por uma chave fixa segura em produção)
app.config['SECRET_KEY'] = os.urandom(24).hex()  # Gera uma chave aleatória para desenvolvimento
bcrypt = Bcrypt(app)

# Database initialization
def init_db():
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
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
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                status TEXT DEFAULT 'Agendado',
                notes TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(id)
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS doctor (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS failed_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                timestamp TEXT,
                ip_address TEXT
            )''')
            
            # Insere um médico padrão apenas se não existir
            c.execute("SELECT COUNT(*) FROM doctor WHERE username = 'doutor'")
            if c.fetchone()[0] == 0:
                hashed = bcrypt.generate_password_hash('peres321', rounds=10).decode('utf-8')
                c.execute("INSERT INTO doctor (username, password) VALUES (?, ?)", ('doutor', hashed))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o banco de dados: {e}")

# Validação personalizada para telefone
def validate_phone(form, field):
    phone = field.data
    if not re.match(r'^\+?1?\d{10,15}$', phone):
        raise ValidationError('Número de telefone inválido. Use o formato +5511999999999.')

# Validação personalizada para CPF
def validate_cpf(form, field):
    cpf = field.data
    if cpf and not re.match(r'^\d{11}$', cpf):
        raise ValidationError('CPF inválido. Use apenas 11 dígitos numéricos.')

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

class ScheduleForm(FlaskForm):
    date = DateField('Data', validators=[DataRequired()])
    time = SelectField('Horário', choices=[
        ('08:00', '08:00'), ('09:00', '09:00'), ('10:00', '10:00'), ('11:00', '11:00'),
        ('13:00', '13:00'), ('14:00', '14:00'), ('15:00', '15:00'), ('16:00', '16:00'),
        ('17:00', '17:00'), ('18:00', '18:00')
    ], validators=[DataRequired()])
    submit = SubmitField('Agendar')

class DoctorLoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class DateRangeForm(FlaskForm):
    start_date = DateField('Data Inicial', validators=[DataRequired()])
    end_date = DateField('Data Final', validators=[DataRequired()])
    submit = SubmitField('Filtrar')

# Input sanitization
def sanitize_input(value):
    if value:
        return re.sub(r'[^a-zA-Z0-9\s@.+\-]', '', value).strip()
    return value

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
                c.execute("SELECT * FROM clients WHERE email = ?", (email,))
                client = c.fetchone()
                if client:
                    print(f"Cliente encontrado: {client}")
                    if bcrypt.check_password_hash(client[3], password):
                        session['client_id'] = client[0]
                        flash('Login bem-sucedido!', 'success')
                        return redirect(url_for('client_dashboard'))
                    else:
                        print("Senha incorreta")
                else:
                    print("Cliente não encontrado")
                c.execute("INSERT INTO failed_logins (username, timestamp, ip_address) VALUES (?, ?, ?)",
                          (email, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), request.remote_addr))
                conn.commit()
                flash('E-mail ou senha inválidos', 'danger')
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
    if form.validate_on_submit():
        date = form.date.data.strftime('%Y-%m-%d')
        time = form.time.data
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM appointments WHERE date = ? AND time = ?", (date, time))
            if c.fetchone():
                flash('Horário já reservado', 'danger')
            else:
                c.execute("INSERT INTO appointments (client_id, date, time) VALUES (?, ?, ?)",
                          (session['client_id'], date, time))
                conn.commit()
                flash('Consulta agendada com sucesso', 'success')
                return redirect(url_for('client_dashboard'))
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
                c.execute("INSERT INTO failed_logins (username, timestamp, ip_address) VALUES (?, ?, ?)",
                          (username, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), request.remote_addr))
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

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        if start_date and end_date:
            c.execute('''SELECT a.date, a.time, c.name, c.email, c.cpf
                         FROM appointments a
                         JOIN clients c ON a.client_id = c.id
                         WHERE a.date BETWEEN ? AND ? AND a.status = 'Agendado'
                         ORDER BY a.date, a.time''', (start_date, end_date))
        else:
            c.execute('''SELECT a.date, a.time, c.name, c.email, c.cpf
                         FROM appointments a
                         JOIN clients c ON a.client_id = c.id
                         WHERE a.status = 'Agendado'
                         ORDER BY a.date, a.time''')
        appointments_raw = c.fetchall()

    # Formatar a data para DD/MM/YYYY
    appointments = []
    for appt in appointments_raw:
        date_str = appt[0]
        formatted_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%d/%m/%Y')
        appointments.append((formatted_date, appt[1], appt[2], appt[3], appt[4]))

    return render_template('doctor_daily.html', form=form, appointments=appointments, start_date=start_date, end_date=end_date)

@app.route('/doctor/failed_logins')
def doctor_failed_logins():
    if 'doctor_id' not in session:
        return redirect(url_for('doctor_login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT username, timestamp, ip_address FROM failed_logins ORDER BY timestamp DESC")
        failed_logins = c.fetchall()
    return render_template('doctor_failed_logins.html', failed_logins=failed_logins)

@app.route('/logout')
def logout():
    session.pop('client_id', None)
    session.pop('doctor_id', None)
    flash('Desconectado com sucesso', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
    import sqlite3

# Conectar ao banco de dados
conn = sqlite3.connect('database.db')
c = conn.cursor()

# Criar a tabela login_attempts
c.execute('''
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        user_type TEXT NOT NULL, -- 'client' ou 'doctor'
        success INTEGER NOT NULL -- 1 para sucesso, 0 para falha
    )
''')

# Confirmar e fechar
conn.commit()
conn.close()

print("Tabela login_attempts criada com sucesso!")