from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from datetime import datetime
from scapy.all import ARP, Ether, srp
from forms import ContactForm, RegistrationForm, LoginForm

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///firstapp.db"
app.config['SECRET_KEY'] = 'very_secret_key_here'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

@app.before_request
def make_session_permanent():
    session.permanent = True

# ---------------- Models ----------------
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    website = db.Column(db.String(200), nullable=True)
    message = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"{self.id} - {self.name}"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"

# ---------------- Routes ----------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print("Hashed password:", hashed_password)
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            return redirect(url_for('contact'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', form=form, error=error)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = ContactForm()
    if form.validate_on_submit():
        contact_entry = Contact(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            website=form.website.data,
            message=form.message.data
        )
        db.session.add(contact_entry)
        db.session.commit()
        return redirect(url_for('contact_success'))
    return render_template('contact.html', form=form)

@app.route('/view_contacts')
def view_contacts():
    contacts = Contact.query.all()
    return render_template('view_contacts.html', contacts=contacts)

@app.route('/contact_success')
def contact_success():
    return "<h1>Contact form submitted successfully!</h1>"

# ---------------- Network Scanner Route ----------------

@app.route('/scan_network')
def scan_network():
    from scapy.all import ARP, Ether, srp

    target_ip = "192.168.1.0/24"  # this matches your Wi-Fi network
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return render_template('network_scan.html', devices=devices)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# ---------------- App Entry ----------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.first():
            hashed_pw = bcrypt.generate_password_hash('password').decode('utf-8')
            default_user = User(username='admin', password=hashed_pw, email='admin@example.com')
            db.session.add(default_user)
            db.session.commit()

    app.run(debug=True)
