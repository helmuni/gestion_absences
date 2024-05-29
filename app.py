
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_cle_secrete'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gestion_absences.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

def get_user_by_username(username):
    for user in users.values():
        if user.username == username:
            return user
    return None

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    nom_centre = db.Column(db.String(150), nullable=False)  # Nouveau champ
    genre = db.Column(db.String(10), nullable=False)  # Nouveau champ


    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Absence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    absents_masculin = db.Column(db.Integer, nullable=False)
    absents_feminin = db.Column(db.Integer, nullable=False)
    filiere = db.Column(db.String(50), nullable=False)  
    periode = db.Column(db.String(50), nullable=False)
    user = db.relationship('User', backref=db.backref('absences', lazy=True))
    
@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        nom_centre = request.form['nom_centre']
        genre = request.form['genre']
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash, nom_centre=nom_centre, genre=genre)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_user.html')

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        user = User.query.filter_by(username=username).first()
        if user:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Mot de passe modifié avec succès')
            return redirect(url_for('index'))
        else:
            flash('Utilisateur non trouvé')
    return render_template('update_password.html')



@app.route('/saisie_absence', methods=['GET', 'POST'])
@login_required
def saisie_absence():
    if request.method == 'POST':
        date = request.form['date']
        absents_masculin = request.form['absents_masculin']
        absents_feminin = request.form['absents_feminin']
        filiere = request.form['filiere']  # Nouveau champ filiere
        periode = request.form['periode']  # Nouveau champ periode


        
        new_absence = Absence(
            user_id=current_user.id,
            date=datetime.strptime(date, '%Y-%m-%d'),
            absents_masculin=int(absents_masculin),
            absents_feminin=int(absents_feminin),
            filiere= filiere,
            periode= periode
            
            
        )
        db.session.add(new_absence)
        db.session.commit()
        flash('Les absences ont été enregistrées avec succès')
        return redirect(url_for('saisie_absence'))
    
    return render_template('saisie_absence.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Page d'accueil
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)
        if user and user.verify_password(password):
            login_user(user)
            return redirect(url_for('absences'))
        else:
            flash('Nom d’utilisateur ou mot de passe incorrect')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/absences')
@login_required
def absences():
    return redirect(url_for('saisie_absence'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.username != 'admin':  # Assurez-vous que seul l'administrateur peut accéder à cette page
        flash('Accès interdit')
        return redirect(url_for('index'))
    
    absences = Absence.query.join(User).all()
    return render_template('admin_dashboard.html', absences=absences)


@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_user_by_username(username):
    return User.query.filter_by(username=username).first()

@app.route('/view_users')
@login_required
def view_users():
    users = User.query.all()
    return render_template('view_users.html', users=users)

def recreate_database():
    db.drop_all()  # Supprime toutes les tables existantes
    db.create_all()  # Recrée toutes les tables selon le modèle défini

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    with app.app_context():
        test_user = User(username='admin', password_hash=generate_password_hash('password'))
        db.session.add(test_user)
        db.session.commit()
    with app.app_context():
        users = User.query.all()
        for user in users:
            print(f'ID: {user.id}, Username: {user.username}')

