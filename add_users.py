from app import db, User
from werkzeug.security import generate_password_hash

# Création de nouveaux utilisateurs
user1 = User(username='admin', password_hash=generate_password_hash('password'))
user2 = User(username='user2', password_hash=generate_password_hash('password2'))

# Ajout des utilisateurs à la session de la base de données
db.session.add(user1)
db.session.add(user2)

# Commit des changements
db.session.commit()
