from app import db, User
from werkzeug.security import generate_password_hash

# Chargez l'utilisateur par son nom d'utilisateur ou son ID
user = User.query.filter_by(username='user1').first()

# Modifiez le mot de passe
if user:
    user.password_hash = generate_password_hash('new_password1')
    db.session.commit()
