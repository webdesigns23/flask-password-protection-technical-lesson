from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields
# add bcrypt to imports from config
from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    _password_hash = db.Column(db.String) # add _password_hash

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'
    
    # Build method to protect password_hash property
    @hybrid_property
    def password_hash(self):
        raise Exception('Password hashes may not be viewed.')
    
    # Build method to set password hash property using:
    # bcrypt.generate_password_hash() 
    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    # Build authenticate method that uses bcrypt.check_password_hash()
    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()