# Technical Lesson: Password Protection

## Introduction

In earlier modules, we built a basic login system using a session and username, but we’ve skipped
a critical piece: password protection. Without secure password handling, any user could impersonate
another simply by knowing their username. That’s a major security risk in any real-world application.

In this lesson, we’ll implement secure password hashing using Flask-Bcrypt, an industry-standard
library for storing and validating passwords safely. You’ll extend the User model with methods to:

* Set hashed passwords on signup
* Prevent direct access to password data
* Verify user credentials securely during login

We’ll also refactor our signup and login routes to integrate password logic, laying the foundation
for more robust authentication systems.

This is a critical shift: instead of storing plain-text credentials, your app will use irreversible
password hashes, protecting users even if the database were compromised. By the end of this lesson,
your application will support full authentication workflows using modern security practices.

## Tools & Resources

- [GitHub Repo](https://github.com/learn-co-curriculum/flask-password-protection-technical-lesson)
- [Flask-Bcrypt](https://flask-bcrypt.readthedocs.io/en/1.0.1/)

## Set Up

There is some starter code in place for a Flask API backend.
To get set up, run:

```bash
$ pipenv install && pipenv shell
$ cd server
$ flask db upgrade head
```

You can run the Flask server with:

```console
$ python app.py
```

## Instructions

### Task 1: Define the Problem

We need to create a secure login system on the backend for the frontend team to use. This will include:
- secure passwords
- sign up
- log in
- log out
- checking if a user is logged in on page load

### Task 2: Determine the Design

We need to implement a way for users to sign up, log in, and log out with secure
passwords.

We will create methods using bcrypt in our user model to:
- hash passwords and store them in the database
- protect the hashed_password property
- authenticate a user by their username and password

Then we'll use those methods in our login and signup endpoints to create and log in users securely.

#### Note on Configuration

Take note of the new `config.py` file in the `server/` directory. As our app is
getting more and more complex, setting up a config file can help clean up our
code a bit.

In each of our applications so far, `app.py` needed to import from `models.py`
in order to initialize the database's connection to the app. That's still the
case here, but we also find ourselves with the need to import an instantiated
`Bcrypt` from `app.py` into `models.py`! This creates a _circular import_, where
objects in two separate files are dependent upon one another to function.

To avoid this, you can often refactor your objects to avoid unnecessary
dependencies (we're all guilty of this!), you can refactor your code into one
large file, or you can move some of your imports and configurations into a third
file. That's what we did here- check out `config.py` and you'll notice a lot of
familiar code. We took the imports and configurations from `app.py` and
`models.py` and put them together to avoid circular imports. These are then
imported by `app.py` and `models.py` when they're ready to be used.

### Task 3: Develop, Test, and Refine the Code

#### Step 1: Import bcrypt

In config.py, add an import for bcrypt:

```python
from flask import Flask
# import Bcrypt
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
```

#### Step 2: Instantiate bcrypt

In config.py, instantiate bcrypt:

```python
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

db = SQLAlchemy()
migrate = Migrate(app, db)
db.init_app(app)

# Create bcrypt instance from app
bcrypt = Bcrypt(app)

api = Api(app)
```

In models.py, import this new instance:

```python
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields
# add bcrypt to imports from config
from config import db, bcrypt
```

#### Step 3: Create `_password_hash` Property

Create a property to store passwords in the database after being hashed.

```python
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    # add _password_hash
    _password_hash = db.Column(db.String)

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'
```

#### Step 4: Protect the `password_hash` Property

In the User model, add logic to protect the password_property by raising an Exception.

```python
# import hybrid_property
from sqlalchemy.ext.hybrid import hybrid_property

# rest of imports

class User:
    # ......rest of User logic....


    # Build method to protect password_hash property
    @hybrid_property
    def password_hash(self):
        raise Exception('Password hashes may not be viewed.')
```

#### Step 5: Use Bcrypt to Hash the Password

In the User model, use `bcrypt.generate_password_hash` to set the property.

```python
# Build method to set password hash property using bcrypt.generate_password_hash()
@password_hash.setter
def password_hash(self, password):
    password_hash = bcrypt.generate_password_hash(
        password.encode('utf-8'))
    self._password_hash = password_hash.decode('utf-8')
```

#### Step 6: Use Bcrypt to Authenticate a User

In the User model, use `bcrypt.check_password_hash` to verify a user's password.

```python
# Build authenticate method that uses bcrypt.check_password_hash()
def authenticate(self, password):
    return bcrypt.check_password_hash(
        self._password_hash, password.encode('utf-8'))
```

Once you have all methods created, commit your code.

#### Step 7: Test New Methods in `flask shell`

Let's test the new methods we created. First, let's create, migrate, and update our database:

```bash
flask db init
flask db migrate -m "initial migration"
flask db upgrade head
```

Now that our database is ready, let's test creating some users:

```bash
flask shell
>>> u = User(username="Laura")
>>> u.password_hash = "password"
>>> u.password_hash
Traceback (most recent call last):
    ...
    raise Exception('Password hashes may not be viewed.')
Exception: Password hashes may not be viewed.
>>> db.session.add(u)
>>> db.session.commit()
>>> User.query.first()
User Laura, ID: 1
>>> User.query.first().authenticate("password")
True
>>> User.query.first().authenticate("passwords")
False
>>> exit()
```

Feel free to try creating more users if you wish. You should verify:
* calling .password_hash (getter) on a user results in an error
* users can be successfully saved to the database
* the authenticate method returns True if the password is correct and False if not.

#### Step 8: Add Passwords to User Accounts in Signup

In signup, we're currently just creating users from usernames. Let's use our new User
methods to add a password to a user when they sign up.

```python
class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )

        # Use the .password_hash setter to hash and set password
        user.password_hash = json['password']

        db.session.add(user)
        db.session.commit()
        return UserSchema().dump(user), 201
```

#### Step 9: Use the Authenticate Method in the Login Route

In the login route, we need to alter some of our logic to use our new authenticate method.

In the Login `post` method, add a check for `user.authenticate(password)` after verifying
the user exists:

```python
class Login(Resource):
    def post(self):

        username = request.get_json()['username']
        password = request.get_json()['password']

        user = User.query.filter(User.username == username).first()

        # Add password verification using the new .authenticate() method
        if user and user.authenticate(password):

            session['user_id'] = user.id
            return UserSchema().dump(user), 200

        return {'error': '401 Unauthorized'}, 401
```

#### Step 10: Verify your Code

Final Solution:

```python
# config.py
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

db = SQLAlchemy()
migrate = Migrate(app, db)
db.init_app(app)

bcrypt = Bcrypt(app)

api = Api(app)
```

```python
# models.py
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    _password_hash = db.Column(db.String)

    @hybrid_property
    def password_hash(self):
        raise Exception('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'

class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()
```

```python
# app.py
#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User, UserSchema

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']
        db.session.add(user)
        db.session.commit()
        return UserSchema().dump(user), 201

class CheckSession(Resource):
    def get(self):

        if session.get('user_id'):
            
            user = User.query.filter(User.id == session['user_id']).first()
            
            return UserSchema().dump(user), 200

        return {}, 204

class Login(Resource):
    def post(self):

        username = request.get_json()['username']
        password = request.get_json()['password']

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return UserSchema().dump(user), 200

        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):

        session['user_id'] = None

        return {}, 204


api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)

```

#### Step 11: Commit and Push Git History

Once all tests are passing, `git commit` (if needed) and `git push` your final code
to GitHub:

```bash
git add .
git commit -m "final solution"
git push
```

If you created a separate feature branch, remember to open a PR on main and merge.

### Task 4: Document and Maintain

Best Practice documentation steps:
* Add comments to the code to explain purpose and logic, clarifying intent and 
functionality of your code to other developers.
* Update README text to reflect the functionality of the application following 
https://makeareadme.com. 
  * Add screenshot of completed work included in Markdown in README.
* Delete any stale branches on GitHub
* Remove unnecessary/commented out code
* If needed, update git ignore to remove sensitive data

## Considerations

### Never Store Plaintext Passwords

Storing raw passwords in the database is a critical security flaw.

Even during testing, passwords should always be hashed using a tool like bcrypt, which applies one-way encryption.

### Password Hashes Are Not Reversible

A hash is not encrypted in the traditional sense—it cannot be decrypted.

Instead, during login, the entered password is re-hashed and compared to the stored hash using bcrypt.check_password_hash().

### Do Not Expose Hashes in Responses

Avoid sending hashed passwords in API responses.

Protect access using hybrid properties or raise an exception in the getter (as done in the User model).

### Circular Imports Can Break Your App
If app, db, and bcrypt are defined across multiple files, Flask can crash due to circular import errors.

Use a shared configuration file (like config.py) to centralize app setup and avoid fragile import chains.