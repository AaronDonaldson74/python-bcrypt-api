# Python Flask Bcrypt Api
> Python Flask backend app for playing with user creation and login.  It uses a flask sqlite database along with flask-marshmallow for object serialization/deserialization.  You can create a user, hash their password, store that data in a database and during the login it will check that data.
- Dependencies
  - Python
    - [python](https://www.python.org/)
  - Flask
    - [flask-pypi](https://pypi.org/project/Flask/)
    - [flask-docs](https://flask.palletsprojects.com/en/1.1.x/)
  - Flask-SQLAlchemy
    - [flask-sqlalchemy-pypi](https://pypi.org/project/Flask-SQLAlchemy/)
    - [flask-sqlalchemy-docs](https://flask-sqlalchemy.palletsprojects.com/en/2.x/)
  - Flask-Marshmallow
    - [flask-marshmallow-pypi](https://pypi.org/project/flask-marshmallow/)
    - [flask-marshmallow-docs](https://flask-marshmallow.readthedocs.io/)
  - Flask-Bcrypt
    - [flask-bcrypt-pypi](https://pypi.org/project/Flask-Bcrypt/)
    - [flask-bcrypt-docs](https://flask-bcrypt.readthedocs.io/)
- download zip or clone
- Install all dependencies
```
$ pipenv install Flask Flask-SQLAlchemy flask-marshmallow
```
- Create your sqlite database
```
$ pipenv shell
$ python
>>> from app import db
>>> db.create_all()
```
- Flask Routes (test in postman or build a front-end)
  - Create User
    - http://localhost:5000/api/register
    ```json
    {
        "username": "test",
        "password": "test"
    }
    ```
  - GET All Users (For test purposes)
    - http://localhost:5000/api/users
  - Login
    - http://localhost:5000/api/login
    ```json
    {
        "username": "test",
        "password": "test"
    }
    ```





