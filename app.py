from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
import os


app = Flask(__name__)


basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.sqlite")
db = SQLAlchemy(app)
ma = Marshmallow(app)
flask_bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200), nullable=False)



class UserSchema(ma.Schema):
    class Meta:
        fields = (
        "id",
        "username",
        "password"
        )

user_schema = UserSchema()
users_schema = UserSchema(many=True)


@app.route("/")
def hello():
    return "Hello World2!"

@app.route("/api/register", methods=["POST"])
def register():
    post_data = request.get_json()
    username = post_data.get('username')
    password = post_data.get('password')
    hashed_password = flask_bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify('User Created')


# This route just for testing purposes.
@app.route('/api/users', methods=["GET"])
def get_users():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result)

# In the future, you'll want to add jwt tokens, , sessions or cookies, etc. But this one will not include those things.
@app.route('/api/login', methods=["POST"])
def login():
    post_data = request.get_json()
    db_user = User.query.filter_by(username=post_data.get('username')).first()
    
    if db_user is None:
        return jsonify('Username Not Found')

    password = post_data.get('password')
    db_user_hashed_password = db_user.password
    valid_password = flask_bcrypt.check_password_hash(db_user_hashed_password, password)

    if valid_password:
        return jsonify('User Verified')
    
    return jsonify('Password is not correct')

if __name__ == "__main__":
    app.run(debug=True)
    