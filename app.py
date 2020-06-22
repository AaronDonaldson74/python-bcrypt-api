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

if __name__ == "__main__":
    app.run(debug=True)
    