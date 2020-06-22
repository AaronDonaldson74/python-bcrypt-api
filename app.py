from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os


app = Flask(__name__)


basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.sqlite")
db = SQLAlchemy(app)
ma = Marshmallow(app)


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


if __name__ == "__main__":
    app.run(debug=True)
    