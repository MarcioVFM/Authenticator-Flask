from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud"

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)#query: buscar algo no banco de dados

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message":"Autenticação realizada com sucesso"})

    return jsonify({"message":"Credenciais invalidas"}), 404

@app.route("/logout", methods=["GET"])
@login_required#somente quem esta logado pode acessar essa rota
def logout():
    logout_user()
    return jsonify({"message":"Logout realizado com sucesso!"})
    
@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed, role="user")#não e necessario colocar o role, porem fica mais evidente para outros programadores que olharem o codigo 
        db.session.add(user)
        db.session.commit()
        return jsonify({"message" : "Usuario cadastrados com sucesso"})

    return jsonify({"message" : "Dados invalidos"}), 400

@app.route("/user/<int:id_user>", methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)
    
    if user:
        return {"username":user.username}

    return jsonify({"messager":"Usuário não encontrado"}), 404

@app.route("/user/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if id_user != current_user.id and current_user.role == "user":#user nao pode mudar outros user
        return jsonify ({"message":"Operação inválida"}),403

    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message":f"Usuario {id_user} atualizado com sucesso"})
    
    return jsonify ({"message":"Usuario nao encontrado"}), 404

@app.route("/user/<int:id_user>", methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if current_user.role != "admin":#somente admin pode deletar usuario
        return jsonify({"message":"Operação não permitida"}), 403

    if id_user == current_user.id:#não deixa excluir o usuario atual logado
        return jsonify({"message":"Deleção não permitida"}), 403

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message":f"Usuario {id_user} deletado com sucesso!"})
    
    return jsonify({"message":"Usuario nao encontrado"}), 404

if __name__ == "__main__":
    app.run(debug=True)
    