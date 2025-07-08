from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
import os

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui' # Mude para uma chave segura em produção

    # Usa a variável de ambiente para a URL do banco PostgreSQL do Render, ou a URL padrão do Render
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL',
        'postgresql://sitedb_n2nj_user:d6DySncwYdOOjefL3eD86QOiOuwV5Qg0@dpg-d1m8j62li9vc7397a260-a.oregon-postgres.render.com/sitedb_n2nj'
    )    
    app.config['UPLOAD_FOLDER'] = path.join(app.root_path, 'static', 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Limite de 16MB para uploads

    # Garantir que o diretório de upload exista
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Configurações para Flask-Mail (exemplo com Gmail SMTP)
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') or 'seu_email@gmail.com'
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') or 'sua_senha'
    app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

    # Inicializa as extensões com o app
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    # Importa os modelos aqui para evitar problemas de importação circular
    # e garantir que eles sejam carregados após 'db' ser inicializado.
    from backend.models import User, Paciente, RegistroEmocao, RespostaQuestionario, Consulta

    # Importa as rotas
    from backend.routes import routes
    app.register_blueprint(routes, url_prefix='/')

    # Não cria mais o banco SQLite local, pois usaremos PostgreSQL

    # Configura o Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = 'routes.login' # Rota para onde redirecionar se o usuário não estiver logado
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id)) # Busca um usuário pelo ID

    return app

# Se você estiver usando um arquivo app.py que é executado diretamente,
# pode querer adicionar o seguinte para que 'python -m backend.app' funcione:
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True) # Modo debug é bom para desenvolvimento
