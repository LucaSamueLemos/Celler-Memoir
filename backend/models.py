from backend import db  # Importa a instância global de SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=True)  # Novo campo para nome do psicólogo
    email = db.Column(db.String(150), unique=True, nullable=False)
    cpf = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    tipo = db.Column(db.String(20), nullable=False) # 'paciente' ou 'psicologo'
    trocar_senha = db.Column(db.Boolean, default=False, nullable=False)

    paciente_perfil = db.relationship(
        'Paciente',
        back_populates='user_login',
        lazy=True,
        uselist=False,
        primaryjoin="User.id == Paciente.id"
    )

    pacientes_atendidos = db.relationship(
        'Paciente',
        foreign_keys='Paciente.psicologo_id',
        backref='psicologo_responsavel',
        lazy=True
    )

    def __repr__(self):
        return f'<User {self.email} ({self.tipo})>'

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Paciente(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    data_nascimento = db.Column(db.Date, nullable=True)
    psicologo_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    foto_perfil = db.Column(db.String(255), nullable=False, default='default.jpg')

    user_login = db.relationship(
        'User',
        back_populates='paciente_perfil',
        foreign_keys=[id],
        lazy=True,
        uselist=False
    )

    registros_emocoes = db.relationship('RegistroEmocao', backref='paciente_obj', lazy=True)
    respostas_questionario = db.relationship('RespostaQuestionario', backref='paciente_obj', lazy=True)
    respostas_pergunta = db.relationship('RespostaPergunta', backref='paciente_obj', lazy=True)

    def __repr__(self):
        return f'<Paciente {self.nome} (ID User: {self.id})>'

class RegistroEmocao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emocao = db.Column(db.String(100), nullable=False)
    data_registro = db.Column(db.DateTime, default=datetime.utcnow)
    paciente_id = db.Column(db.Integer, db.ForeignKey('paciente.id'), nullable=False)

    def __repr__(self):
        return f'<RegistroEmocao {self.emocao} - Paciente: {self.paciente_id}>'

class RespostaQuestionario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    humor_geral = db.Column(db.Integer, nullable=True)
    sentimento_principal = db.Column(db.String(100), nullable=True)
    dormiu_bem = db.Column(db.Boolean, nullable=True)
    motivacao_tarefas = db.Column(db.Boolean, nullable=True)
    causa_estresse = db.Column(db.Text, nullable=True)
    nivel_ansiedade = db.Column(db.Integer, nullable=True)
    qualidade_sono = db.Column(db.String(50), nullable=True)
    alimentou_bem = db.Column(db.String(10), nullable=True)
    feliz_motivado = db.Column(db.Text, nullable=True)
    data_resposta = db.Column(db.DateTime, default=datetime.utcnow)
    paciente_id = db.Column(db.Integer, db.ForeignKey('paciente.id'), nullable=False)

    def __repr__(self):
        return f'<RespostaQuestionario - Paciente: {self.paciente_id} - {self.data_resposta.strftime("%Y-%m-%d")}>'

class Consulta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    psicologo_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    paciente_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data_hora = db.Column(db.DateTime, nullable=False)
    duracao_minutos = db.Column(db.Integer, default=50)
    status = db.Column(db.String(50), default='Agendada')
    notas = db.Column(db.Text)

    paciente_da_consulta = db.relationship(
        'Paciente',
        primaryjoin="Consulta.paciente_id == Paciente.id",
        foreign_keys=[paciente_id],
        lazy=True
    )

    psicologo_da_consulta = db.relationship(
        'User',
        primaryjoin="Consulta.psicologo_id == User.id",
        foreign_keys=[psicologo_id],
        lazy=True
    )

    def __repr__(self):
        return f'<Consulta {self.id} - Psicólogo: {self.psicologo_id} / Paciente: {self.paciente_id} em {self.data_hora}>'

# New model for psychologist questions
# Association table for many-to-many relationship between PsicologoPergunta and Paciente
psicologo_pergunta_paciente = db.Table(
    'psicologo_pergunta_paciente',
    db.Column('pergunta_id', db.Integer, db.ForeignKey('psicologo_pergunta.id'), primary_key=True),
    db.Column('paciente_id', db.Integer, db.ForeignKey('paciente.id'), primary_key=True)
)

class PsicologoPergunta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    psicologo_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pergunta_texto = db.Column(db.Text, nullable=False)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)

    psicologo = db.relationship('User', backref='perguntas_criadas', lazy=True)
    pacientes = db.relationship('Paciente', secondary=psicologo_pergunta_paciente, backref='perguntas', lazy='dynamic')

    def __repr__(self):
        return f'<PsicologoPergunta {self.id} - Psicologo: {self.psicologo_id}>'

# New model for patient answers to psychologist questions
class RespostaPergunta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pergunta_id = db.Column(db.Integer, db.ForeignKey('psicologo_pergunta.id'), nullable=False)
    paciente_id = db.Column(db.Integer, db.ForeignKey('paciente.id'), nullable=False)
    resposta_texto = db.Column(db.Text, nullable=True)
    data_resposta = db.Column(db.DateTime, default=datetime.utcnow)

    pergunta = db.relationship('PsicologoPergunta', backref='respostas', lazy=True)

    def __repr__(self):
        return f'<RespostaPergunta {self.id} - Paciente: {self.paciente_id} - Pergunta: {self.pergunta_id}>'
