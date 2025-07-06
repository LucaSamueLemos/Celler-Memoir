# backend/routes.py

from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from backend.models import User, Paciente, RegistroEmocao, RespostaQuestionario, Consulta, PsicologoPergunta, RespostaPergunta
from backend import db  # Importa a instância db
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from datetime import datetime, date # Importar date também para o campo de data do formulário
from werkzeug.utils import secure_filename
import os
import pytz

# Função auxiliar para validar extensões de arquivo
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

import re

def normalize_cpf(cpf):
    return re.sub(r'\D', '', cpf)  # Remove tudo que não for dígito

routes = Blueprint('routes', __name__)

@routes.app_context_processor
def inject_perguntas_pendentes():
    from sqlalchemy import func
    from backend.models import PsicologoPergunta, Paciente, RespostaPergunta
    from flask_login import current_user

    if current_user.is_authenticated and current_user.tipo == 'paciente':
        paciente_logado = current_user.paciente_perfil
        if paciente_logado:
            total_perguntas = PsicologoPergunta.query.join(PsicologoPergunta.pacientes).filter(Paciente.id == paciente_logado.id).count()
            perguntas_respondidas = db.session.query(func.count(RespostaPergunta.id)).filter(
                RespostaPergunta.paciente_id == paciente_logado.id
            ).scalar() or 0
            perguntas_pendentes = total_perguntas - perguntas_respondidas
            return dict(perguntas_pendentes=perguntas_pendentes)
        else:
            return dict(perguntas_pendentes=0)
    return dict(perguntas_pendentes=0)

# Routes for psychologist question management

@routes.route('/psicologo/perguntas')
@login_required
def psicologo_perguntas():
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    perguntas = PsicologoPergunta.query.filter_by(psicologo_id=current_user.id).all()
    return redirect(url_for('routes.lista_pergunta'))

@routes.route('/psicologo/perguntas/novo', methods=['GET', 'POST'])
@login_required
def psicologo_pergunta_novo():
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    if request.method == 'POST':
        pergunta_texto = request.form.get('pergunta_texto')
        selected_paciente_ids = request.form.getlist('pacientes')  # List of selected patient IDs
        if not pergunta_texto:
            flash('O texto da pergunta é obrigatório.', category='error')
            return redirect(url_for('routes.psicologo_pergunta_novo'))
        nova_pergunta = PsicologoPergunta(
            psicologo_id=current_user.id,
            pergunta_texto=pergunta_texto
        )
        # Associate selected patients
        if selected_paciente_ids:
            pacientes = Paciente.query.filter(Paciente.id.in_(selected_paciente_ids)).all()
            nova_pergunta.pacientes.extend(pacientes)
        db.session.add(nova_pergunta)
        db.session.commit()
        flash('Pergunta criada com sucesso.', category='success')
        return redirect(url_for('routes.psicologo_perguntas'))
    else:
        pacientes = Paciente.query.filter_by(psicologo_id=current_user.id).all()
        return render_template('psicologo_pergunta_form.html', pacientes=pacientes)

@routes.route('/psicologo/api/paciente/<int:paciente_id>/perguntas')
@login_required
def api_perguntas_por_paciente(paciente_id):
    if current_user.tipo != 'psicologo':
        return {"error": "Acesso não autorizado."}, 403
    paciente = Paciente.query.filter_by(id=paciente_id, psicologo_id=current_user.id).first()
    if not paciente:
        return {"error": "Paciente não encontrado ou não associado."}, 404
    perguntas = PsicologoPergunta.query.join(PsicologoPergunta.pacientes).filter(Paciente.id == paciente_id).all()
    perguntas_data = [{"id": p.id, "pergunta_texto": p.pergunta_texto} for p in perguntas]
    return {"perguntas": perguntas_data}

@routes.route('/psicologo/perguntas/<int:pergunta_id>/editar', methods=['GET', 'POST'])
@login_required
def psicologo_pergunta_editar(pergunta_id):
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    pergunta = PsicologoPergunta.query.filter_by(id=pergunta_id, psicologo_id=current_user.id).first()
    if not pergunta:
        flash('Pergunta não encontrada.', category='error')
        return redirect(url_for('routes.psicologo_perguntas'))
    if request.method == 'POST':
        pergunta_texto = request.form.get('pergunta_texto')
        selected_paciente_ids = request.form.getlist('pacientes')  # List of selected patient IDs
        if not pergunta_texto:
            flash('O texto da pergunta é obrigatório.', category='error')
            return redirect(url_for('routes.psicologo_pergunta_editar', pergunta_id=pergunta_id))
        pergunta.pergunta_texto = pergunta_texto
        # Update patients association
        if selected_paciente_ids:
            pacientes = Paciente.query.filter(Paciente.id.in_(selected_paciente_ids)).all()
            pergunta.pacientes = pacientes
        else:
            pergunta.pacientes = []
        db.session.commit()
        flash('Pergunta atualizada com sucesso.', category='success')
        return redirect(url_for('routes.lista_pergunta'))
    else:
        pacientes = Paciente.query.filter_by(psicologo_id=current_user.id).all()
        return render_template('psicologo_pergunta_form.html', pergunta=pergunta, pacientes=pacientes)

@routes.route('/psicologo/perguntas/<int:pergunta_id>/deletar', methods=['POST'])
@login_required
def psicologo_pergunta_deletar(pergunta_id):
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    pergunta = PsicologoPergunta.query.filter_by(id=pergunta_id, psicologo_id=current_user.id).first()
    if not pergunta:
        flash('Pergunta não encontrada.', category='error')
        return redirect(url_for('routes.lista_pergunta'))
    # Delete related RespostaPergunta entries first to avoid integrity error
    RespostaPergunta.query.filter_by(pergunta_id=pergunta.id).delete()
    db.session.delete(pergunta)
    db.session.commit()
    flash('Pergunta deletada com sucesso.', category='success')
    return redirect(url_for('routes.lista_pergunta'))

# Routes for patient to view and answer questions

@routes.route('/paciente/perguntas')
@login_required
def paciente_perguntas():
    if current_user.tipo != 'paciente':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    paciente = current_user.paciente_perfil
    if not paciente:
        flash('Perfil de paciente não encontrado.', category='error')
        return redirect(url_for('routes.login'))
    # Filter perguntas to only those not yet answered by the patient
    answered_pergunta_ids = [r.pergunta_id for r in paciente.respostas_pergunta]
    perguntas = PsicologoPergunta.query.join(PsicologoPergunta.pacientes).filter(
        Paciente.id == paciente.id,
        ~PsicologoPergunta.id.in_(answered_pergunta_ids)
    ).all()
    respostas = {r.pergunta_id: r for r in paciente.respostas_pergunta}
    return render_template('paciente_perguntas.html', perguntas=perguntas, respostas=respostas)

@routes.route('/paciente/perguntas/<int:pergunta_id>/responder', methods=['GET', 'POST'])
@login_required
def paciente_pergunta_responder(pergunta_id):
    if current_user.tipo != 'paciente':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    paciente = current_user.paciente_perfil
    if not paciente:
        flash('Perfil de paciente não encontrado.', category='error')
        return redirect(url_for('routes.login'))
    pergunta = PsicologoPergunta.query.filter_by(id=pergunta_id).first()
    if not pergunta:
        flash('Pergunta não encontrada.', category='error')
        return redirect(url_for('routes.paciente_perguntas'))
    resposta_existente = RespostaPergunta.query.filter_by(pergunta_id=pergunta_id, paciente_id=paciente.id).first()
    if request.method == 'POST':
        resposta_texto = request.form.get('resposta_texto')
        if resposta_existente:
            resposta_existente.resposta_texto = resposta_texto
            resposta_existente.data_resposta = datetime.utcnow()
        else:
            nova_resposta = RespostaPergunta(
                pergunta_id=pergunta_id,
                paciente_id=paciente.id,
                resposta_texto=resposta_texto
            )
            db.session.add(nova_resposta)
        db.session.commit()
        flash('Resposta salva com sucesso.', category='success')
        return redirect(url_for('routes.paciente_perguntas'))
    return render_template('paciente_pergunta_responder.html', pergunta=pergunta, resposta=resposta_existente)

@routes.route('/paciente/perguntas/responder', methods=['POST'])
@login_required
def paciente_perguntas_responder():
    if current_user.tipo != 'paciente':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    paciente = current_user.paciente_perfil
    if not paciente:
        flash('Perfil de paciente não encontrado.', category='error')
        return redirect(url_for('routes.login'))
    perguntas = PsicologoPergunta.query.join(PsicologoPergunta.pacientes).filter(Paciente.id == paciente.id).all()
    try:
        for pergunta in perguntas:
            resposta_texto = request.form.get(f'resposta_{pergunta.id}')
            if resposta_texto is not None:
                resposta_existente = RespostaPergunta.query.filter_by(pergunta_id=pergunta.id, paciente_id=paciente.id).first()
                if resposta_existente:
                    resposta_existente.resposta_texto = resposta_texto
                    resposta_existente.data_resposta = datetime.utcnow()
                else:
                    nova_resposta = RespostaPergunta(
                        pergunta_id=pergunta.id,
                        paciente_id=paciente.id,
                        resposta_texto=resposta_texto
                    )
                    db.session.add(nova_resposta)
        db.session.commit()
        flash('Respostas salvas com sucesso.', category='success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao salvar respostas: {e}', category='error')
    return redirect(url_for('routes.paciente_perguntas'))

@routes.route('/psicologo/paciente/<int:paciente_id>/delete', methods=['POST'])
@login_required
def delete_paciente(paciente_id):
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))

    paciente = Paciente.query.filter_by(id=paciente_id, psicologo_id=current_user.id).first()
    if not paciente:
        flash('Paciente não encontrado ou não associado a você.', category='error')
        return redirect(url_for('routes.psicologo'))

    try:
        # Deletar o usuário associado
        user = User.query.get(paciente_id)
        if user:
            db.session.delete(user)
        db.session.delete(paciente)
        db.session.commit()
        flash('Paciente excluído com sucesso.', category='success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir paciente: {e}', category='error')

    return redirect(url_for('routes.psicologo'))

@routes.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.tipo == 'paciente':
            return redirect(url_for('routes.paciente'))
        elif current_user.tipo == 'psicologo':
            return redirect(url_for('routes.psicologo'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        # Normalize password if user needs to change password (first login)
        if user and user.trocar_senha:
            password_normalized = normalize_cpf(password)
        else:
            password_normalized = password

        # A senha no banco é um hash, então usamos check_password_hash para comparar
        if user and user.check_password(password_normalized): # Usando o método check_password do modelo User
            flash('Login realizado com sucesso!', category='success')
            login_user(user, remember=True)
            if user.tipo == 'paciente':
                if user.trocar_senha:
                    return redirect(url_for('routes.trocar_senha_obrigatoria'))
                else:
                    return redirect(url_for('routes.paciente'))
            elif user.tipo == 'psicologo':
                return redirect(url_for('routes.psicologo'))
        else:
            # Verificação adicional para rejeitar senha antiga (CPF) após troca de senha
            if user and password == user.cpf and not user.trocar_senha:
                flash('Senha antiga (CPF) não é mais válida. Por favor, use a nova senha.', category='error')
            else:
                flash('Email ou senha incorretos.', category='error')

    return render_template('index.html')

@routes.route('/register_psicologo', methods=['GET', 'POST'])
def register_psicologo():
    if current_user.is_authenticated:
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not nome or not email or not password or not confirm_password:
            flash('Por favor, preencha todos os campos.', category='error')
            return redirect(url_for('routes.register_psicologo'))

        if password != confirm_password:
            flash('As senhas não coincidem.', category='error')
            return redirect(url_for('routes.register_psicologo'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Já existe um usuário com este email.', category='error')
            return redirect(url_for('routes.register_psicologo'))

        import random
        import string
        try:
            # Gerar CPF fictício único para psicólogo
            while True:
                fake_cpf = ''.join(random.choices(string.digits, k=11))
                existing_cpf = User.query.filter_by(cpf=fake_cpf).first()
                if not existing_cpf:
                    break
            new_user = User(nome=nome, email=email, tipo='psicologo', cpf=fake_cpf)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Cadastro realizado com sucesso! Faça login.', category='success')
            return redirect(url_for('routes.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar psicólogo: {e}', category='error')
            return redirect(url_for('routes.register_psicologo'))

    return render_template('psicologo_registro.html')

@routes.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso.', category='info')
    return redirect(url_for('routes.login'))

@routes.route('/paciente')
@login_required
def paciente():
    if current_user.tipo != 'paciente':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    
    # Usa a nova relação paciente_perfil (assumindo que você a definiu no modelo User)
    paciente_logado = current_user.paciente_perfil 

    if not paciente_logado:
        flash('Seu perfil de paciente não foi encontrado no sistema. Entre em contato com o administrador.', category='error')
        logout_user()
        return redirect(url_for('routes.login'))

    # Count unanswered questions assigned to the patient
    from sqlalchemy import func
    total_perguntas = PsicologoPergunta.query.join(PsicologoPergunta.pacientes).filter(Paciente.id == paciente_logado.id).count()
    perguntas_respondidas = db.session.query(func.count(RespostaPergunta.id)).filter(
        RespostaPergunta.paciente_id == paciente_logado.id
    ).scalar() or 0
    perguntas_pendentes = total_perguntas - perguntas_respondidas

    return render_template('paciente.html', paciente=paciente_logado, perguntas_pendentes=perguntas_pendentes)

@routes.route('/registrar_emocao', methods=['POST'])
@login_required
def registrar_emocao():
    if current_user.tipo == 'paciente':
        emocao = request.form.get('emocao')
        # Adicione campos de intensidade e notas aqui, se estiverem no seu formulário HTML
        intensidade = request.form.get('intensidade', type=int) # Supondo um campo 'intensidade' numérico
        notas = request.form.get('notas') # Supondo um campo 'notas' de texto

        if not emocao:
            flash('Por favor, insira uma emoção.', category='error')
            return redirect(url_for('routes.paciente'))

        nova_emocao = RegistroEmocao(
            emocao=emocao, 
            paciente_id=current_user.id
        )
        db.session.add(nova_emocao)
        db.session.commit()
        flash('Emoção registrada com sucesso!', category='success')
    else:
        flash('Acesso não autorizado.', category='error')
    return redirect(url_for('routes.paciente'))

@routes.route('/responder_questionario', methods=['POST'])
@login_required
def responder_questionario():
    if current_user.tipo != 'paciente':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))

    # Coletando os dados do formulário HTML do questionário
    humor_geral_str = request.form.get('humor_geral')
    sentimento_principal = request.form.get('sentimento_principal')
    dormiu_bem_str = request.form.get('dormiu_bem')
    motivacao_tarefas_str = request.form.get('motivacao_tarefas')
    causa_estresse = request.form.get('causa_estresse')
    nivel_ansiedade_str = request.form.get('nivel_ansiedade')
    qualidade_sono = request.form.get('qualidade_sono')
    alimentou_bem = request.form.get('alimentou_bem')
    feliz_motivado = request.form.get('feliz_motivado')

    # Convertendo para tipos de dados corretos (inteiro para humor e ansiedade, booleano para sim/não)
    humor_geral = None
    dormiu_bem = None
    motivacao_tarefas = None
    nivel_ansiedade = None

    try:
        if humor_geral_str:
            humor_geral = int(humor_geral_str)
        if nivel_ansiedade_str:
            nivel_ansiedade = int(nivel_ansiedade_str)
        
        # Assegura que dormiu_bem e motivacao_tarefas sejam True/False
        if dormiu_bem_str is not None:
            dormiu_bem = (dormiu_bem_str.lower() == 'true' or dormiu_bem_str.lower() == 'sim')
        
        if motivacao_tarefas_str is not None:
            motivacao_tarefas = (motivacao_tarefas_str.lower() == 'true' or motivacao_tarefas_str.lower() == 'sim')

        nova_resposta = RespostaQuestionario(
            humor_geral=humor_geral,
            sentimento_principal=sentimento_principal,
            dormiu_bem=dormiu_bem,
            motivacao_tarefas=motivacao_tarefas,
            causa_estresse=causa_estresse,
            nivel_ansiedade=nivel_ansiedade,
            qualidade_sono=qualidade_sono,
            alimentou_bem=alimentou_bem,
            feliz_motivado=feliz_motivado,
            paciente_id=current_user.id
        )

        db.session.add(nova_resposta)
        db.session.commit()

        flash('Questionário respondido com sucesso!', category='success')
        return redirect(url_for('routes.paciente'))

    except ValueError:
        flash('Valores inválidos para humor ou perguntas Sim/Não. Por favor, verifique suas respostas.', category='error')
        return redirect(url_for('routes.paciente'))
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro inesperado ao salvar o questionário: {e}', category='error')
        return redirect(url_for('routes.paciente'))

@routes.route('/psicologo')
@login_required
def psicologo():
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    
    # Usa a nova relação pacientes_atendidos
    pacientes = current_user.pacientes_atendidos

    # Obter próximas consultas do psicólogo (ex: próximas 5 consultas futuras)
    from datetime import datetime
    now = datetime.utcnow()
    consultas_proximas = Consulta.query.filter(
        Consulta.psicologo_id == current_user.id,
        Consulta.data_hora >= now
    ).order_by(Consulta.data_hora.asc()).limit(5).all()

    return render_template('psicologo.html', pacientes=pacientes, consultas_proximas=consultas_proximas)

@routes.route('/psicologo/lista_paciente')
@login_required
def lista_paciente():
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    # Aqui você pode buscar os pacientes associados ao psicólogo
    pacientes = current_user.pacientes_atendidos
    return render_template('lista_paciente.html', pacientes=pacientes)

@routes.route('/psicologo/lista_pergunta')
@login_required
def lista_pergunta():
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    # Buscar perguntas associadas ao psicólogo
    perguntas = PsicologoPergunta.query.filter_by(psicologo_id=current_user.id).all()
    # Buscar pacientes associados ao psicólogo para seleção no formulário
    pacientes = Paciente.query.filter_by(psicologo_id=current_user.id).all()
    return render_template('lista_pergunta.html', perguntas=perguntas, pacientes=pacientes)

@routes.route('/psicologo/adicionar_paciente', methods=['GET', 'POST'])
@login_required
def adicionar_paciente():
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        cpf = request.form.get('cpf')
        data_nascimento_str = request.form.get('data_nascimento')

        if not nome or not email or not cpf or not data_nascimento_str:
            flash('Nome, email, CPF e data de nascimento são obrigatórios para o novo paciente.', category='error')
            return redirect(url_for('routes.adicionar_paciente'))

        existing_user_email = User.query.filter_by(email=email).first()
        existing_user_cpf = User.query.filter_by(cpf=cpf).first()
        if existing_user_email or existing_user_cpf:
            flash('Já existe um usuário (seja paciente ou psicólogo) com este email ou CPF.', category='error')
            return redirect(url_for('routes.adicionar_paciente'))

        try:
            new_paciente_user = User(
                email=email,
                cpf=cpf,
                tipo='paciente',
                trocar_senha=True
            )
            new_paciente_user.set_password(normalize_cpf(cpf)) # Usa o CPF normalizado como senha inicial
            db.session.add(new_paciente_user)
            db.session.commit() # Commit para que new_paciente_user.id esteja disponível

            # Converter data de nascimento para objeto date
            from datetime import datetime
            try:
                data_nascimento = datetime.strptime(data_nascimento_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Formato de data de nascimento inválido. Use AAAA-MM-DD.', category='error')
                return redirect(url_for('routes.adicionar_paciente'))

            new_paciente_profile = Paciente(
                id=new_paciente_user.id, # Associa o ID do User ao Paciente
                nome=nome,
                psicologo_id=current_user.id,
                data_nascimento=data_nascimento
            )
            db.session.add(new_paciente_profile)
            db.session.commit()

            flash(f'Paciente "{nome}" adicionado com sucesso e usuário criado!', category='success')
            return redirect(url_for('routes.lista_paciente'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao adicionar paciente: {e}', category='error')
            return redirect(url_for('routes.adicionar_paciente'))
    return render_template('adicionar_paciente.html')

@routes.route('/paciente/upload_foto_propria', methods=['POST'])
@login_required
def upload_foto_propria_paciente():
    if current_user.tipo != 'paciente':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))

    paciente = current_user.paciente_perfil
    if not paciente:
        flash('Seu perfil de paciente não foi encontrado.', category='error')
        return redirect(url_for('routes.paciente'))

    if 'foto' not in request.files:
        flash('Nenhum arquivo de foto enviado.', category='error')
        return redirect(url_for('routes.paciente'))

    file = request.files['foto']

    if file.filename == '':
        flash('Nenhum arquivo selecionado.', category='error')
        return redirect(url_for('routes.paciente'))

    if file and allowed_file(file.filename):
        # Remove a foto antiga se não for a padrão
        if paciente.foto_perfil and paciente.foto_perfil != 'default.jpg':
            old_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], paciente.foto_perfil)
            if os.path.exists(old_filepath):
                os.remove(old_filepath)

        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{current_user.id}_paciente_{timestamp}_{filename}" # Nome mais descritivo

        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        paciente.foto_perfil = filename
        db.session.commit()
        flash('Foto de perfil atualizada com sucesso!', category='success')
    else:
        flash('Tipo de arquivo não permitido.', category='error')

    return redirect(url_for('routes.paciente'))

@routes.route('/paciente/<int:paciente_id>/upload_foto_psicologo', methods=['POST'])
@login_required
def upload_foto_paciente_psicologo(paciente_id):
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))

    paciente = Paciente.query.filter_by(id=paciente_id, psicologo_id=current_user.id).first()
    if not paciente:
        flash('Paciente não encontrado ou não associado a você.', category='error')
        return redirect(url_for('routes.psicologo'))

    if 'foto' not in request.files:
        flash('Nenhum arquivo de foto enviado.', category='error')
        return redirect(url_for('routes.ver_registros_paciente', paciente_user_id=paciente.id))

    file = request.files['foto']

    if file.filename == '':
        flash('Nenhum arquivo selecionado.', category='error')
        return redirect(url_for('routes.ver_registros_paciente', paciente_user_id=paciente.id))

    if file and allowed_file(file.filename):
        # Remove a foto antiga se não for a padrão
        if paciente.foto_perfil and paciente.foto_perfil != 'default.jpg':
            old_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], paciente.foto_perfil)
            if os.path.exists(old_filepath):
                os.remove(old_filepath)

        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{paciente.id}_psicologo_{current_user.id}_{timestamp}_{filename}" 

        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        paciente.foto_perfil = filename
        db.session.commit()
        flash('Foto de perfil do paciente atualizada com sucesso!', category='success')
    else:
        flash('Tipo de arquivo não permitido.', category='error')

    return redirect(url_for('routes.ver_registros_paciente', paciente_user_id=paciente.id))


from flask_mail import Message
from backend import mail

from flask_login import login_required, current_user
from flask import current_app, render_template, request, flash, redirect, url_for


import secrets
import string

import re

def is_strong_password(password):
    # Password must be at least 8 characters long
    if len(password) < 8:
        return False
    # Must contain at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False
    # Must contain at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    # Must contain at least one digit
    if not re.search(r'\d', password):
        return False
    # Must contain at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

@routes.route('/trocar_senha_obrigatoria', methods=['GET', 'POST'])
@login_required
def trocar_senha_obrigatoria():
    if current_user.tipo != 'paciente':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')

        if not nova_senha or not confirmar_senha:
            flash('Por favor, preencha todos os campos.', category='error')
            return redirect(url_for('routes.trocar_senha_obrigatoria'))

        if nova_senha != confirmar_senha:
            flash('As senhas não coincidem.', category='error')
            return redirect(url_for('routes.trocar_senha_obrigatoria'))

        # Verificar se a nova senha é diferente do CPF
        if nova_senha == current_user.cpf:
            flash('A nova senha deve ser diferente do CPF.', category='error')
            return redirect(url_for('routes.trocar_senha_obrigatoria'))

        # Check password strength
        if not is_strong_password(nova_senha):
            flash('A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais.', category='error')
            return redirect(url_for('routes.trocar_senha_obrigatoria'))

        # Atualizar a senha e marcar trocar_senha como False
        current_user.set_password(nova_senha)
        current_user.trocar_senha = False
        db.session.commit()

        flash('Senha alterada com sucesso!', category='success')
        return redirect(url_for('routes.paciente'))

    return render_template('trocar_senha_obrigatoria.html')

@routes.route('/psicologo/adicionar_paciente', methods=['POST'])
@login_required
def adicionar_paciente_web(): # Renomeado para evitar conflito com script
    if current_user.tipo != 'psicologo':
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('routes.login'))

    nome = request.form.get('nome')
    email = request.form.get('email')
    cpf = request.form.get('cpf')
    data_nascimento_str = request.form.get('data_nascimento')

    if not nome or not email or not cpf or not data_nascimento_str:
        flash('Nome, email, CPF e data de nascimento são obrigatórios para o novo paciente.', category='error')
        return redirect(url_for('routes.psicologo'))

    existing_user_email = User.query.filter_by(email=email).first()
    existing_user_cpf = User.query.filter_by(cpf=cpf).first()
    if existing_user_email or existing_user_cpf:
        flash('Já existe um usuário (seja paciente ou psicólogo) com este email ou CPF.', category='error')
        return redirect(url_for('routes.psicologo'))

    try:
        new_paciente_user = User(
            email=email,
            cpf=cpf,
            tipo='paciente',
            trocar_senha=True
        )
        new_paciente_user.set_password(normalize_cpf(cpf)) # Usa o CPF normalizado como senha inicial
        db.session.add(new_paciente_user)
        db.session.commit() # Commit para que new_paciente_user.id esteja disponível

        # Converter data de nascimento para objeto date
        from datetime import datetime
        try:
            data_nascimento = datetime.strptime(data_nascimento_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Formato de data de nascimento inválido. Use AAAA-MM-DD.', category='error')
            return redirect(url_for('routes.psicologo'))

        new_paciente_profile = Paciente(
            id=new_paciente_user.id, # Associa o ID do User ao Paciente
            nome=nome,
            psicologo_id=current_user.id,
            data_nascimento=data_nascimento
        )
        db.session.add(new_paciente_profile)
        db.session.commit()

        flash(f'Paciente "{nome}" adicionado com sucesso e usuário criado!', category='success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao adicionar paciente: {e}', category='error')

    return redirect(url_for('routes.psicologo'))

# --- Rotas para Agenda e Consultas ---

@routes.route('/paciente/registros')
@login_required
def paciente_registros():
    if current_user.tipo != 'paciente':
        flash('Acesso negado. Você não é um paciente.', 'danger')
        return redirect(url_for('routes.login'))

    paciente = current_user.paciente_perfil
    if not paciente:
        flash('Perfil de paciente não encontrado.', 'danger')
        return redirect(url_for('routes.login'))

    registros_emocoes = paciente.registros_emocoes
    respostas_questionarios = paciente.respostas_questionario
    consultas = Consulta.query.filter_by(paciente_id=paciente.id).order_by(Consulta.data_hora.asc()).all()
    respostas_perguntas = RespostaPergunta.query.filter_by(paciente_id=paciente.id).order_by(RespostaPergunta.data_resposta.desc()).all()

    # Convertendo datas para timezone local
    local_tz = pytz.timezone('America/Sao_Paulo')

    for registro in registros_emocoes:
        if registro.data_registro:
            registro.data_registro = registro.data_registro.replace(tzinfo=pytz.utc).astimezone(local_tz)

    for resposta in respostas_questionarios:
        if resposta.data_resposta:
            resposta.data_resposta = resposta.data_resposta.replace(tzinfo=pytz.utc).astimezone(local_tz)

    for resposta_pergunta in respostas_perguntas:
        if resposta_pergunta.data_resposta:
            resposta_pergunta.data_resposta = resposta_pergunta.data_resposta.replace(tzinfo=pytz.utc).astimezone(local_tz)

    return render_template('paciente_registros.html',
                           registros_emocoes=registros_emocoes,
                           respostas_questionarios=respostas_questionarios,
                           consultas=consultas,
                           respostas_perguntas=respostas_perguntas)

@routes.route('/psicologo/paciente/<int:paciente_id>/relatorio')
@login_required
def psicologo_relatorio(paciente_id):
    if current_user.tipo != 'psicologo':
        flash('Acesso negado. Você não é um psicólogo.', 'danger')
        return redirect(url_for('routes.login'))

    paciente = Paciente.query.filter_by(id=paciente_id, psicologo_id=current_user.id).first()
    if not paciente:
        flash('Paciente não encontrado ou não associado a você.', 'danger')
        return redirect(url_for('routes.psicologo'))

    # Dados para gráficos
    registros_emocoes = paciente.registros_emocoes
    respostas_questionarios = paciente.respostas_questionario
    consultas = Consulta.query.filter_by(paciente_id=paciente.id).order_by(Consulta.data_hora.asc()).all()

    # Convertendo datas para timezone local
    local_tz = pytz.timezone('America/Sao_Paulo')

    for registro in registros_emocoes:
        if registro.data_registro:
            registro.data_registro = registro.data_registro.replace(tzinfo=pytz.utc).astimezone(local_tz)

    for resposta in respostas_questionarios:
        if resposta.data_resposta:
            resposta.data_resposta = resposta.data_resposta.replace(tzinfo=pytz.utc).astimezone(local_tz)

    for consulta in consultas:
        if consulta.data_hora:
            consulta.data_hora = consulta.data_hora.replace(tzinfo=pytz.utc).astimezone(local_tz)

    # Agregar dados de emoções para gráfico
    emocao_counts = {}
    for registro in registros_emocoes:
        emocoes = [e.strip() for e in registro.emocao.split(',')]
        for emocao in emocoes:
            if emocao:
                emocao_counts[emocao] = emocao_counts.get(emocao, 0) + 1

    emocao_labels = list(emocao_counts.keys())
    emocao_data = list(emocao_counts.values())

    # Agregar dados de humor geral para gráfico de linha
    questionario_sorted = sorted(respostas_questionarios, key=lambda r: r.data_resposta)
    questionario_labels = [r.data_resposta.strftime('%d/%m/%Y') for r in questionario_sorted]
    questionario_data = [r.humor_geral if r.humor_geral is not None else 0 for r in questionario_sorted]

    return render_template('psicologo_relatorio.html',
                           paciente=paciente,
                           consultas=consultas,
                           emocao_labels=emocao_labels,
                           emocao_data=emocao_data,
                           questionario_labels=questionario_labels,
                           questionario_data=questionario_data)

@routes.route('/psicologo/agenda', methods=['GET', 'POST'])
@login_required
def psicologo_agenda():
    if current_user.tipo != 'psicologo':
        flash('Acesso negado. Você não é um psicólogo.', 'danger')
        return redirect(url_for('routes.login'))

    # Obter todas as consultas agendadas pelo psicólogo logado, ordenadas por data/hora
    consultas = Consulta.query.filter_by(psicologo_id=current_user.id)\
                               .order_by(Consulta.data_hora.asc()).all()

    # Obter lista de pacientes do psicólogo para o formulário de agendamento
    pacientes_do_psicologo = Paciente.query.filter_by(psicologo_id=current_user.id).all()

    if request.method == 'POST':
        paciente_id = request.form.get('paciente_id')
        data = request.form.get('data_consulta')
        hora = request.form.get('hora_consulta')
        duracao = request.form.get('duracao_minutos', type=int)
        status = request.form.get('status')
        notas = request.form.get('notas')

        if not all([paciente_id, data, hora, duracao, status]):
            flash('Por favor, preencha todos os campos obrigatórios para agendar a consulta.', 'warning')
            return redirect(url_for('routes.psicologo_agenda'))

        try:
            # Combina data e hora para um objeto datetime
            data_hora_consulta_str = f"{data} {hora}"
            data_hora_consulta = datetime.strptime(data_hora_consulta_str, '%Y-%m-%d %H:%M')

            # Verifica se o paciente_id corresponde a um paciente do psicólogo logado
            paciente_existente = Paciente.query.filter_by(id=paciente_id, psicologo_id=current_user.id).first()
            if not paciente_existente:
                flash('Paciente inválido. Por favor, selecione um paciente da sua lista.', 'danger')
                return redirect(url_for('routes.psicologo_agenda'))

            # Cria a nova consulta
            nova_consulta = Consulta(
                psicologo_id=current_user.id,
                paciente_id=paciente_id, # ID do perfil de Paciente, que é também o user.id
                data_hora=data_hora_consulta,
                duracao_minutos=duracao,
                status=status,
                notas=notas
            )
            db.session.add(nova_consulta)
            db.session.commit()
            flash('Consulta agendada com sucesso!', 'success')
            return redirect(url_for('routes.psicologo_agenda'))

        except ValueError:
            flash('Formato de data/hora inválido. Use AAAA-MM-DD e HH:MM.', 'danger')
        except Exception as e:
            flash(f'Erro ao agendar consulta: {e}', 'danger')
            db.session.rollback() # Em caso de erro, desfaz a transação

    from datetime import datetime as dt_now
    now = dt_now.utcnow()
    return render_template('psicologo_agenda.html', consultas=consultas, pacientes=pacientes_do_psicologo, now=now)

# Route to delete a consultation
@routes.route('/psicologo/agenda/consulta/<int:consulta_id>/delete', methods=['POST'])
@login_required
def delete_consulta(consulta_id):
    if current_user.tipo != 'psicologo':
        flash('Acesso negado. Você não é um psicólogo.', 'danger')
        return redirect(url_for('routes.login'))

    consulta = Consulta.query.filter_by(id=consulta_id, psicologo_id=current_user.id).first()
    if not consulta:
        flash('Consulta não encontrada ou acesso negado.', 'danger')
        return redirect(url_for('routes.psicologo_agenda'))

    try:
        db.session.delete(consulta)
        db.session.commit()
        flash('Consulta excluída com sucesso.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir consulta: {e}', 'danger')

    return redirect(url_for('routes.psicologo_agenda'))

# Routes to edit a consultation
@routes.route('/psicologo/agenda/consulta/<int:consulta_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_consulta(consulta_id):
    if current_user.tipo != 'psicologo':
        flash('Acesso negado. Você não é um psicólogo.', 'danger')
        return redirect(url_for('routes.login'))

    consulta = Consulta.query.filter_by(id=consulta_id, psicologo_id=current_user.id).first()
    if not consulta:
        flash('Consulta não encontrada ou acesso negado.', 'danger')
        return redirect(url_for('routes.psicologo_agenda'))

    if request.method == 'POST':
        paciente_id = request.form.get('paciente_id')
        data = request.form.get('data_consulta')
        hora = request.form.get('hora_consulta')
        duracao = request.form.get('duracao_minutos', type=int)
        notas = request.form.get('notas')
        status = request.form.get('status')

        if not all([paciente_id, data, hora, duracao, status]):
            flash('Por favor, preencha todos os campos obrigatórios para editar a consulta.', 'warning')
            return redirect(url_for('routes.edit_consulta', consulta_id=consulta_id))

        try:
            data_hora_consulta_str = f"{data} {hora}"
            data_hora_consulta = datetime.strptime(data_hora_consulta_str, '%Y-%m-%d %H:%M')

            paciente_existente = Paciente.query.filter_by(id=paciente_id, psicologo_id=current_user.id).first()
            if not paciente_existente:
                flash('Paciente inválido. Por favor, selecione um paciente da sua lista.', 'danger')
                return redirect(url_for('routes.edit_consulta', consulta_id=consulta_id))

            consulta.paciente_id = paciente_id
            consulta.data_hora = data_hora_consulta
            consulta.duracao_minutos = duracao
            consulta.notas = notas
            consulta.status = status

            db.session.commit()
            flash('Consulta atualizada com sucesso!', 'success')
            return redirect(url_for('routes.psicologo_agenda'))

        except ValueError:
            flash('Formato de data/hora inválido. Use AAAA-MM-DD e HH:MM.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar consulta: {e}', 'danger')
            return redirect(url_for('routes.edit_consulta', consulta_id=consulta_id))

    pacientes_do_psicologo = Paciente.query.filter_by(psicologo_id=current_user.id).all()
    return render_template('edit_consulta.html', consulta=consulta, pacientes=pacientes_do_psicologo)

@routes.route('/paciente/minhas_consultas')
@login_required
def paciente_minhas_consultas():
    if current_user.tipo != 'paciente':
        flash('Acesso negado. Você não é um paciente.', 'danger')
        return redirect(url_for('routes.login'))

    # Obter todas as consultas do paciente logado, ordenadas por data/hora
    consultas = Consulta.query.filter_by(paciente_id=current_user.id)\
                               .order_by(Consulta.data_hora.asc()).all()

    from datetime import datetime as dt_now
    now = dt_now.utcnow()

    return render_template('paciente_minhas_consultas.html', consultas=consultas, now=now)

@routes.route('/paciente/minhas_consultas/confirmar/<int:consulta_id>', methods=['POST'])
@login_required
def paciente_confirmar_consulta(consulta_id):
    if current_user.tipo != 'paciente':
        flash('Acesso negado. Você não é um paciente.', 'danger')
        return redirect(url_for('routes.login'))

    consulta = Consulta.query.filter_by(id=consulta_id, paciente_id=current_user.id).first()
    if not consulta:
        flash('Consulta não encontrada.', 'danger')
        return redirect(url_for('routes.paciente_minhas_consultas'))

    try:
        consulta.status = 'Confirmada'
        db.session.commit()
        flash('Consulta confirmada com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao confirmar consulta: {e}', 'danger')

    return redirect(url_for('routes.paciente_minhas_consultas'))

@routes.route('/paciente/minhas_consultas/rejeitar/<int:consulta_id>', methods=['POST'])
@login_required
def paciente_rejeitar_consulta(consulta_id):
    if current_user.tipo != 'paciente':
        flash('Acesso negado. Você não é um paciente.', 'danger')
        return redirect(url_for('routes.login'))

    consulta = Consulta.query.filter_by(id=consulta_id, paciente_id=current_user.id).first()
    if not consulta:
        flash('Consulta não encontrada.', 'danger')
        return redirect(url_for('routes.paciente_minhas_consultas'))

    try:
        consulta.status = 'Rejeitada'
        db.session.commit()
        flash('Consulta rejeitada com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao rejeitar consulta: {e}', 'danger')

    return redirect(url_for('routes.paciente_minhas_consultas'))


# Rota para ver os registros de um paciente específico (psicologo)
# Esta é a versão FINAL e CORRIGIDA. A outra versão duplicada deve ser REMOVIDA.
@routes.route('/psicologo/paciente/<int:paciente_user_id>/registros')
@login_required
def ver_registros_paciente(paciente_user_id):
    if current_user.tipo != 'psicologo':
        flash('Acesso negado. Você não é um psicólogo.', 'danger')
        return redirect(url_for('routes.login'))

    # Verifica se o paciente existe e está associado ao psicólogo logado
    # Importante: paciente_user_id é o ID do User, que é o mesmo do Paciente
    paciente = Paciente.query.filter_by(id=paciente_user_id, psicologo_id=current_user.id).first()
    if not paciente:
        flash('Paciente não encontrado ou não associado a você.', 'danger')
        return redirect(url_for('routes.psicologo')) # Redireciona para a lista de pacientes

    # Busca os registros de emoção e respostas de questionário do paciente
    registros_emocoes = RegistroEmocao.query.filter_by(paciente_id=paciente.id).order_by(RegistroEmocao.data_registro.desc()).all()
    respostas_questionarios = RespostaQuestionario.query.filter_by(paciente_id=paciente.id).order_by(RespostaQuestionario.data_resposta.desc()).all()
    respostas_perguntas = RespostaPergunta.query.filter_by(paciente_id=paciente.id).order_by(RespostaPergunta.data_resposta.desc()).all()

    # Convertendo datas para timezone local
    local_tz = pytz.timezone('America/Sao_Paulo')

    for registro in registros_emocoes:
        if registro.data_registro:
            registro.data_registro = registro.data_registro.replace(tzinfo=pytz.utc).astimezone(local_tz)

    for resposta in respostas_questionarios:
        if resposta.data_resposta:
            resposta.data_resposta = resposta.data_resposta.replace(tzinfo=pytz.utc).astimezone(local_tz)

    for resposta_pergunta in respostas_perguntas:
        if resposta_pergunta.data_resposta:
            resposta_pergunta.data_resposta = resposta_pergunta.data_resposta.replace(tzinfo=pytz.utc).astimezone(local_tz)

    # Busca as consultas agendadas com este paciente
    # Garante que o psicólogo só veja as consultas que ele mesmo agendou para este paciente
    consultas_paciente = Consulta.query.filter_by(paciente_id=paciente.id, psicologo_id=current_user.id).order_by(Consulta.data_hora.desc()).all()

    for consulta in consultas_paciente:
        if consulta.data_hora:
            consulta.data_hora = consulta.data_hora.replace(tzinfo=pytz.utc).astimezone(local_tz)

    # Combinar registros de emoções, respostas de questionário e respostas de perguntas em uma lista única ordenada por data
    combined_records = []

    for registro in registros_emocoes:
        combined_records.append({
            'type': 'emocao',
            'data': registro.data_registro,
            'record': registro
        })

    for resposta in respostas_questionarios:
        combined_records.append({
            'type': 'questionario',
            'data': resposta.data_resposta,
            'record': resposta
        })

    for resposta_pergunta in respostas_perguntas:
        combined_records.append({
            'type': 'resposta_pergunta',
            'data': resposta_pergunta.data_resposta,
            'record': resposta_pergunta
        })

    combined_records.sort(key=lambda x: x['data'], reverse=True)

    # Group combined records by day (date only)
    from collections import defaultdict
    grouped_records = defaultdict(list)
    for item in combined_records:
        day = item['data'].date() if item['data'] else None
        grouped_records[day].append(item)

    # Sort grouped records by day descending
    grouped_records_sorted = sorted(grouped_records.items(), key=lambda x: x[0], reverse=True)

    # Agregar dados de emoções para gráfico
    emocao_counts = {}
    for registro in registros_emocoes:
        emocoes = [e.strip() for e in registro.emocao.split(',')]
        for emocao in emocoes:
            if emocao:
                emocao_counts[emocao] = emocao_counts.get(emocao, 0) + 1

    emocao_labels = list(emocao_counts.keys())
    emocao_data = list(emocao_counts.values())

    return render_template('registros_paciente.html', 
                           paciente=paciente, 
                           combined_records=combined_records,
                           grouped_records=grouped_records_sorted,
                           consultas_paciente=consultas_paciente,
                           emocao_labels=emocao_labels,
                           emocao_data=emocao_data) # Passa as consultas e dados para o template
