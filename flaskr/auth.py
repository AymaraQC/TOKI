import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        Confirmarpassword = request.form['password2']
       
        db = get_db()
        error = None

        if not username:
            error = 'Usuario requerido.'
        elif not password:
            error = 'Contraseña requerida.'
        #elif not Confirmarpassword:
        #   error = 'Confirmacion requerida.'
        elif not Confirmarpassword == password:
            error = 'Confirmacion incorrecta.'
        elif not email:
            error = 'Email requerido.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, email) VALUES (?, ?, ?)", #agregue el email
                    (username, generate_password_hash(password), email),
                )
                db.commit()
            except db.IntegrityError:
                error = f"El usuario {username} ya esta registrado."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Usuario incorrecto.'
        elif not check_password_hash(user['password'], password):
            error = 'Contraseña incorrecta.'

        

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

#agregado
@bp.route('/updatemail', methods=('GET', 'POST'))
@login_required
def cambiaremail():


    if request.method == 'POST':
        emailnuevo = request.form['emailnuevo']#pude ir emailnuevo
        error = None

        if not emailnuevo:
            error = 'email nuevo requerido.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            #pedazo de consulta de la base
            db.execute(
                'UPDATE user SET email = ?'
                ' WHERE id = ?',
                (emailnuevo, g.user["id"])   
            )
            db.commit()
            return redirect(url_for('blog.index'))

    return render_template('auth/email.html')
