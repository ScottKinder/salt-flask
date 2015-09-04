from flask import Flask, render_template, session, redirect, url_for
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField
from wtforms.validators import Required
from socket import gethostname
from saw import user_session

hostname = gethostname()
app = Flask(__name__)
app.debug = True
app.secret_key = 'abc123'


class LoginForm(Form):
    username = StringField('username',  validators=[Required()])
    password = PasswordField('password', validators=[Required()])


@app.route('/')
def index():
    if session.get('auth_token'):
        username = session.get('username')
        auth_token = session.get('auth_token')
    else:
        return redirect(url_for('login'))
    return render_template('base.html', hostname=hostname, username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('auth_token'):
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        session['username'] = form.username.data
        user = user_session(user_name=session.get('username'))
        user.set_auth_token(user_pass=form.password.data)
        session['auth_token'] = user.auth_token
        return redirect(url_for('index'))
    return render_template('login.html', form=form, hostname=hostname)


@app.route('/logout')
def logout():
    session.pop('auth_token', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0')
