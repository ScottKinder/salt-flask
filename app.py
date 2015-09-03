from flask import Flask, render_template, redirect, url_for
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField
from wtforms.validators import Required
from socket import gethostname

hostname = gethostname()
app = Flask(__name__)
app.debug = True
app.secret_key = 'abc123'


class LoginForm(Form):
    username = StringField('username',  validators=[Required()])
    password = PasswordField('password', validators=[Required()])


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        return redirect(url_for('index'))
    return render_template('login.html', form=form, hostname=hostname)


@app.route('/')
def index():
    return render_template('base.html', hostname=hostname, username='slk')


if __name__ == '__main__':
    app.run(host='0.0.0.0')
