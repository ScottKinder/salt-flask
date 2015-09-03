# salt-flask
How to run
* $git clone https://github.com/ScottKinder/salt-flask.git
* $cd salt-flask
* $virtualenv venv
* $source venv/bin/activate
* $pip install -r requirements.txt
* $python app.py

## Nginx and uwsgi
* Edit nginx_salt_vhost as necessary, updating server_name and other variables
as necessary.
* $sudo cp nginx_salt_host /etc/nginx/sites-available/
* $sudo ln -s /etc/nginx/sites-available/nginx_salt_host /etc/nginx/sites-enabled/nginx_salt_vhost
* $service service nginx restart
* Edit salt-flask_upstart.conf as necessary.
* $sudo cp salt-flask_upstart.conf /etc/init/salt-flask.conf
* Edit app.ini as necessary
* $sudo service salt-flask start
