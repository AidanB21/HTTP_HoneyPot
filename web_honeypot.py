# libraries
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for

# logging format
logging_format = logging.Formatter('%(asctime)s %(message)s')

# HTTP Logger
funnel_logger = logging.getLogger('HTTP Logger') #going to capture username, password, IP
funnel_logger.setLevel(logging.INFO) #sets where the logging will be going to
funnel_handler = RotatingFileHandler('http_audits.log', maxBytes = 2000, backupCount = 5)         #creates an audit log
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Baseline Honeypot

def web_honeypot(input_username = "admin", input_password = "password"):
    app = Flask(__name__)

    @app.route('/')

    def index():
        return render_template('wp-admin.html')
    
    @app.route('/wp-admin-login', methods=['POST'])

    def login():
        username = request.form['username']
        password = request.form['password']

        ip_address = request.remote_addr

        funnel_logger.info(f'Client with IP Address: {ip_address} entered\n Username:{username}, Password: {password}')

        if username == input_username and password == input_password:
            return "YaAAYY!"
        else:
            return "Invalid username or password. Try Again."
        
    return app

def run_web_honeypot(port = 5000, input_username = 'admin', input_password = "password"):
    run_web_honeypot_app = web_honeypot(input_username, input_password)
    run_web_honeypot_app.run(debug = True, port = port, host = "0.0.0.0")

    return run_web_honeypot_app
    

run_web_honeypot(port = 5000, input_username = 'admin', input_password = "password")