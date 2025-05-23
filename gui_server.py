from flask import Flask, render_template, request, jsonify, session
from atm_client import ATMClient
from flask_cors import CORS

app = Flask(__name__, static_folder='gui/static', template_folder='gui')
CORS(app)
app.secret_key = 'supersecretkey'

# Dictionary to track each logged-in user's ATM client
clients = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    atm = ATMClient("127.0.0.1", 6000)
    success = atm.connect_and_authenticate(username, password)

    if success:
        session['username'] = username
        clients[username] = atm
        return "Login success"
    else:
        return "Login failed"

@app.route('/action', methods=['POST'])
def action():
    username = session.get('username')
    if not username or username not in clients:
        return "User not logged in", 403

    atm = clients[username]
    data = request.get_json()
    action = data['action']
    amount = data.get('amount', '')
    result = atm.send_transaction(action, amount)
    return result

if __name__ == '__main__':
    app.run(port=8000)
