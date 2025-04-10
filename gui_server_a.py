from flask import Flask, render_template, request, jsonify, session
from atm_client_a import ATMClient
from flask_cors import CORS

app = Flask(__name__, static_folder='gui/static', template_folder='gui')
CORS(app)
app.secret_key = 'supersecretkey'

atm = ATMClient("127.0.0.1", 6000)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    print(f"[FLASK A] Login request for {username}")

    success = atm.connect_and_authenticate(username, password)
    session['username'] = username if success else None
    return "Login success" if success else "Login failed"

@app.route('/action', methods=['POST'])
def action():
    data = request.get_json()
    username = session.get('username')
    if not username:
        return "User not logged in", 403

    action = data['action']
    amount = data.get('amount', '')
    result = atm.send_transaction(action, amount)
    return result

if __name__ == '__main__':
    app.run(port=8000)
