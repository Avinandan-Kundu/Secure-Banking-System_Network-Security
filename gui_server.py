from flask import Flask, render_template, request, jsonify
from atm_client import ATMClient  # You will create this next

app = Flask(__name__, static_folder='gui/static', template_folder='gui')
atm = ATMClient("127.0.0.1", 6000)  # Connect to your bank server

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print("========== LOGIN REQUEST ==========")
    print("[FLASK] Received login POST request")
    print("[FLASK] Request JSON:", data)

    try:
        success = atm.connect_and_authenticate(data['username'], data['password'])
        print("[FLASK] ATMClient.connect_and_authenticate() returned:", success)
    except Exception as e:
        print("[FLASK] Error during login:", e)
        success = False

    result = "Login success" if success else "Login failed"
    print("[FLASK] Sending response back to frontend:", result)
    print("====================================\n")
    return result



@app.route('/action', methods=['POST'])
def action():
    data = request.get_json()
    action = data['action']
    amount = data.get('amount', '')
    response = atm.send_transaction(action, amount)
    return response

if __name__ == '__main__':
    app.run(port=8000)
