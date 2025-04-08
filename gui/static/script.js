async function login() {
    const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        })
    });
    const data = await res.text();
    document.getElementById('result').innerText = data;

    if (data.includes("success")) {
        document.getElementById("login-section").style.display = "none";
        document.getElementById("actions").style.display = "block";
    }
}

async function deposit() {
    await transaction("deposit");
}

async function withdraw() {
    await transaction("withdraw");
}

async function checkBalance() {
    await transaction("balance");
}

async function transaction(action) {
    const amount = document.getElementById('amount').value;
    const res = await fetch('/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, amount })
    });
    const data = await res.text();
    document.getElementById('result').innerText = data;
}
