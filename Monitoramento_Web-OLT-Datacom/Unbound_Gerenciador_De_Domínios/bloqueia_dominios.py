import json
import time
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, render_template_string, jsonify, redirect, url_for, session
import paramiko

# Variável global para sessões ativas
active_sessions = {}

# Nome do arquivo de logs
LOG_FILE = "logs.json"

app = Flask(__name__)
app.secret_key = "sua_chave_secreta_aqui"  # Altere para uma chave secreta 
app.permanent_session_lifetime = timedelta(hours=1)  # A sessão expira após 1 hora

#####################
# Funções para Gerenciamento de Logs
#####################
def load_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                return json.load(f)
            except Exception:
                return []
    return []

def save_logs(logs):
    # Mantém somente os 100 registros mais recentes
    logs = logs[-100:]
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

def record_log(message):
    logs = load_logs()
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "message": message
    }
    logs.append(log_entry)
    save_logs(logs)

#####################
# Função para Capturar IP da máquina que está acessando
#####################
def get_client_ip():
    return request.remote_addr or "Desconhecido"

#####################
# Carrega Credenciais e Senha
#####################
with open("credenciais.json", "r") as f:
    SERVIDORES = json.load(f)

with open("login-senha.json", "r") as f:
    login_data = json.load(f)
LOGIN_SENHA = login_data.get("senha", "")

#####################
# Templates HTML (Obrigado GPT)
#####################

# Template para a página de login (login.html)
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Login - Domain Manager</title>
    <style>
        body {
            background-color: #000;
            color: #fff;
            font-family: Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: #222;
            padding: 20px;
            border: 1px solid #444;
            border-radius: 5px;
            width: 300px;
        }
        input[type="password"] {
            width: 100%;
            padding: 10px;
            background-color: #333;
            border: 1px solid #555;
            color: #fff;
            margin-bottom: 10px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #444;
            border: none;
            color: #fff;
            cursor: pointer;
        }
        button:hover {
            background-color: #666;
        }
        .error { color: red; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <form method="POST">
            <input type="password" name="senha" placeholder="Digite a senha" required>
            <button type="submit">Entrar</button>
        </form>
    </div>
</body>
</html>
"""

# Template para a página principal (Pagina-principal.html)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Domain Manager - Dns-Recursivo</title>
    <style>
        body {
            background-color: #000;
            color: #fff;
            font-family: Arial, sans-serif;
            margin: 20px;
            position: relative;
        }
        input[type="text"], textarea {
            width: 100%;
            padding: 10px;
            background-color: #222;
            color: #fff;
            border: 1px solid #444;
            margin-bottom: 10px;
        }
        textarea {
            height: 200px;
        }
        .result-container {
            display: flex;
            background: #222;
            border: 1px solid #444;
            padding: 10px;
            overflow-x: auto;
            font-family: monospace;
            white-space: pre;
        }
        .line-numbers {
            text-align: right;
            margin-right: 10px;
            border-right: 1px solid #444;
            padding-right: 10px;
            user-select: none;
            color: #888;
        }
        .result-text {
            flex: 1;
        }
        button {
            padding: 8px 16px;
            margin: 5px 5px;
            background-color: #444;
            color: #fff;
            border: none;
            cursor: pointer;
        }
        button:hover {
            background-color: #666;
        }
        /* Container para os botões */
        .button-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .button-left, .button-right {
            display: flex;
            gap: 10px;
        }
        /* Estilos para o modal */
        #modalOverlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: none;
            align-items: center;
            justify-content: center;
        }
        #modalContent {
            background: #222;
            padding: 20px;
            border: 1px solid #444;
            max-width: 600px;
            width: 90%;
            max-height: 80%;
            overflow-y: auto;
            position: relative;
        }
        #modalContent h3 {
            margin-top: 0;
        }
        #modalContent label {
            display: block;
            margin-bottom: 10px;
        }
        /* Botão "X" para fechar */
        #closeResultsButton {
            position: absolute;
            right: 10px;
            top: 10px;
            background: transparent;
            color: #fff;
            border: none;
            font-size: 24px;
            cursor: pointer;
        }
        #closeResultsButton:hover {
            color: red;
        }
        /* Indicador de sessões (agora à esquerda do botão log) */
        #session-indicator {
            position: absolute;
            top: 10px;
            right: 80px;
            background: red;
            color: white;
            padding: 5px 10px;
            border-radius: 12px;
            cursor: pointer;
            font-weight: bold;
        }
        /* Botão de Log (agora à direita) */
        #log-button {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #444;
            color: #fff;
            padding: 5px 10px;
            border-radius: 12px;
            cursor: pointer;
            font-weight: bold;
            border: none;
        }
        #log-button:hover {
            background: #666;
        }
        #session-tooltip {
            position: absolute;
            background: #222;
            color: #fff;
            padding: 5px;
            border: 1px solid #444;
            border-radius: 5px;
            display: none;
            z-index: 1000;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <!-- Botão de Log e Indicador de Sessões -->
    <button id="log-button" onclick="window.location.href='/log'">Log</button>
    <div id="session-indicator">0</div>
    <div id="session-tooltip"></div>

    <h1>Gerenciador de Domínios - Blacklist.conf</h1>
    <form id="mainForm" method="POST">
        <label for="title">Insira um título para os novos Domínios a serem Bloqueados:</label>
        <input type="text" id="title" name="title" placeholder="Ex: Ofício CyberGreco - XYZ" value="{{ title or '' }}">
        <label for="domains">Cole os domínios abaixo (cada domínio em uma linha):</label>
        <textarea name="domains" id="domains" placeholder="exemplo.com&#10;outrodominio.net">{{ domains or "" }}</textarea>
        <br>
        <!-- Container flex para alinhar os botões -->
        <div class="button-container">
            <div class="button-left">
                <button type="submit">👇 Formatar</button>
                <button type="button" id="copyButton" onclick="copyResult()">👇 Copiar Formatação</button>
            </div>
            <div class="button-right">
                <button type="button" onclick="openModal()">👮🚫 Add na Blacklist</button>
                <button type="button" onclick="window.location.href='/select_edit'">👮✏️ Editar Blacklist</button>
            </div>
        </div>
    </form>

    {% if resultado %}
    <h2>=== Formatação para Bloqueio ===</h2>
    <div class="result-container">
        <div class="line-numbers">
            {% for i in range(1, lines|length + 1) %}
                {{ i }}<br>
            {% endfor %}
        </div>
        <div class="result-text" id="resultText">
{{ resultado }}
        </div>
    </div>
    {% endif %}

    <!-- Modal para seleção dos servidores -->
    <div id="modalOverlay">
        <div id="modalContent">
            <button id="closeResultsButton" onclick="closeModal()">×</button>
            <h3> 👇 Executar no Blacklist.conf - DNS Recursivo</h3>
            <div id="selecaoServidores">
                {% for nome, info in servidores.items() %}
                    <label>
                        <input type="checkbox" name="servidores" value="{{ nome }}">
                        {{ nome }} - {{ info.ip }}
                    </label>
                {% endfor %}
                <div style="text-align: right; margin-top: 15px;">
                    <button type="button" onclick="executeDNS()">Confirmar</button>
                    <button type="button" onclick="closeModal()">Cancelar</button>
                </div>
            </div>
            <div id="resultadoServidores" style="display:none;"></div>
        </div>
    </div>

    <script>
        // Função para copiar resultado
        function copyResult() {
            var resultElem = document.getElementById('resultText');
            if (!resultElem) {
                alert("Não há resultado para copiar.");
                return;
            }
            var textToCopy = resultElem.innerText;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(textToCopy).then(function() {
                    alert("Resultado copiado para a área de transferência!");
                }, function(err) {
                    alert("Erro ao copiar o texto: " + err);
                });
            } else {
                let tempTextArea = document.createElement("textarea");
                tempTextArea.value = textToCopy;
                tempTextArea.style.position = "fixed";
                tempTextArea.style.top = "0";
                tempTextArea.style.left = "0";
                tempTextArea.style.opacity = "0";
                document.body.appendChild(tempTextArea);
                tempTextArea.focus();
                tempTextArea.select();
                try {
                    var successful = document.execCommand('copy');
                    if(successful){
                        alert("Resultado copiado para a área de transferência!");
                    } else {
                        alert("Falha ao copiar o texto.");
                    }
                } catch (err) {
                    alert("Erro ao copiar o texto: " + err);
                }
                document.body.removeChild(tempTextArea);
            }
        }

        // Funções para o Modal
        function openModal() {
            var resultElem = document.getElementById('resultText');
            if (!resultElem || resultElem.innerText.trim() === "") {
                alert("Não há resultado formatado. Primeiro preencha e formate os domínios.");
                return;
            }
            document.getElementById('selecaoServidores').style.display = "block";
            document.getElementById('resultadoServidores').style.display = "none";
            document.getElementById('modalOverlay').style.display = "flex";
        }
        function closeModal() {
            document.getElementById('modalOverlay').style.display = "none";
        }

        // Função para executar comandos nos servidores remotos
        function executeDNS() {
            var checkboxes = document.querySelectorAll('input[name="servidores"]:checked');
            if (checkboxes.length === 0) {
                return;
            }
            var servidores = [];
            checkboxes.forEach(function(cb) {
                servidores.push(cb.value);
            });
            var resultado = document.getElementById('resultText').innerText;
            fetch("/exec_dns", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ servidores: servidores, resultado: resultado })
            })
            .then(response => response.json())
            .then(data => {
                var resultadosDiv = document.getElementById('resultadoServidores');
                resultadosDiv.innerHTML = "<h3>Resultados dos Comandos</h3>";
                for (var servidor in data.mensagem) {
                    var info = data.mensagem[servidor];
                    resultadosDiv.innerHTML += "<div style='margin-bottom:20px; border-bottom:1px solid #444; padding-bottom:10px;'>" +
                        "<strong>" + servidor + " - " + info.ip + "</strong><br>" +
                        (info.conclusao ? info.conclusao : "") +
                        (info.shell_output ? "<br><pre style='background:#111; padding:10px; overflow:auto;'>" + info.shell_output + "</pre>" : "") +
                        "</div>";
                }
                document.getElementById('selecaoServidores').style.display = "none";
                resultadosDiv.style.display = "block";
            })
            .catch(err => {
                console.error("Erro na execução:", err);
                closeModal();
            });
        }

        // Atualiza o contador de sessões ativas e o tooltip
        function updateSessionCounter() {
            fetch("/heartbeat", { method: "POST", headers: { "X-Requested-With": "XMLHttpRequest" }})
                .then(response => response.json())
                .then(data => {
                    document.getElementById("session-indicator").textContent = data.active;
                    let tooltipHTML = "<strong>Sessões Ativas:</strong><br>";
                    data.sessions.forEach(function(sess) {
                        tooltipHTML += sess.user + " - " + sess.ip + "<br>";
                    });
                    document.getElementById("session-tooltip").innerHTML = tooltipHTML;
                })
                .catch(error => console.error("Erro ao atualizar contador:", error));
        }

        // Exibe tooltip ao passar o mouse sobre o indicador
        var sessionIndicator = document.getElementById("session-indicator");
        var tooltip = document.getElementById("session-tooltip");
        sessionIndicator.addEventListener("mouseover", function(e) {
            tooltip.style.display = "block";
            var rect = sessionIndicator.getBoundingClientRect();
            tooltip.style.left = rect.left + "px";
            tooltip.style.top = (rect.bottom + window.scrollY) + "px";
        });
        sessionIndicator.addEventListener("mouseout", function(e) {
            tooltip.style.display = "none";
        });

        setInterval(updateSessionCounter, 5000);
        updateSessionCounter();

        // Encerra a sessão ao fechar ou recarregar a página
        window.addEventListener("beforeunload", function() {
            navigator.sendBeacon("/logout");
        });
    </script>
</body>
</html>
"""

# Template para a página de log (log.html)
LOG_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Logs - Domain Manager</title>
    <style>
        body {
            background-color: #000;
            color: #fff;
            font-family: Arial, sans-serif;
            padding: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #444;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #222;
        }
        tr:nth-child(even) {
            background-color: #111;
        }
        a {
            color: #0af;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <h1>Logs das Ações Executadas</h1>
    <a href="{{ url_for('index') }}">← Voltar</a>
    <table>
        <tr>
            <th>Data/Horário</th>
            <th>Ação</th>
        </tr>
        {% for log in logs %}
        <tr>
            <td>{{ log.timestamp }}</td>
            <td>{{ log.message }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

#####################
# Funções Auxiliares
#####################
def process_domains(domains_text, title_text):
    resultado = []
    title_text = title_text.strip()
    if title_text:
        resultado.append(f"#{title_text}")
    else:
        resultado.append("")
    for line in domains_text.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        if "local-zone:" in trimmed or "local-data:" in trimmed:
            continue
        if "." not in trimmed:
            continue
        resultado.append(f'local-zone: "{trimmed}" redirect')
        resultado.append(f'local-data: "{trimmed} A 127.0.0.1"\n')
    return "\n".join(resultado)

def execute_commands_on_remote(server_info, texto):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    shell_output = ""
    try:
        client.connect(hostname=server_info["ip"],
                       port=server_info["port"],
                       username=server_info["user"],
                       password=server_info["password"],
                       timeout=10)
        comando_append = (
            f'echo "{server_info["password"]}" | sudo -S -p "" sh -c \'cat >> /etc/unbound/unbound.conf.d/blacklist.conf << "EOF"\n'
            f'{texto}\n'
            'EOF\n\''
        )
        stdin, stdout, stderr = client.exec_command(comando_append, get_pty=True)
        erro_append = stderr.read().decode().strip()
        if erro_append and "[sudo] password" in erro_append:
            client.close()
            return (False, erro_append, "", "")
        comando_reload = f'echo "{server_info["password"]}" | sudo -S -p "" systemctl reload unbound'
        stdin, stdout, stderr = client.exec_command(comando_reload, get_pty=True)
        erro_reload = stderr.read().decode().strip()
        time.sleep(5)
        comando_status = f'echo "{server_info["password"]}" | sudo -S -p "" systemctl status unbound --no-pager'
        stdin, stdout, stderr = client.exec_command(comando_status, get_pty=True)
        status_output = stdout.read().decode()
        erro_status = stderr.read().decode().strip()
        erros_consolidados = (erro_reload + "\n" + erro_status).strip()
        if "active (running)" in status_output:
            conclusao = "CONCLUÍDO, UNBOUND RODANDO"
            shell_output = ""
        else:
            conclusao = "ERRO!! UNBOUND DESATIVADO"
            comando_checkconf = f'echo "{server_info["password"]}" | sudo -S -p "" unbound-checkconf'
            stdin, stdout, stderr = client.exec_command(comando_checkconf, get_pty=True)
            shell_output = stdout.read().decode()
            shell_erro = stderr.read().decode().strip()
            if shell_erro:
                shell_output += "\n" + shell_erro
            comando_start = f'echo "{server_info["password"]}" | sudo -S -p "" systemctl start unbound'
            stdin, stdout, stderr = client.exec_command(comando_start, get_pty=True)
            start_output = stdout.read().decode().strip()
            start_error = stderr.read().decode().strip()
            if start_error:
                shell_output += "\nStart Error: " + start_error
            else:
                shell_output += "\nStart executado com sucesso." if start_output == "" else "\n" + start_output
        client.close()
        return (True, erros_consolidados, conclusao, shell_output)
    except Exception as e:
        client.close()
        return (False, str(e), "", "")

def reload_unbound_on_remote(server_info):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    shell_output = ""
    try:
        client.connect(hostname=server_info["ip"],
                       port=server_info["port"],
                       username=server_info["user"],
                       password=server_info["password"],
                       timeout=10)
        comando_reload = f'echo "{server_info["password"]}" | sudo -S -p "" systemctl reload unbound'
        stdin, stdout, stderr = client.exec_command(comando_reload, get_pty=True)
        erro_reload = stderr.read().decode().strip()
        time.sleep(5)
        comando_status = f'echo "{server_info["password"]}" | sudo -S -p "" systemctl status unbound --no-pager'
        stdin, stdout, stderr = client.exec_command(comando_status, get_pty=True)
        status_output = stdout.read().decode()
        erro_status = stderr.read().decode().strip()
        erros_consolidados = (erro_reload + "\n" + erro_status).strip()
        if "active (running)" in status_output:
            conclusao = "CONCLUÍDO, UNBOUND ATIVO"
            shell_output = ""
        else:
            conclusao = "CONCLUÍDO, porém verifique o status"
            comando_checkconf = f'echo "{server_info["password"]}" | sudo -S -p "" unbound-checkconf'
            stdin, stdout, stderr = client.exec_command(comando_checkconf, get_pty=True)
            shell_output = stdout.read().decode()
            shell_erro = stderr.read().decode().strip()
            if shell_erro:
                shell_output += "\n" + shell_erro
            comando_start = f'echo "{server_info["password"]}" | sudo -S -p "" systemctl start unbound'
            stdin, stdout, stderr = client.exec_command(comando_start, get_pty=True)
            start_output = stdout.read().decode().strip()
            start_error = stderr.read().decode().strip()
            if start_error:
                shell_output += "\nStart Error: " + start_error
            else:
                shell_output += "\nStart executado com sucesso." if start_output == "" else "\n" + start_output
        client.close()
        return (True, erros_consolidados, conclusao, shell_output)
    except Exception as e:
        client.close()
        return (False, str(e), "", "")

def read_remote_blacklist(server_info):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=server_info["ip"],
                       port=server_info["port"],
                       username=server_info["user"],
                       password=server_info["password"],
                       timeout=10)
        comando_cat = f'echo "{server_info["password"]}" | sudo -S -p "" cat /etc/unbound/unbound.conf.d/blacklist.conf'
        stdin, stdout, stderr = client.exec_command(comando_cat, get_pty=True)
        conteudo = stdout.read().decode()
        conteudo = conteudo.replace('\r\n', '\n').replace('\r', '')
        client.close()
        return conteudo
    except Exception as e:
        client.close()
        return f"Erro ao ler o arquivo: {str(e)}"

def save_remote_blacklist(server_info, novo_conteudo):
    novo_conteudo = novo_conteudo.replace('\r\n', '\n').replace('\r', '')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=server_info["ip"],
                       port=server_info["port"],
                       username=server_info["user"],
                       password=server_info["password"],
                       timeout=10)
        sftp = client.open_sftp()
        remote_temp_path = "/tmp/blacklist.conf.tmp"
        with sftp.open(remote_temp_path, "w") as remote_file:
            remote_file.write(novo_conteudo)
        sftp.close()
        comando_move = (
            f'echo "{server_info["password"]}" | sudo -S cp {remote_temp_path} /etc/unbound/unbound.conf.d/blacklist.conf && '
            f'sudo rm -f {remote_temp_path}'
        )
        stdin, stdout, stderr = client.exec_command(comando_move, get_pty=True)
        error = stderr.read().decode().strip()
        client.close()
        return error
    except Exception as e:
        client.close()
        return str(e)

#####################
# Decorador de Verificação de Login
#####################
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

#####################
# Rotas de Login e Logout
#####################
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        senha = request.form.get("senha", "")
        if senha == LOGIN_SENHA:
            session.permanent = True
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            error = "Senha incorreta. Tente novamente."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

#####################
# Restrição de Acesso
#####################
@app.before_request
def require_login():
    if request.endpoint not in ("login", "static") and not session.get("logged_in"):
        return redirect(url_for("login"))

#####################
# Rotas para Sessões Ativas e Logs
#####################
@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    if "session_id" not in session:
         session["session_id"] = os.urandom(16).hex()
    active_sessions[session["session_id"]] = {
         "timestamp": datetime.now(),
         "user": session.get("logged_in", "Não autenticado"),
         "ip": get_client_ip()
    }
    threshold = datetime.now() - timedelta(seconds=30)
    active_list = []
    for sid in list(active_sessions.keys()):
        if active_sessions[sid]["timestamp"] < threshold:
            del active_sessions[sid]
        else:
            active_list.append({"user": active_sessions[sid]["user"], "ip": active_sessions[sid]["ip"]})
    return jsonify({"active": len(active_sessions), "sessions": active_list})

@app.route("/record_log", methods=["POST"])
def record_log_route():
    data = request.get_json()
    action = data.get("action", "Ação desconhecida")
    record_log(action)
    return jsonify({"status": "ok"})

@app.route("/log")
@login_required
def view_log():
    recent_logs = load_logs()[::-1]  # Inverte a lista para que o mais novo apareça no topo
    return render_template_string(LOG_TEMPLATE, logs=recent_logs)

#####################
# Rotas Principais da Aplicação
#####################
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    domains = ""
    resultado = ""
    title = ""
    line_list = []
    if request.method == "POST":
        title = request.form.get("title", "")
        domains = request.form.get("domains", "")
        resultado = process_domains(domains, title)
        line_list = resultado.split("\n")
    return render_template_string(HTML_TEMPLATE, domains=domains, resultado=resultado, title=title, lines=line_list, servidores=SERVIDORES)

@app.route("/exec_dns", methods=["POST"])
@login_required
def exec_dns():
    data = request.get_json()
    servidores_escolhidos = data.get("servidores", [])
    resultado_texto = data.get("resultado", "")
    resposta = {}
    for srv in servidores_escolhidos:
        if srv in SERVIDORES:
            success, erros, conclusao, shell_output = execute_commands_on_remote(SERVIDORES[srv], resultado_texto)
            if not success:
                resposta[srv] = {
                    "ip": SERVIDORES[srv]["ip"],
                    "conclusao": f"ERRO: {erros}",
                    "shell_output": ""
                }
            else:
                resposta[srv] = {
                    "ip": SERVIDORES[srv]["ip"],
                    "conclusao": conclusao,
                    "shell_output": shell_output
                }
                record_log(f"Alteração executada via exec_dns no servidor {srv} em {datetime.now().isoformat()}")
        else:
            resposta[srv] = {
                "ip": "Desconhecido",
                "conclusao": "Servidor não encontrado nas credenciais.",
                "shell_output": ""
            }
    return jsonify({"mensagem": resposta})

@app.route("/select_edit")
@login_required
def select_edit():
    template = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <title>Selecione o Servidor para Editar Blacklist</title>
        <style>
            body { background-color: #000; color: #fff; font-family: Arial, sans-serif; padding: 20px; }
            a { color: #0af; text-decoration: none; font-size: 18px; display: block; margin-bottom: 10px; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>Selecione o Servidor para Editar a Blacklist</h1>
        {% for nome, info in servidores.items() %}
            <a href="{{ url_for('edit_blacklist', server=nome) }}">{{ nome }} - {{ info.ip }}</a>
        {% endfor %}
        <br>
        <a href="{{ url_for('index') }}">← Voltar</a>
    </body>
    </html>
    """
    return render_template_string(template, servidores=SERVIDORES)

@app.route("/edit_blacklist/<server>", methods=["GET", "POST"])
@login_required
def edit_blacklist(server):
    if server not in SERVIDORES:
        return f"Servidor {server} não encontrado.", 404
    servidor_info = SERVIDORES[server]
    mensagem = ""
    conteudo_completo = read_remote_blacklist(servidor_info)
    linhas = conteudo_completo.split('\n')
    header = ""
    if linhas and linhas[0].startswith("server:"):
        header = linhas[0]
        conteudo_para_editar = "\n".join(linhas[1:])
    else:
        conteudo_para_editar = conteudo_completo

    if request.method == "POST":
        novo_conteudo_editado = request.form.get("conteudo", "")
        if header:
            novo_conteudo_completo = header + "\n" + novo_conteudo_editado
        else:
            novo_conteudo_completo = novo_conteudo_editado
        erro = save_remote_blacklist(servidor_info, novo_conteudo_completo)
        if erro:
            mensagem = f"Erro ao salvar: {erro}"
        else:
            mensagem = "Arquivo salvo com sucesso."
            success, erros, conclusao, shell_output = reload_unbound_on_remote(servidor_info)
            if not success:
                mensagem += f" Erro ao recarregar: {erros}"
            else:
                mensagem += f" {conclusao}"
                if shell_output:
                    mensagem += f" {shell_output}"
            record_log(f"Arquivo editado e recarregado no servidor {server} em {datetime.now().isoformat()}")
        conteudo_completo = read_remote_blacklist(servidor_info)
        linhas = conteudo_completo.split('\n')
        if linhas and linhas[0].startswith("server:"):
            header = linhas[0]
            conteudo_para_editar = "\n".join(linhas[1:])
        else:
            conteudo_para_editar = conteudo_completo

    editor_template = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <title>Editar Blacklist - {{ server }}</title>
        <style>
            body { background-color: #000; color: #fff; font-family: Arial, sans-serif; padding: 20px; }
            textarea { 
                width: 100%; 
                height: 500px; 
                padding: 10px; 
                background-color: #222; 
                color: #fff; 
                border: 1px solid #444; 
                font-family: monospace;
                white-space: pre;
                box-sizing: border-box;
            }
            button { padding: 8px 16px; margin-top: 10px; background-color: #444; color: #fff; border: none; cursor: pointer; }
            button:hover { background-color: #666; }
            a { color: #0af; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>Editar Blacklist - {{ server }}</h1>
        {% if mensagem %}
            <p>{{ mensagem }}</p>
        {% endif %}
        <form method="POST">
            <textarea name="conteudo">{{ conteudo }}</textarea><br>
            <button type="submit">Salvar e Aplicar</button>
        </form>
        <br>
        <a href="{{ url_for('select_edit') }}">← Voltar</a>
    </body>
    </html>
    """
    return render_template_string(editor_template, server=server, conteudo=conteudo_para_editar, mensagem=mensagem)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6060, debug=True)
