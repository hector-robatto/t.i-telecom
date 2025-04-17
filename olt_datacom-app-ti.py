from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify
from functools import wraps
from datetime import timedelta, datetime
import json
import paramiko
import threading
from collections import defaultdict
from tabulate import tabulate
import os
import re

# Imports para execução em multithread na automação
from concurrent.futures import ThreadPoolExecutor, as_completed

# Imports para agendamento
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# Carrega a configuração a partir do arquivo JSON
with open("config.json", "r") as f:
    config = json.load(f)

# Dados de credenciais para SSH e login
ssh_username = config["ssh"]["username"]
ssh_password = config["ssh"]["password"]
ssh_default_port = config["ssh"].get("port", "22")
login_password = config["login_password"]

app = Flask(__name__)
app.secret_key = config.get("secret_key", "defaultsecret")
app.permanent_session_lifetime = timedelta(hours=1)

# Global flag para cancelamento de operações iniciadas pelo usuário
cancel_user = False

# LOCK para escrita dos relatórios (cada escrita é independente)
report_lock = threading.Lock()

# Pasta base para salvar os relatórios individualmente por OLT
REPORTS_FOLDER = "relatorios_gerados"

def sanitize_olt_name(olt_name):
    """
    Converte o nome da OLT para um formato seguro para nomes de arquivo:
    permite letras, números, hífens e underlines, substituindo outros caracteres por underlines.
    """
    return re.sub(r'[^A-Za-z0-9\-_]', '_', olt_name)

# ---------------------------
# Funções de SSH e Processamento
# ---------------------------
def ssh_execute_commands(olt_ip, username, password, commands, check_cancel=True):
    global cancel_user
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    outputs = {}
    try:
        client.connect(olt_ip, username=username, password=password)
        for label, command in commands.items():
            if check_cancel and cancel_user:
                client.close()
                return None, ""
            stdin, stdout, stderr = client.exec_command(command)
            outputs[label] = stdout.read().decode().strip()
        client.close()
    except paramiko.AuthenticationException:
        return None, "Erro de autenticação!"
    except Exception as e:
        return None, f"Erro: {e}"
    return outputs, None

def process_pppoe_sessions(output2, default_gpon):
    pppoe_sessions = defaultdict(list)
    current_gpon = None
    current_onu_id = None
    for line in output2.splitlines():
        line = line.strip()
        if line.startswith("gpon ") and not line.startswith("gpon-status"):
            parts = line.split()
            if len(parts) >= 2:
                current_gpon = parts[1]
        elif line.startswith("onu-id"):
            parts = line.split()
            if len(parts) >= 2:
                current_onu_id = parts[1].rstrip(";")
        elif line.startswith("remote-mac") and current_onu_id is not None:
            parts = line.split()
            if len(parts) >= 2:
                remote_mac = parts[1].rstrip(";")
                if not current_gpon:
                    current_gpon = default_gpon
                composite_key = f"{current_gpon}/{current_onu_id}"
                pppoe_sessions[composite_key].append(remote_mac)
    return pppoe_sessions

def process_service_ports(output4, default_gpon):
    service_ports = defaultdict(list)
    current_service = None
    for line in output4.splitlines():
        line = line.strip()
        if line.startswith("service-port"):
            parts = line.split()
            if len(parts) >= 2:
                current_service = parts[1]
        elif line.startswith("gpon") and current_service is not None:
            parts = line.split()
            gpon_val = parts[1] if len(parts) >= 2 else default_gpon
            if "onu" in parts:
                try:
                    onu_index = parts.index("onu")
                    onu_val = parts[onu_index + 1].strip(";")
                    composite_key = f"{gpon_val}/{onu_val}"
                    service_ports[composite_key].append(current_service)
                except (IndexError, ValueError):
                    pass
            current_service = None
    return service_ports

def process_vlans(output3, default_gpon):
    vlan_info = defaultdict(list)
    current_gpon = None
    current_onu = None
    for line in output3.splitlines():
        line = line.strip()
        if line.startswith("gpon ") and not line.startswith("gpon-status"):
            parts = line.split()
            if len(parts) >= 2:
                current_gpon = parts[1]
        elif line.startswith("onu"):
            parts = line.split()
            if len(parts) >= 2:
                current_onu = parts[1].rstrip(";")
        elif "vlan-id" in line and current_onu:
            parts = line.split()
            if len(parts) >= 2:
                vlan_id = parts[1].rstrip(";")
                if not current_gpon:
                    current_gpon = default_gpon
                composite_key = f"{current_gpon}/{current_onu}"
                vlan_info[composite_key].append(vlan_id)
    return vlan_info

def process_ssh_outputs(outputs, interface):
    onus = {}
    current_onu = None
    current_gpon = interface
    output1 = outputs.get('onus', '')
    for line in output1.splitlines():
        line = line.strip()
        if line.startswith("gpon ") and not line.startswith("gpon-status"):
            parts = line.split()
            if len(parts) >= 2:
                current_gpon = parts[1]
        elif line.startswith('onu'):
            if current_onu:
                key = f"{current_onu['gpon']}/{current_onu['onu']}"
                onus[key] = current_onu
            parts = line.split()
            if len(parts) >= 2:
                onu_number = parts[1]
                current_onu = {'onu': onu_number, 'gpon': current_gpon}
        elif current_onu:
            split_line = line.split(maxsplit=1)
            if len(split_line) == 2:
                k, v = split_line
                current_onu[k.strip()] = v.strip().rstrip(";")
    if current_onu:
        key = f"{current_onu['gpon']}/{current_onu['onu']}"
        onus[key] = current_onu

    output2 = outputs.get('pppoe_sessions', '')
    pppoe_sessions = process_pppoe_sessions(output2, interface)

    output3 = outputs.get('vlans', '')
    vlan_info = process_vlans(output3, interface)

    output4 = outputs.get('service_ports', '')
    service_ports = process_service_ports(output4, interface)

    headers = [
        "Gpon", "onu", "Serial-Onu", "Documentacao", "Estado", "Sinal-rx",
        "Tempo On", "Off há", "Porta Wan", "P.Cord(Mb)", "NºMac's",
        "Mac-Roteador", "Vlan(*V4/Eth)", "Ipv4-Address", "service-port"
    ]

    table_data = []
    for composite_key, onu_info in onus.items():
        row = []
        gpon_val = onu_info.get("gpon", interface)
        if "/" in gpon_val:
            gpon_val = gpon_val.split("/")[-1]
        row.append(gpon_val)
        row.append(onu_info.get("onu", "N/A"))
        row.append(onu_info.get("serial-number", "N/A"))
        row.append(onu_info.get("name", "N/A"))
        row.append(onu_info.get("oper-state", "N/A"))
        row.append(onu_info.get("rx-optical-pw", "N/A"))
        row.append(onu_info.get("uptime", "N/A"))
        row.append(onu_info.get("last-seen-online", "N/A"))
        row.append(onu_info.get("link", "N/A"))
        row.append(onu_info.get("negotiatedSpeed", "N/A"))
        remote_macs = pppoe_sessions.get(composite_key, [])
        row.append(str(len(remote_macs)) if remote_macs else "0")
        row.append(" / ".join(remote_macs) if remote_macs else "N/A")
        vlans = vlan_info.get(composite_key, [])
        row.append(", ".join(vlans) if vlans else "N/A")
        row.append(onu_info.get("dhcp-status-ipv4-cidr", "N/A"))
        sp_list = service_ports.get(composite_key, [])
        row.append(" / ".join(sp_list) if sp_list else "N/A")
        table_data.append(row)

    return headers, table_data

# ---------------------------
# Funções para pesquisa de MAC (já existentes)
# ---------------------------
def load_olt_data_zabbix():
    JSON_FILE = "/opt/script/datacom/0-lista-de-olts-zabbix.json"
    try:
        with open(JSON_FILE, 'r') as f:
            data = json.load(f)
        return {name: values[0] for name, values in data.items() if isinstance(values, list) and values}
    except Exception as e:
        return {}

def ssh_execute_mac_search(olt_ip, olt_name, username, password, port, mac):
    global cancel_user
    if cancel_user:
        return ""
    command = f"show pppoe intermediate-agent sessions interface gpon | include {mac}"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(olt_ip, username=username, password=password, port=int(port), timeout=10)
        stdin, stdout, stderr = client.exec_command(command)
        result = stdout.read().decode().strip()
        client.close()
    except Exception as e:
        result = f"Erro: {e}"
    return result

def ssh_mac_search(olt_dict, username, password, port, mac):
    global cancel_user
    semaphore = threading.Semaphore(5)
    lock = threading.Lock()
    results = {}
    threads = []

    def worker(olt_name, olt_ip):
        nonlocal results
        if cancel_user:
            with lock:
                results[olt_name] = (olt_ip, "")
            return
        res = ssh_execute_mac_search(olt_ip, olt_name, username, password, port, mac)
        with lock:
            results[olt_name] = (olt_ip, res)

    for olt_name, olt_ip in olt_dict.items():
        t = threading.Thread(target=worker, args=(olt_name, olt_ip))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    return results

# ---------------------------
# Funções de armazenamento e carregamento dos relatórios individualmente
# ---------------------------
def store_report(olt_name, report_result):
    now = datetime.now()
    # Normaliza o timestamp (zera minutos, segundos e microssegundos)
    normalized_time = now.replace(minute=0, second=0, microsecond=0)
    safe_timestamp = normalized_time.isoformat().replace(":", "-")
    safe_olt = sanitize_olt_name(olt_name)
    report_id = f"{safe_olt}_{safe_timestamp}"
    report = {
        "id": report_id,
        "olt": olt_name,
        "timestamp": now.isoformat(),
        "result": report_result
    }
    folder = os.path.join(REPORTS_FOLDER, safe_olt)
    os.makedirs(folder, exist_ok=True)
    file_path = os.path.join(folder, report_id + ".json")
    with report_lock:
        if os.path.exists(file_path):
            return
        with open(file_path, "w") as f:
            json.dump(report, f)
        # Mantém somente os últimos 60 relatórios para esta OLT
        files = [f for f in os.listdir(folder) if f.endswith(".json")]
        if len(files) > 90:
            reports = []
            for filename in files:
                fpath = os.path.join(folder, filename)
                try:
                    with open(fpath, "r") as f:
                        data = json.load(f)
                        ts = datetime.fromisoformat(data["timestamp"])
                        reports.append((fpath, ts))
                except Exception:
                    continue
            reports.sort(key=lambda x: x[1])
            excess = len(reports) - 90
            for i in range(excess):
                os.remove(reports[i][0])

def load_report_history(olt_name=None):
    reports = []
    base_folder = REPORTS_FOLDER
    if olt_name:
        safe_olt = sanitize_olt_name(olt_name)
        folder = os.path.join(base_folder, safe_olt)
        if os.path.exists(folder):
            for filename in os.listdir(folder):
                if filename.endswith(".json"):
                    fpath = os.path.join(folder, filename)
                    try:
                        with open(fpath, "r") as f:
                            data = json.load(f)
                            reports.append(data)
                    except Exception:
                        continue
    else:
        if os.path.exists(base_folder):
            for subfolder in os.listdir(base_folder):
                folder = os.path.join(base_folder, subfolder)
                if os.path.isdir(folder):
                    for filename in os.listdir(folder):
                        if filename.endswith(".json"):
                            fpath = os.path.join(folder, filename)
                            try:
                                with open(fpath, "r") as f:
                                    data = json.load(f)
                                    reports.append(data)
                            except Exception:
                                continue
    return reports

# ---------------------------
# Geração do relatório para uma OLT
# ---------------------------
def generate_report_for_olt(olt_obj, interface="1/1", check_cancel=True):
    olt_ip = olt_obj["endereco"]
    username = ssh_username
    password = ssh_password
    if interface.count("/") == 1:
        onus_cmd   = f"show interface gpon {interface} | display curly-braces"
        pppoe_cmd  = "show pppoe intermediate-agent sessions interface gpon | display curly-braces"
        vlans_cmd  = "show running-config interface gpon | display curly-braces"
        servp_cmd  = "show running-config service-port gpon"
    else:
        onus_cmd   = f"show interface gpon {interface} | display curly-braces"
        pppoe_cmd  = f"show pppoe intermediate-agent sessions interface gpon {interface} | display curly-braces"
        vlans_cmd  = f"show running-config interface gpon {interface} | display curly-braces | include \"onu|vlan-id\""
        servp_cmd  = f"show running-config service-port gpon {interface}"
    
    commands = {
        "onus": onus_cmd,
        "pppoe_sessions": pppoe_cmd,
        "vlans": vlans_cmd,
        "service_ports": servp_cmd
    }
    outputs, err = ssh_execute_commands(olt_ip, username, password, commands, check_cancel=check_cancel)
    if err:
        return f"Erro ao gerar relatório: {err}" if err.strip() else ""
    else:
        headers, table_data = process_ssh_outputs(outputs, interface)
        result_table = tabulate(table_data, headers=headers, tablefmt="html")
        result_table = result_table.replace('<table>', '<table class="sortable">')
        return result_table

# ---------------------------
# Automação dos relatórios (executa em todas as OLTs simultaneamente)
# ---------------------------
def automate_reports():
    print("Iniciando automação de relatórios")
    try:
        with open("00-lista-de-olts-jumpserver.json", "r") as f:
            olts = json.load(f)
    except Exception as e:
        print("Erro ao carregar OLTs:", e)
        return

    with ThreadPoolExecutor(max_workers=len(olts)) as executor:
        future_to_olt = {executor.submit(generate_report_for_olt, olt, "1/1", False): olt for olt in olts}
        for future in as_completed(future_to_olt):
            olt = future_to_olt[future]
            try:
                report_result = future.result()
                store_report(olt["nome"], report_result)
                print(f"Relatório gerado para OLT {olt['nome']} em {datetime.now().isoformat()}")
            except Exception as e:
                print(f"Erro ao gerar relatório para OLT {olt.get('nome', 'N/A')}: {e}")

# ---------------------------
# Rotas da aplicação
# ---------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/cancel_execution", methods=["POST"])
@login_required
def cancel_execution_route():
    global cancel_user
    cancel_user = True
    return "Cancelled", 200

@app.route("/mac_search_stream", methods=["POST"])
@login_required
def mac_search_stream():
    global cancel_user
    mac = request.form.get("mac_search")
    mac_option = request.form.get("mac_option")
    port = request.form.get("port", ssh_default_port)
    username = ssh_username
    password = ssh_password

    with open("00-lista-de-olts-jumpserver.json", "r") as f:
        olts = json.load(f)
    for olt in olts:
        if olt.get("caminho") and len(olt["caminho"]) > 0:
            olt["group"] = olt["caminho"][0].rsplit('/', 1)[-1]
        else:
            olt["group"] = ""
    if mac_option == "all":
        olt_dict = load_olt_data_zabbix()
    elif mac_option == "locality":
        selected_group = request.form.get("group")
        olt_dict = {olt["nome"]: olt["endereco"] for olt in olts if olt.get("group") == selected_group}
    elif mac_option == "single":
        selected_olt = request.form.get("olt")
        olt_obj = next((o for o in olts if o["nome"] == selected_olt), None)
        if olt_obj:
            olt_dict = {olt_obj["nome"]: olt_obj["endereco"]}
        else:
            olt_dict = {}
    else:
        olt_dict = {}

    if not olt_dict:
        def error_stream():
            yield "Nenhuma OLT encontrada para a pesquisa MAC.\n"
        return Response(error_stream(), mimetype='text/plain')

    def generate():
        global cancel_user
        for olt_name, olt_ip in olt_dict.items():
            if cancel_user:
                break
            yield f"Resultados da OLT: {olt_name} ({olt_ip})\n"
            yield "-" * 60 + "\n"
            command = f"show pppoe intermediate-agent sessions interface gpon | include {mac}"
            try:
                if cancel_user:
                    break
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(olt_ip, username=username, password=password, port=int(port), timeout=10)
                stdin, stdout, stderr = client.exec_command(command)
                for line in iter(lambda: stdout.readline(), ""):
                    if cancel_user:
                        break
                    yield line
                client.close()
            except Exception as e:
                yield f"Erro ao conectar à OLT: {e}\n"
            yield "-" * 60 + "\n\n"
        cancel_user = False

    return Response(generate(), mimetype='text/plain')

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    global cancel_user
    cancel_user = False

    with open("00-lista-de-olts-jumpserver.json", "r") as f:
        olts = json.load(f)
    for olt in olts:
        if olt.get("caminho") and len(olt["caminho"]) > 0:
            olt["group"] = olt["caminho"][0].rsplit('/', 1)[-1]
        else:
            olt["group"] = ""
    groups = sorted({olt["group"] for olt in olts})

    selected_group = request.form.get("group") or (groups[0] if groups else "")
    selected_olt = request.form.get("olt")
    result_table = None
    error_message = None
    exec_info = request.form.get("exec_info", "")

    if request.method == "POST":
        action = request.form.get("action", "report")
        if action == "report":
            exec_info = request.form.get("exec_info", "")
            olt_obj = next((o for o in olts if o["nome"] == selected_olt), None)
            if olt_obj:
                olt_ip = olt_obj["endereco"]
                username = ssh_username
                password = ssh_password
                interface = request.form.get("interface")
                if interface.count("/") == 1:
                    onus_cmd   = f"show interface gpon {interface} | display curly-braces"
                    pppoe_cmd  = "show pppoe intermediate-agent sessions interface gpon | display curly-braces"
                    vlans_cmd  = "show running-config interface gpon | display curly-braces"
                    servp_cmd  = "show running-config service-port gpon"
                else:
                    onus_cmd   = f"show interface gpon {interface} | display curly-braces"
                    pppoe_cmd  = f"show pppoe intermediate-agent sessions interface gpon {interface} | display curly-braces"
                    vlans_cmd  = f"show running-config interface gpon {interface} | display curly-braces | include \"onu|vlan-id\""
                    servp_cmd  = f"show running-config service-port gpon {interface}"
    
                commands = {
                    "onus": onus_cmd,
                    "pppoe_sessions": pppoe_cmd,
                    "vlans": vlans_cmd,
                    "service_ports": servp_cmd
                }
    
                outputs, err = ssh_execute_commands(olt_ip, username, password, commands)
                if err and err.strip():
                    error_message = err
                else:
                    headers, table_data = process_ssh_outputs(outputs, interface)
                    result_table = tabulate(table_data, headers=headers, tablefmt="html")
                    result_table = result_table.replace('<table>', '<table class="sortable">')
            else:
                error_message = "OLT não encontrada."
        # A ação "mac_search" é processada via o endpoint /mac_search_stream

    return render_template("index.html", olts=olts, groups=groups, result_table=result_table,
                           error_message=error_message, selected_olt=selected_olt, selected_group=selected_group,
                           exec_info=exec_info)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password_input = request.form.get("password")
        if password_input == login_password:
            session["logged_in"] = True
            session.permanent = True
            return redirect(url_for("index"))
        else:
            error = "Senha incorreta."
            return render_template("login.html", error=error)
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------
# Rotas para o Histórico de Relatórios
# ---------------------------
@app.route("/history", methods=["GET"])
@login_required
def history():
    olt_selected = request.args.get("olt")
    history_data = load_report_history(olt_selected)
    history_data.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify(history_data)

@app.route("/load_report/<report_id>", methods=["GET"])
@login_required
def load_report(report_id):
    # Considera que o report_id tem o formato "safe_olt_safeTimestamp"
    # Para extrair a pasta, usamos rsplit para pegar tudo antes do último "_"
    safe_olt = report_id.rsplit("_", 1)[0]
    file_path = os.path.join(REPORTS_FOLDER, safe_olt, report_id + ".json")
    if not os.path.exists(file_path):
        return "Relatório não encontrado.", 404
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        return data["result"]
    except Exception as e:
        return "Erro ao carregar relatório.", 500

# ---------------------------
# Configuração do Scheduler para Automação
# ---------------------------
scheduler = BackgroundScheduler()
# Agenda para executar às 05:00 e às 17:00 (hora local)
trigger = CronTrigger(hour='5,12,20', minute=30)
scheduler.add_job(automate_reports, trigger)
scheduler.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050, debug=True, threaded=True)