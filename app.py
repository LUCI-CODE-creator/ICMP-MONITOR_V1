from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import pythonping
import sqlite3
from datetime import datetime, timedelta
from threading import Thread, Lock
import time
import requests
import os
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # >>> IMPORTANT: CHANGE THIS TO A STRONG, RANDOM KEY IN PRODUCTION <<<

# Configuration
CONFIG_DIR = "config"
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram.cfg")
os.makedirs(CONFIG_DIR, exist_ok=True)


# Database setup with schema migration
def init_db():
    conn = sqlite3.connect('monitor.db', check_same_thread=False)
    c = conn.cursor()

    # Check if 'ips' table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ips'")
    if not c.fetchone():
        # Create new table with all columns
        c.execute('''CREATE TABLE ips
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    description TEXT,
                    active INTEGER DEFAULT 1,
                    last_status INTEGER,
                    last_checked TEXT,
                    response_time REAL)''')
        conn.commit()

    # Add new 'ping_history' table if it doesn't exist
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ping_history'")
    if not c.fetchone():
        c.execute('''CREATE TABLE ping_history
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_id INTEGER,
                    timestamp TEXT,
                    status INTEGER,
                    response_time REAL,
                    FOREIGN KEY(ip_id) REFERENCES ips(id) ON DELETE CASCADE)''')
        conn.commit()

    conn.close()


# Telegram configuration
def load_telegram_config():
    if os.path.exists(TELEGRAM_CONFIG_FILE):
        with open(TELEGRAM_CONFIG_FILE, 'r') as f:
            config = {}
            for line in f:
                parts = line.strip().split('=', 1)
                if len(parts) == 2:
                    config[parts[0]] = parts[1]
            return config
    return None


def save_telegram_config(bot_token, chat_id):
    with open(TELEGRAM_CONFIG_FILE, 'w') as f:
        f.write(f"bot_token={bot_token}\n")
        f.write(f"chat_id={chat_id}\n")


def test_telegram_connection(bot_token, chat_id):
    try:
        # Test bot token validity
        url = f"https://api.telegram.org/bot{bot_token}/getMe"
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return False, f"Invalid bot token or network issue to Telegram API. Status: {response.status_code}"

        # Try sending a test message
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': '🔌 ICMP Monitor Connection Test\n\nThis message confirms your Telegram notifications are working!'
        }
        response = requests.post(url, data=payload, timeout=5)
        return response.status_code == 200, "Test message sent successfully" if response.status_code == 200 else f"Failed to send test message: {response.json().get('description', 'Unknown error')}"
    except requests.exceptions.Timeout:
        return False, "Telegram API connection timed out."
    except requests.exceptions.RequestException as e:
        return False, f"Connection error to Telegram API: {str(e)}"
    except Exception as e:
        return False, f"An unexpected error occurred: {str(e)}"


# Telegram alerts
def send_telegram_alert(ip, description, status):
    config = load_telegram_config()
    if not config or not config.get('bot_token') or not config.get('chat_id'):
        print("Telegram not configured or incomplete!")
        return

    try:
        if status == "DOWN":
            message = f"🔴 Network Alert\n\nDear Team\n{description} ({ip}) is DOWN\nPlease check it."
        else:
            message = f"🟢 Network Update\n\nDear Team\n{description} ({ip}) is UP again."

        url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
        payload = {
            'chat_id': config['chat_id'],
            'text': message
        }
        response = requests.post(url, data=payload, timeout=10)

        if response.status_code == 200:
            print(f"Telegram alert sent for {ip}: {status}")
        else:
            print(f"Failed to send Telegram alert for {ip}. Status: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Telegram alert failed due to connection error for {ip}: {e}")
    except Exception as e:
        print(f"Telegram alert failed due to an unexpected error for {ip}: {e}")


# Monitoring system
notification_state = {}
state_lock = Lock()


def check_ip_status(ip, description, ip_id):
    global notification_state

    try:
        response = pythonping.ping(ip, count=2, timeout=1)
        status = 1 if response.success() else 0
        response_time = response.rtt_avg_ms if response.success() else None
        now = datetime.now().isoformat()

        with sqlite3.connect('monitor.db', check_same_thread=False) as conn:
            c = conn.cursor()
            c.execute("SELECT last_status FROM ips WHERE id=?", (ip_id,))
            prev_status_row = c.fetchone()
            prev_status = prev_status_row[0] if prev_status_row else None

            # Update database
            c.execute("UPDATE ips SET last_status=?, last_checked=?, response_time=? WHERE id=?",
                      (status, now, response_time, ip_id))

            # Insert into ping_history table
            c.execute("INSERT INTO ping_history (ip_id, timestamp, status, response_time) VALUES (?, ?, ?, ?)",
                      (ip_id, now, status, response_time))
            conn.commit()

            with state_lock:
                if ip not in notification_state:
                    notification_state[ip] = {'down_sent': False, 'up_sent': False}

                current_notification_state = notification_state[ip]

                if prev_status is not None:
                    if status == 0 and prev_status == 1:  # Went from UP to DOWN
                        def delayed_down_check():
                            time.sleep(30)
                            with sqlite3.connect('monitor.db', check_same_thread=False) as conn2:
                                c2 = conn2.cursor()
                                c2.execute("SELECT last_status FROM ips WHERE ip=?", (ip,))
                                current_status_row_after_delay = c2.fetchone()
                                current_status_after_delay = current_status_row_after_delay[
                                    0] if current_status_row_after_delay else None

                                with state_lock:
                                    if current_status_after_delay == 0 and not current_notification_state.get(
                                            'down_sent', False):
                                        send_telegram_alert(ip, description, "DOWN")
                                        notification_state[ip]['down_sent'] = True
                                        notification_state[ip]['up_sent'] = False
                                        print(f"Sent DOWN alert for {ip} after delay.")
                                    elif current_status_after_delay == 1:
                                        print(f"IP {ip} recovered before DOWN alert could be sent.")

                        Thread(target=delayed_down_check).start()

                    elif status == 1 and prev_status == 0:  # Went from DOWN to UP
                        if current_notification_state.get('down_sent', False) or not current_notification_state.get(
                                'up_sent', False):
                            send_telegram_alert(ip, description, "UP")
                            notification_state[ip]['up_sent'] = True
                            notification_state[ip]['down_sent'] = False
                            print(f"Sent UP alert for {ip}.")

    except Exception as e:
        print(f"Error monitoring {ip}: {e}")


def monitor_ips():
    while True:
        try:
            with sqlite3.connect('monitor.db', check_same_thread=False) as conn:
                c = conn.cursor()
                c.execute("SELECT id, ip, description FROM ips WHERE active=1")
                ips = c.fetchall()

                threads = []
                for ip_id, ip, description in ips:
                    t = Thread(target=check_ip_status, args=(ip, description, ip_id))
                    t.daemon = True
                    t.start()
                    threads.append(t)

                for t in threads:
                    t.join(timeout=1)

        except Exception as e:
            print(f"Monitoring error: {e}")

        time.sleep(5)


# Routes
@app.route('/')
def dashboard():
    if not os.path.exists(TELEGRAM_CONFIG_FILE):
        flash('Please configure Telegram notifications for alerts.', 'info')
    return render_template('dashboard.html')


@app.route('/telegram_setup', methods=['GET', 'POST'])
def telegram_setup():
    if request.method == 'POST':
        bot_token = request.form['bot_token'].strip()
        chat_id = request.form['chat_id'].strip()

        success, message = test_telegram_connection(bot_token, chat_id)
        if success:
            save_telegram_config(bot_token, chat_id)
            flash('Telegram configuration saved and verified!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(f'Telegram verification failed: {message}', 'danger')
            return render_template('telegram_setup.html', bot_token=bot_token, chat_id=chat_id)

    config = load_telegram_config()
    bot_token = config['bot_token'] if config else ''
    chat_id = config['chat_id'] if config else ''
    return render_template('telegram_setup.html', bot_token=bot_token, chat_id=chat_id)


@app.route('/telegram_settings', methods=['GET', 'POST'])
def telegram_settings():
    config = load_telegram_config()
    bot_token = config['bot_token'] if config and 'bot_token' in config else ''
    chat_id = config['chat_id'] if config and 'chat_id' in config else ''
    test_message_result = None

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'save_config':
            new_bot_token = request.form['bot_token'].strip()
            new_chat_id = request.form['chat_id'].strip()
            save_telegram_config(new_bot_token, new_chat_id)
            flash('Telegram configuration saved!', 'success')
            bot_token = new_bot_token
            chat_id = new_chat_id
        elif action == 'test_connection':
            test_bot_token = request.form['bot_token'].strip()
            test_chat_id = request.form['chat_id'].strip()
            success, message = test_telegram_connection(test_bot_token, test_chat_id)
            test_message_result = {"success": success, "message": message}
            if success:
                flash(f'Test connection successful: {message}', 'success')
            else:
                flash(f'Test connection failed: {message}', 'danger')
        elif action == 'send_custom_message':
            custom_message = request.form['custom_message'].strip()
            current_config = load_telegram_config()
            if current_config and 'bot_token' in current_config and 'chat_id' in current_config:
                try:
                    url = f"https://api.telegram.org/bot{current_config['bot_token']}/sendMessage"
                    payload = {
                        'chat_id': current_config['chat_id'],
                        'text': custom_message
                    }
                    response = requests.post(url, data=payload, timeout=10)
                    if response.status_code == 200:
                        flash('Custom message sent successfully!', 'success')
                    else:
                        flash(f'Failed to send custom message: {response.json().get("description", "Unknown error")}',
                              'danger')
                except requests.exceptions.RequestException as e:
                    flash(f'Error sending custom message (network issue): {str(e)}', 'danger')
                except Exception as e:
                    flash(f'Error sending custom message: {str(e)}', 'danger')
            else:
                flash('Telegram not configured. Please save credentials first.', 'danger')

    return render_template('telegram_settings.html', bot_token=bot_token, chat_id=chat_id,
                           test_result=test_message_result)


@app.route('/get_ips')
def get_ips():
    with sqlite3.connect('monitor.db', check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM ips ORDER BY active DESC, ip")
        ips = c.fetchall()

        ips_list = []
        for ip in ips:
            ips_list.append({
                'id': ip['id'],
                'ip': ip['ip'],
                'description': ip['description'],
                'active': bool(ip['active']),
                'last_status': bool(ip['last_status']) if ip['last_status'] is not None else None,
                'last_checked': ip['last_checked'],
                'response_time': ip['response_time']
            })
        return jsonify(ips_list)


@app.route('/add', methods=['GET', 'POST'])
def add_ip():
    if request.method == 'POST':
        ip = request.form['ip'].strip()
        description = request.form['description'].strip()

        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            flash('Invalid IP address format. Please use format like 192.168.1.1', 'danger')
            return render_template('add_ip.html')

        with sqlite3.connect('monitor.db', check_same_thread=False) as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO ips (ip, description) VALUES (?, ?)",
                          (ip, description))
                conn.commit()
                flash('IP added successfully!', 'success')
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError:
                flash(f'IP address {ip} already exists', 'danger')

    return render_template('add_ip.html')


@app.route('/add_multiple', methods=['GET', 'POST'])
def add_multiple_ips():
    if request.method == 'POST':
        ip_list_raw = request.form['ip_list']
        ip_entries = ip_list_raw.split('\n')
        added_ips = []
        errors = []

        with sqlite3.connect('monitor.db', check_same_thread=False) as conn:
            c = conn.cursor()
            for entry in ip_entries:
                entry = entry.strip()
                if not entry:
                    continue

                ip = ""
                description = ""

                if '|' in entry:
                    parts = entry.split('|', 1)
                    ip = parts[0].strip()
                    description = parts[1].strip() if len(parts) > 1 else f"Monitor {ip}"
                else:
                    ip = entry
                    description = f"Monitor {ip}"

                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    errors.append(f"Invalid IP format for '{entry}'")
                    continue

                try:
                    c.execute("INSERT INTO ips (ip, description) VALUES (?, ?)",
                              (ip, description))
                    added_ips.append(f"{ip} - {description}")
                except sqlite3.IntegrityError:
                    errors.append(f"IP {ip} already exists")

            conn.commit()

        if added_ips:
            flash(f'Successfully added {len(added_ips)} IPs', 'success')
        if errors:
            flash(f'{len(errors)} IPs not added: ' + ', '.join(errors), 'warning')

        return render_template('add_multiple.html',
                               ip_list=ip_list_raw,
                               added_ips=added_ips,
                               errors=errors)

    return render_template('add_multiple.html')


@app.route('/delete/<int:ip_id>')
def delete_ip(ip_id):
    with sqlite3.connect('monitor.db', check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM ips WHERE id=?", (ip_id,))
        conn.commit()
    flash('IP deleted successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/toggle/<int:ip_id>')
def toggle_ip(ip_id):
    with sqlite3.connect('monitor.db', check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("UPDATE ips SET active = NOT active WHERE id=?", (ip_id,))
        conn.commit()
    flash('Monitoring status changed.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/ip_detail/<int:ip_id>')
def ip_detail(ip_id):
    # தரவுத்தளத்துடன் இணைக்கவும்
    conn = sqlite3.connect('monitor.db', check_same_thread=False)
    # நிரல் பெயர்கள் மூலம் தரவை அணுக row_factory ஐ Row ஆக அமைக்கவும்
    conn.row_factory = sqlite3.Row

    c = conn.cursor()

    # குறிப்பிட்ட IP இன் விவரங்களை fetch செய்யவும்
    c.execute("SELECT * FROM ips WHERE id=?", (ip_id,))
    ip_data_row = c.fetchone()

    # sqlite3.Row ஆப்ஜெக்ட்டை ஒரு Python dictionary ஆக மாற்றவும்
    # இது Jinja2 இன் tojson filter க்கு JSON ஆக மாற்ற உதவும்
    ip_data = dict(ip_data_row) if ip_data_row else None

    # IP கண்டறியப்படவில்லை என்றால், ஒரு flash message காட்டி dashboard க்கு திருப்பி விடவும்
    if ip_data is None:
        flash("IP not found!", "danger")
        conn.close()
        return redirect(url_for('dashboard'))

    # கடந்த 24 மணிநேரத்திற்கான ping history ஐ fetch செய்யவும்
    # (தேவைப்பட்டால் கால அளவை சரிசெய்யவும்)
    one_day_ago = (datetime.now() - timedelta(days=1)).isoformat()
    c.execute(
        "SELECT timestamp, status, response_time FROM ping_history WHERE ip_id=? AND timestamp > ? ORDER BY timestamp ASC",
        (ip_id, one_day_ago))

    # sqlite3.Row ஆப்ஜெக்ட்களின் பட்டியலை dictionaries பட்டியலாக மாற்றவும்
    # இது Jinja2 இன் tojson filter க்கு JSON ஆக மாற்ற உதவும்
    history_data_rows = c.fetchall()
    history_data = [dict(row) for row in history_data_rows]

    # தரவுத்தள இணைப்பை மூடவும்
    conn.close()

    # ip_detail.html template ஐ ரெண்டர் செய்யவும், dictionary ஆக மாற்றப்பட்ட தரவுகளுடன்
    return render_template('ip_detail.html', ip=ip_data, history=history_data)


if __name__ == '__main__':
    init_db()

    monitor_thread = Thread(target=monitor_ips)
    monitor_thread.daemon = True
    monitor_thread.start()

    app.run(host='0.0.0.0', port=5000, debug=True)
