import os
from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime, timedelta

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, template_folder=os.path.join(basedir, 'templates'))

def get_db_connection():
    conn = sqlite3.connect('signals.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stats')
def get_stats():
    conn = get_db_connection()
    cur = conn.cursor()

    # Get total counts
    cur.execute("SELECT COUNT(DISTINCT bssid) FROM wifi_signals")
    total_wifi = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT address) FROM bluetooth_signals")
    total_bluetooth = cur.fetchone()[0]

    # Get counts for last 24 hours
    last_24h = datetime.now() - timedelta(hours=24)
    cur.execute("SELECT COUNT(DISTINCT bssid) FROM wifi_signals WHERE timestamp > ?", (last_24h,))
    wifi_24h = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT address) FROM bluetooth_signals WHERE timestamp > ?", (last_24h,))
    bluetooth_24h = cur.fetchone()[0]

    # Get top 5 Wi-Fi SSIDs
    cur.execute("""
        SELECT ssid, COUNT(*) as count
        FROM wifi_signals
        GROUP BY ssid
        ORDER BY count DESC
        LIMIT 5
    """)
    top_ssids = [dict(row) for row in cur.fetchall()]

    # Get top 5 Bluetooth device names
    cur.execute("""
        SELECT name, COUNT(*) as count
        FROM bluetooth_signals
        GROUP BY name
        ORDER BY count DESC
        LIMIT 5
    """)
    top_bt_names = [dict(row) for row in cur.fetchall()]

    conn.close()

    return jsonify({
        'total_wifi': total_wifi,
        'total_bluetooth': total_bluetooth,
        'wifi_24h': wifi_24h,
        'bluetooth_24h': bluetooth_24h,
        'top_ssids': top_ssids,
        'top_bt_names': top_bt_names
    })

@app.route('/probes')
def get_probes():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT ssid, bssid, signal_strength, timestamp
        FROM wifi_signals
        WHERE type = 'probe' OR ssid != ''
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    probes = [dict(row) for row in cur.fetchall()]

    conn.close()

    return jsonify(probes)

@app.route('/suspicious')
def get_suspicious():
    conn = get_db_connection()
    cur = conn.cursor()

    # Devices that have been seen many times in a short period
    cur.execute("""
        SELECT bssid, COUNT(*) as count
        FROM wifi_signals
        WHERE timestamp > datetime('now', '-1 hour')
        GROUP BY bssid
        HAVING count > 50
        ORDER BY count DESC
        LIMIT 10
    """)
    suspicious_wifi = [dict(row) for row in cur.fetchall()]

    # Bluetooth devices with very strong signal (potentially very close)
    cur.execute("""
        SELECT address, name, rssi, timestamp
        FROM bluetooth_signals
        WHERE rssi > -50
        ORDER BY timestamp DESC
        LIMIT 10
    """)
    suspicious_bt = [dict(row) for row in cur.fetchall()]

    conn.close()

    return jsonify({
        'suspicious_wifi': suspicious_wifi,
        'suspicious_bt': suspicious_bt
    })

@app.route('/device_details')
def get_device_details():
    device_id = request.args.get('id')
    device_type = request.args.get('type')

    conn = get_db_connection()
    cur = conn.cursor()

    if device_type == 'wifi':
        cur.execute("""
            SELECT * FROM wifi_signals
            WHERE ssid = ? OR bssid = ?
            ORDER BY timestamp DESC
            LIMIT 50
        """, (device_id, device_id))
    else:
        cur.execute("""
            SELECT * FROM bluetooth_signals
            WHERE name = ? OR address = ?
            ORDER BY timestamp DESC
            LIMIT 50
        """, (device_id, device_id))

    details = [dict(row) for row in cur.fetchall()]
    conn.close()

    return jsonify(details)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
