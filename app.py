import json
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>DNS Cache Monitor</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Segoe UI', sans-serif;
      background: #f0f0f0;
      color: #333;
    }

    header {
      background: #fff;
      border-bottom: 1px solid #ddd;
      padding: 18px 40px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    header h1 { font-size: 17px; font-weight: 600; color: #222; }
    header p  { font-size: 12px; color: #999; margin-top: 3px; }

    .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: #4caf50; display: inline-block;
      margin-right: 6px; animation: pulse 1.5s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.4; }
    }

    .cards {
      display: flex;
      gap: 16px;
      padding: 28px 40px 0;
    }

    .card {
      background: #fff;
      border: 1px solid #e0e0e0;
      border-radius: 10px;
      padding: 20px 24px;
      flex: 1;
    }

    .card .num   { font-size: 30px; font-weight: 600; color: #222; }
    .card .label { font-size: 12px; color: #999; margin-top: 4px; }
    .card.green .num { color: #2e7d32; }
    .card.red   .num { color: #c62828; }
    .card.blue  .num { color: #1565c0; }

    .section-title {
      font-size: 13px;
      font-weight: 600;
      color: #888;
      padding: 28px 40px 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    table {
      width: calc(100% - 80px);
      margin: 0 40px 40px;
      background: #fff;
      border: 1px solid #e0e0e0;
      border-radius: 10px;
      border-collapse: separate;
      border-spacing: 0;
      overflow: hidden;
    }

    th {
      background: #fafafa;
      font-size: 11px;
      font-weight: 600;
      color: #777;
      text-align: left;
      padding: 11px 18px;
      border-bottom: 1px solid #eee;
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }

    td {
      font-size: 13px;
      padding: 11px 18px;
      border-bottom: 1px solid #f2f2f2;
      color: #444;
    }

    tr:last-child td { border-bottom: none; }

    .ttl-bar-wrap {
      background: #f0f0f0;
      border-radius: 4px;
      height: 6px;
      width: 120px;
      overflow: hidden;
      display: inline-block;
      vertical-align: middle;
      margin-right: 8px;
    }

    .ttl-bar {
      height: 100%;
      border-radius: 4px;
      background: #90a4ae;
      transition: width 0.3s;
    }

    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 20px;
      font-size: 11px;
      background: #e8f5e9;
      color: #2e7d32;
      font-weight: 500;
    }

    .empty {
      text-align: center;
      color: #bbb;
      padding: 30px;
      font-size: 13px;
    }
  </style>
</head>
<body>

  <header>
    <div>
      <h1>DNS Cache Monitor</h1>
      <p>Tracking your local DNS server at 127.0.0.1:9053</p>
    </div>
    <div style="font-size:13px; color:#888;">
      <span class="dot"></span> Live — refreshes every 3s
    </div>
  </header>

  <div class="cards" id="stats">
    <div class="card"><div class="num">—</div><div class="label">Cache Hits</div></div>
    <div class="card"><div class="num">—</div><div class="label">Cache Misses</div></div>
    <div class="card"><div class="num">—</div><div class="label">Hit Rate</div></div>
    <div class="card"><div class="num">—</div><div class="label">Stored Entries</div></div>
  </div>

  <div class="section-title">Cached Entries</div>

  <table>
    <thead>
      <tr>
        <th>Domain</th>
        <th>TTL Remaining</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody id="entries">
      <tr><td colspan="3" class="empty">Waiting for DNS queries...</td></tr>
    </tbody>
  </table>

  <script>
    async function refresh() {
      try {
        const r = await fetch('/api/stats');
        const d = await r.json();

        document.getElementById('stats').innerHTML = `
          <div class="card green">
            <div class="num">${d.hits}</div>
            <div class="label">Cache Hits</div>
          </div>
          <div class="card red">
            <div class="num">${d.misses}</div>
            <div class="label">Cache Misses</div>
          </div>
          <div class="card blue">
            <div class="num">${d.hit_rate}</div>
            <div class="label">Hit Rate</div>
          </div>
          <div class="card">
            <div class="num">${d.entries}</div>
            <div class="label">Stored Entries</div>
          </div>
        `;

        const tbody = document.getElementById('entries');

        if (!d.cache_list || d.cache_list.length === 0) {
          tbody.innerHTML = '<tr><td colspan="3" class="empty">No entries yet — run client.py to generate queries</td></tr>';
        } else {
          tbody.innerHTML = d.cache_list.map(e => {
            const pct = Math.min(100, Math.round((e.ttl_left / 300) * 100));
            return `
              <tr>
                <td style="font-family: monospace; font-size:13px;">${e.domain}</td>
                <td>
                  <span class="ttl-bar-wrap">
                    <span class="ttl-bar" style="width:${pct}%"></span>
                  </span>
                  ${e.ttl_left}s
                </td>
                <td><span class="badge">cached</span></td>
              </tr>
            `;
          }).join('');
        }

      } catch(err) {
        console.log("Waiting for server...", err);
      }
    }

    refresh();
    setInterval(refresh, 3000);
  </script>

</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/api/stats')
def stats():
    try:
        with open("cache_state.json") as f:
            data = json.load(f)
        total = data["hits"] + data["misses"]
        rate = round((data["hits"] / total) * 100, 1) if total > 0 else 0
        return jsonify({
            "hits":       data["hits"],
            "misses":     data["misses"],
            "hit_rate":   f"{rate}%",
            "entries":    len(data["entries"]),
            "cache_list": data["entries"]
        })
    except:
        return jsonify({
            "hits": 0, "misses": 0,
            "hit_rate": "0%", "entries": 0,
            "cache_list": []
        })


if __name__ == '__main__':
    app.run(port=8080, debug=False)