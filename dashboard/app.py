"""Q-SHIELD live dashboard (Flask).

    python dashboard/app.py          ->  http://127.0.0.1:5000

Runs the gateway + three domain devices in-process. Use the controls to change
the key-establishment mode, channel noise, eavesdropper strength and quantum link
state, then step the simulation and watch QBER, key method and attack alerts.
"""

from __future__ import annotations

import os
import sys
import threading

import numpy as np
from flask import Flask, jsonify, render_template_string, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qshield.bb84 import QBER_THRESHOLD  # noqa: E402
from qshield.devices import DOMAINS, Device  # noqa: E402
from qshield.gateway import Gateway  # noqa: E402
from qshield.keymanager import KeyManager, QuantumChannel  # noqa: E402
from qshield.transport import InProcessBroker  # noqa: E402

app = Flask(__name__)
LOCK = threading.Lock()


class Sim:
    def __init__(self, mode: str = "hybrid", seed: int = 7):
        self.rng = np.random.default_rng(seed)
        self.broker = InProcessBroker()
        self.gw = Gateway(self.broker, KeyManager(rng=self.rng), mode=mode)
        self.channel = QuantumChannel(error=0.01, loss=0.10)
        self.devices = {d: Device(f"{d}-01", d, self.gw, self.channel, rng=self.rng) for d in DOMAINS}
        self.round = 0
        self.qber_history: list[dict] = []
        self._seen_events = 0

    def step(self, n: int = 1) -> None:
        for _ in range(n):
            self.round += 1
            for dev in self.devices.values():
                dev.send_reading()
            for ev in self.gw.events[self._seen_events:]:
                if ev["kind"] in ("key_established", "key_failed"):
                    self.qber_history.append({"round": self.round, "device": ev["device"], "method": ev["method"],
                                              "qber": ev["qber"], "reason": ev["reason"]})
            self._seen_events = len(self.gw.events)
        self.qber_history = self.qber_history[-120:]

    def attack_replay(self) -> int:
        """Replay the last 5 captured frames; returns how many the gateway accepted."""
        before = self.gw.counters["accepted"]
        for topic, wire in self.broker.sniffed[-5:]:
            self.broker.inject(topic, wire)
        return self.gw.counters["accepted"] - before

    def state(self) -> dict:
        g = self.gw
        return {
            "round": self.round, "mode": g.mode, "threshold": QBER_THRESHOLD,
            "channel": vars(self.channel), "counters": g.counters,
            "sessions": {d: {"method": s.method, "msgs": s.msgs, "key_id": s.key_id} for d, s in g.sessions.items()},
            "qber_history": self.qber_history,
            "events": [{k: v for k, v in e.items()} for e in g.events[-40:]][::-1],
            "latest_reading": g.accepted[-1] if g.accepted else None,
        }


SIM = Sim()


@app.get("/api/state")
def api_state():
    with LOCK:
        return jsonify(SIM.state())


@app.post("/api/config")
def api_config():
    body = request.get_json(force=True)
    with LOCK:
        ch = SIM.channel
        if "error" in body:
            ch.error = float(np.clip(body["error"], 0, 0.5))
        if "eve_fraction" in body:
            ch.eve_fraction = float(np.clip(body["eve_fraction"], 0, 1))
        if "link_up" in body:
            ch.link_up = bool(body["link_up"])
        if "mode" in body and body["mode"] in ("classical", "qkd", "hybrid"):
            SIM.gw.mode = body["mode"]
            SIM.gw.sessions.clear()  # force re-establishment under the new mode
        return jsonify(SIM.state())


@app.post("/api/step")
def api_step():
    n = int(request.get_json(force=True).get("n", 1))
    with LOCK:
        SIM.step(max(1, min(n, 200)))
        return jsonify(SIM.state())


@app.post("/api/replay")
def api_replay():
    with LOCK:
        accepted = SIM.attack_replay()
        s = SIM.state()
        s["replay_accepted"] = accepted
        return jsonify(s)


@app.post("/api/reset")
def api_reset():
    global SIM
    with LOCK:
        SIM = Sim(mode=SIM.gw.mode)
        return jsonify(SIM.state())


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Q-SHIELD dashboard</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#16202a;--mut:#5d6b78;--line:#e2e6ea;--ok:#1b8a4b;--warn:#c27c0e;--bad:#c62f2f;--acc:#2a5db0}
@media (prefers-color-scheme:dark){:root{--bg:#12171c;--card:#1b222a;--ink:#e8edf2;--mut:#93a1ae;--line:#2c3640;--ok:#4cc17f;--warn:#e0a13a;--bad:#ef6b6b;--acc:#6d9bef}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,Segoe UI,sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}
h1{font-size:18px;margin:0}header span{color:var(--mut)}
main{padding:20px 24px;display:grid;gap:16px;grid-template-columns:repeat(12,1fr);max-width:1300px;margin:auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.c3{grid-column:span 3}.c4{grid-column:span 4}.c5{grid-column:span 5}.c7{grid-column:span 7}.c8{grid-column:span 8}.c12{grid-column:span 12}
@media(max-width:900px){.c3,.c4,.c5,.c7,.c8{grid-column:span 12}}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:0 0 10px}
.big{font-size:26px;font-weight:650}.mut{color:var(--mut)}
label{display:block;margin:8px 0 2px;font-size:13px}input[type=range]{width:100%}
select,button{font:inherit;padding:6px 10px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
button.primary{background:var(--acc);color:#fff;border-color:var(--acc)}button.danger{border-color:var(--bad);color:var(--bad)}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:5px 6px;border-bottom:1px solid var(--line)}
.pill{padding:1px 8px;border-radius:99px;font-size:12px;border:1px solid currentColor}
.QKD{color:var(--ok)}.ML-KEM{color:var(--warn)}.X25519{color:var(--acc)}.none{color:var(--bad)}
.alert{color:var(--bad)}.warning{color:var(--warn)}
#log{max-height:260px;overflow:auto}
svg text{fill:var(--mut);font-size:11px}
</style></head><body>
<header><h1>Q-SHIELD</h1><span>Adaptive hybrid QKD-PQC gateway &middot; simulation</span></header>
<main>
 <div class="card c4"><h2>Controls</h2>
  <label>Key mode</label>
  <select id="mode"><option value="hybrid">Hybrid (QKD, ML-KEM fallback)</option><option value="qkd">QKD only</option><option value="classical">Classical (X25519)</option></select>
  <label>Channel error: <b id="errv">1</b>%</label><input id="err" type="range" min="0" max="20" step="1" value="1">
  <label>Eavesdropper intercepts: <b id="evev">0</b>% of qubits</label><input id="eve" type="range" min="0" max="100" step="10" value="0">
  <label><input id="link" type="checkbox" checked> Quantum link up</label>
  <div class="row"><button class="primary" onclick="step(1)">Step 1 round</button><button onclick="step(25)">Step 25</button>
  <button id="auto" onclick="toggleAuto()">Auto-run</button><button class="danger" onclick="replay()">Replay attack</button><button onclick="reset()">Reset</button></div>
  <p class="mut" id="note"></p>
 </div>
 <div class="card c3"><h2>Current key method</h2><div id="sessions"></div></div>
 <div class="card c5"><h2>Gateway counters</h2><table id="counters"></table></div>
 <div class="card c8"><h2>QBER at each key establishment (threshold line = abort)</h2><svg id="chart" viewBox="0 0 720 220" width="100%"></svg></div>
 <div class="card c4"><h2>Latest authenticated reading</h2><pre id="reading" class="mut" style="white-space:pre-wrap;margin:0"></pre></div>
 <div class="card c12"><h2>Event log</h2><div id="log"><table id="events"></table></div></div>
</main>
<script>
let auto=null;
const $=id=>document.getElementById(id);
async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});return r.json()}
async function cfg(b){render(await post('/api/config',b))}
$('mode').onchange=e=>cfg({mode:e.target.value});
$('err').oninput=e=>{$('errv').textContent=e.target.value;cfg({error:e.target.value/100})};
$('eve').oninput=e=>{$('evev').textContent=e.target.value;cfg({eve_fraction:e.target.value/100})};
$('link').onchange=e=>cfg({link_up:e.target.checked});
async function step(n){render(await post('/api/step',{n}))}
async function reset(){render(await post('/api/reset'))}
async function replay(){const s=await post('/api/replay');render(s);$('note').textContent='Replayed 5 captured frames: '+s.replay_accepted+' accepted by the gateway.'}
function toggleAuto(){if(auto){clearInterval(auto);auto=null;$('auto').textContent='Auto-run'}else{auto=setInterval(()=>step(1),700);$('auto').textContent='Stop'}}
function chart(h,th){
 const W=720,H=220,L=40,B=24,T=10,maxY=0.35,n=Math.max(h.length,1),sx=i=>L+(W-L-10)*(h.length>1?i/(h.length-1):0.5),sy=v=>T+(H-T-B)*(1-Math.min(v,maxY)/maxY);
 const col={QKD:'var(--ok)','ML-KEM':'var(--warn)',X25519:'var(--acc)',none:'var(--bad)'};
 let s='';for(let v=0;v<=0.35;v+=0.05)s+=`<line x1="${L}" x2="${W-10}" y1="${sy(v)}" y2="${sy(v)}" stroke="var(--line)"/><text x="4" y="${sy(v)+4}">${Math.round(v*100)}%</text>`;
 s+=`<line x1="${L}" x2="${W-10}" y1="${sy(th)}" y2="${sy(th)}" stroke="var(--bad)" stroke-dasharray="4 3"/>`;
 h.forEach((p,i)=>{if(p.qber===null){s+=`<circle cx="${sx(i)}" cy="${H-B+2}" r="4" fill="${col[p.method]||'gray'}"><title>${p.device}: ${p.method} (no QKD attempt: ${p.reason})</title></circle>`}
  else s+=`<circle cx="${sx(i)}" cy="${sy(p.qber)}" r="4" fill="${col[p.method]||'gray'}"><title>${p.device}: ${p.method}, QBER ${(p.qber*100).toFixed(1)}%</title></circle>`});
 if(!h.length)s+=`<text x="${L+10}" y="${H/2}">Step the simulation to see key establishments</text>`;
 $('chart').innerHTML=s}
function render(s){
 $('sessions').innerHTML=Object.keys(s.sessions).length?Object.entries(s.sessions).map(([d,x])=>`<div style="margin-bottom:8px"><span class="mut">${d}</span><div class="big ${x.method}">${x.method}</div><span class="mut">${x.msgs} msgs on key #${x.key_id}</span></div>`).join(''):'<span class="mut">No active session (QKD-only mode cannot establish a key)</span>';
 const c=s.counters;$('counters').innerHTML=Object.entries(c).map(([k,v])=>`<tr><td>${k.replace(/_/g,' ')}</td><td><b>${v}</b></td></tr>`).join('');
 chart(s.qber_history,s.threshold);
 $('reading').textContent=s.latest_reading?JSON.stringify(s.latest_reading,null,1):'-';
 $('events').innerHTML='<tr><th>kind</th><th>device</th><th>detail</th></tr>'+s.events.map(e=>{
  const d=e.kind==='key_established'?`${e.method}${e.qber!=null?' &middot; QBER '+(e.qber*100).toFixed(1)+'%':''}${e.reason?' &middot; fallback: '+e.reason:''} &middot; ${e.wire_bytes} B, ${e.latency_ms} ms`:e.kind==='key_failed'?`no key: ${e.reason}`:e.message||e.reason||'';
  return `<tr><td class="${e.kind==='alert'?'alert':e.kind==='warning'?'warning':''}">${e.kind}</td><td>${e.device||''}</td><td>${d}</td></tr>`}).join('');
 $('mode').value=s.mode}
fetch('/api/state').then(r=>r.json()).then(render);
</script></body></html>"""


@app.get("/")
def index():
    return render_template_string(PAGE)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
