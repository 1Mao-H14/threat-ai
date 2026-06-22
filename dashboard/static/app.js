/* ZeroTrust AI — dashboard frontend logic */
"use strict";

const REFRESH_MS = 5000;
const COLORS = {
  critical:"#ff4d4f", high:"#ff9f43", medium:"#ffd23f", info:"#34d399",
  accent:"#3b82f6", accent2:"#60a5fa", muted:"#8190a8", grid:"#1f2940",
};
const SEV_ORDER = ["critical","high","medium","info"];
const charts = {};
let selectedUser = null;
let lastSnapshot = null;

const $ = s => document.querySelector(s);

/* ── data fetch (live API, fallback to embedded demo) ───────────────────── */
async function fetchSnapshot(){
  try{
    const r = await fetch("/api/snapshot",{cache:"no-store"});
    if(!r.ok) throw new Error("HTTP "+r.status);
    return await r.json();
  }catch(e){
    return window.DEMO_SNAPSHOT || null;
  }
}

async function postAction(user, action){
  // returns {ok, data}
  try{
    const r = await fetch(`/api/users/${encodeURIComponent(user)}/${action}`,{method:"POST"});
    const data = await r.json();
    return {ok:r.ok, data};
  }catch(e){
    return {ok:false, data:{error:String(e), offline:true}};
  }
}

/* ── render ─────────────────────────────────────────────────────────────── */
function render(s){
  lastSnapshot = s;
  // mode badge
  const live = !!s.live;
  const badge = $("#modeBadge");
  badge.textContent = live ? "LIVE" : "DEMO DATA";
  badge.className = "mode-badge " + (live ? "live" : "demo");
  $("#liveDot").style.background = live ? "var(--ok)" : "var(--med)";
  $("#updated").textContent = "updated " + new Date(s.generated_at).toLocaleTimeString();

  renderKpis(s.kpis);
  renderMachines(s.machines);
  renderUsers(s.users);
  renderUserSelect(s);
  renderSeverity(s.severity_distribution);
  renderOs(s.os_distribution);
  renderTopAttacks(s.top_techniques);
  renderTactics(s.tactic_distribution);
  renderBehavior(s);
  renderFeed(s.incidents);
}

function renderKpis(k){
  const cards = [
    {label:"Endpoints", value:k.endpoints, sub:`${k.online} online · ${k.offline} offline`, cls:"info"},
    {label:"Active Threats", value:k.active_threats, sub:"across all hosts", cls:k.active_threats?"warn":"ok"},
    {label:"Critical Incidents", value:k.critical_incidents, sub:"severity = critical", cls:k.critical_incidents?"crit":"ok"},
    {label:"Blocked Users", value:k.blocked_users, sub:"enforcement active", cls:k.blocked_users?"crit":"ok"},
    {label:"Avg Risk", value:k.avg_risk+"%", sub:`${k.total_users} monitored users`, cls:k.avg_risk>=60?"crit":k.avg_risk>=35?"warn":"ok"},
    {label:"Incidents (recent)", value:k.incidents_24h, sub:"in rolling log", cls:"info"},
  ];
  $("#kpiGrid").innerHTML = cards.map(c=>`
    <div class="kpi ${c.cls}">
      <div class="k-label">${c.label}</div>
      <div class="k-value">${c.value}</div>
      <div class="k-sub">${c.sub}</div>
    </div>`).join("");
}

function statusPill(status){
  const map={online:"st-online",offline:"st-offline",blocked:"st-blocked",active:"st-active",warmup:"st-warmup"};
  return `<span class="pill ${map[status]||"st-active"}"><span class="dot"></span>${status}</span>`;
}
function riskColor(v){return v>=85?COLORS.critical:v>=70?COLORS.high:v>=50?COLORS.medium:COLORS.info;}

function renderMachines(machines){
  $("#infraCount").textContent = `${machines.length} hosts`;
  $("#machineTable tbody").innerHTML = machines.map(m=>`
    <tr>
      <td><div class="host-cell">${m.name}</div><div class="ip-cell">${m.ip}</div></td>
      <td>${m.os}</td>
      <td class="mono" style="font-size:11px;color:var(--muted)">${m.os_version}</td>
      <td class="mono">${m.primary_user}</td>
      <td>${statusPill(m.status)}</td>
      <td>${m.active_threats>0?`<span class="sev-high mono">${m.active_threats}</span>`:`<span class="muted">0</span>`}</td>
      <td>
        <div style="display:flex;align-items:center">
          <div class="riskbar"><div class="fill" style="width:${m.risk}%;background:${riskColor(m.risk)}"></div></div>
          <span class="risk-num" style="color:${riskColor(m.risk)}">${m.risk}</span>
        </div>
      </td>
    </tr>`).join("");
}

function renderUsers(users){
  $("#userTable tbody").innerHTML = users.map(u=>{
    const dev = u.deviation_sigma;
    const devCls = dev>0.5?"up":dev<-0.5?"down":"flat";
    const devTxt = (dev>0?"+":"")+dev+"σ ("+(u.deviation_pct>0?"+":"")+u.deviation_pct+"pt)";
    const blocked = u.status==="blocked";
    const btn = blocked
      ? `<button class="btn unblock" data-user="${u.user}" data-act="unblock">Unblock</button>`
      : `<button class="btn block" data-user="${u.user}" data-act="block">Block</button>`;
    return `<tr>
      <td class="mono" style="font-weight:600">${u.user}</td>
      <td class="mono" style="font-size:11px;color:var(--muted)">${u.machine}</td>
      <td>
        <div style="display:flex;align-items:center">
          <div class="riskbar">
            <div class="fill" style="width:${u.score}%;background:${riskColor(u.score)}"></div>
            <div class="base" style="left:${u.baseline}%"></div>
          </div>
          <span class="risk-num" style="color:${riskColor(u.score)}">${u.score}</span>
        </div>
      </td>
      <td><span class="dev ${devCls}">${devTxt}</span></td>
      <td><span class="trend ${u.trend}">${u.trend==="rising"?"▲":u.trend==="falling"?"▼":"▬"} ${u.trend}</span></td>
      <td>${u.top_technique?`<span class="tech-tag">${u.top_technique}</span>`:'<span class="muted">—</span>'}</td>
      <td>${statusPill(u.status)}</td>
      <td>${btn}</td>
    </tr>`;
  }).join("");

  document.querySelectorAll("#userTable button[data-user]").forEach(b=>{
    b.addEventListener("click", ()=>handleAction(b.dataset.user, b.dataset.act, b));
  });
}

async function handleAction(user, act, btn){
  btn.disabled = true; btn.textContent = "…";
  const {ok, data} = await postAction(user, act);
  if(ok){
    const enf = data.enforcement || {};
    toast(`${user} ${act==="block"?"blocked":"unblocked"}${enf.success?" · Entra ID enforced":""}`, "ok");
  }else if(data.offline){
    // offline/demo preview: flip local state so the UI still responds
    const u = (lastSnapshot.users||[]).find(x=>x.user===user);
    if(u) u.status = act==="block" ? "blocked" : "active";
    toast(`${user} ${act==="block"?"blocked":"unblocked"} (preview)`, "ok");
  }else{
    toast(`Failed to ${act} ${user}`, "err");
  }
  if(lastSnapshot) renderUsers(lastSnapshot.users);
  refresh();
}

/* ── charts ──────────────────────────────────────────────────────────────── */
function donut(id, labels, data, colors){
  const ctx = document.getElementById(id);
  if(charts[id]) charts[id].destroy();
  charts[id] = new Chart(ctx,{
    type:"doughnut",
    data:{labels, datasets:[{data, backgroundColor:colors, borderColor:"#0e1320", borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:"62%",
      plugins:{legend:{position:"right",labels:{color:COLORS.muted,boxWidth:11,font:{size:11},padding:8}}}}
  });
}
function renderSeverity(d){
  const labels = SEV_ORDER.filter(k=>d[k]!==undefined);
  donut("severityChart", labels.map(l=>l[0].toUpperCase()+l.slice(1)),
    labels.map(l=>d[l]||0), labels.map(l=>COLORS[l]));
}
function renderOs(d){
  const labels = Object.keys(d);
  const palette = ["#3b82f6","#60a5fa","#a78bfa","#34d399","#ffd23f","#ff9f43","#ff4d4f","#8190a8"];
  donut("osChart", labels, labels.map(l=>d[l]), labels.map((_,i)=>palette[i%palette.length]));
}
function renderTactics(d){
  const labels = Object.keys(d);
  if(!labels.length){clearChart("tacticChart");return;}
  const ctx = document.getElementById("tacticChart");
  if(charts.tacticChart) charts.tacticChart.destroy();
  charts.tacticChart = new Chart(ctx,{
    type:"polarArea",
    data:{labels, datasets:[{data:labels.map(l=>d[l]),
      backgroundColor:labels.map((_,i)=>["#3b82f6","#a78bfa","#34d399","#ffd23f","#ff9f43","#ff4d4f","#60a5fa","#f472b6"][i%8]+"cc")}]},
    options:{responsive:true,maintainAspectRatio:false,
      scales:{r:{grid:{color:COLORS.grid},ticks:{display:false},pointLabels:{display:false}}},
      plugins:{legend:{position:"right",labels:{color:COLORS.muted,boxWidth:11,font:{size:10},padding:6}}}}
  });
}
function renderTopAttacks(techs){
  const ctx = document.getElementById("topAttackChart");
  if(charts.topAttackChart) charts.topAttackChart.destroy();
  charts.topAttackChart = new Chart(ctx,{
    type:"bar",
    data:{labels:techs.map(t=>`${t.id} ${t.name}`),
      datasets:[{data:techs.map(t=>t.count),
        backgroundColor:techs.map(t=>t.severity>=90?COLORS.critical:t.severity>=80?COLORS.high:COLORS.medium),
        borderRadius:4,barThickness:15}]},
    options:{indexAxis:"y",responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>` ${c.raw} detections`}}},
      scales:{x:{grid:{color:COLORS.grid},ticks:{color:COLORS.muted,font:{size:10},precision:0}},
              y:{grid:{display:false},ticks:{color:COLORS.muted,font:{size:10.5,family:"monospace"}}}}}
  });
}
function renderBehavior(s){
  const u = selectedUser && s.behavior[selectedUser] ? selectedUser : Object.keys(s.behavior)[0];
  selectedUser = u;
  const b = s.behavior[u] || {labels:[],scores:[],baseline:[]};
  const ctx = document.getElementById("behaviorChart");
  if(charts.behaviorChart) charts.behaviorChart.destroy();
  charts.behaviorChart = new Chart(ctx,{
    type:"line",
    data:{labels:b.labels,datasets:[
      {label:"Risk score",data:b.scores,borderColor:COLORS.accent,
        backgroundColor:"rgba(59,130,246,.15)",fill:true,tension:.35,pointRadius:0,borderWidth:2},
      {label:"Baseline (normal)",data:b.baseline,borderColor:COLORS.muted,borderDash:[5,4],
        fill:false,pointRadius:0,borderWidth:1.4}
    ]},
    options:{responsive:true,maintainAspectRatio:false,interaction:{mode:"index",intersect:false},
      plugins:{legend:{labels:{color:COLORS.muted,boxWidth:12,font:{size:11}}}},
      scales:{y:{min:0,max:100,grid:{color:COLORS.grid},ticks:{color:COLORS.muted,font:{size:10},callback:v=>v+"%"}},
              x:{grid:{display:false},ticks:{color:COLORS.muted,font:{size:9},maxTicksLimit:12}}}}
  });
}
function renderUserSelect(s){
  const sel = $("#userSelect");
  const users = Object.keys(s.behavior);
  if(!selectedUser) selectedUser = users[0];
  sel.innerHTML = users.map(u=>`<option value="${u}" ${u===selectedUser?"selected":""}>${u}</option>`).join("");
  sel.onchange = ()=>{ selectedUser = sel.value; renderBehavior(lastSnapshot); };
}
function clearChart(id){ if(charts[id]){charts[id].destroy();delete charts[id];} }

/* ── feed ───────────────────────────────────────────────────────────────── */
function timeAgo(ts){
  const d=(Date.now()-new Date(ts).getTime())/1000;
  if(d<60)return Math.floor(d)+"s ago";
  if(d<3600)return Math.floor(d/60)+"m ago";
  if(d<86400)return Math.floor(d/3600)+"h ago";
  return Math.floor(d/86400)+"d ago";
}
function renderFeed(incidents){
  $("#feedCount").textContent = `${incidents.length} events`;
  const ico={critical:"🛑",high:"⚠️",medium:"🔶",info:"ℹ️"};
  $("#feed").innerHTML = incidents.map(i=>`
    <div class="feed-item ${i.severity}">
      <div class="feed-ico">${ico[i.severity]||"•"}</div>
      <div class="feed-body">
        <div class="feed-top">
          <span class="feed-title sev-${i.severity}">${i.technique_id} · ${i.technique_name}</span>
          <span class="feed-time">${timeAgo(i.ts)}</span>
        </div>
        <div class="feed-meta">
          <span class="mono">${i.user}</span> @ <span class="mono">${i.machine}</span>
          · ${i.tactic} · score ${(i.score*100).toFixed(0)}%
          <span class="act act-${i.action}">${(i.action||"none").toUpperCase()}${i.action_success===false?" ✕":""}</span>
        </div>
      </div>
    </div>`).join("");
}

/* ── toast ───────────────────────────────────────────────────────────────── */
let toastTimer;
function toast(msg, kind){
  const t=$("#toast"); t.textContent=msg; t.className="toast show "+(kind||"");
  clearTimeout(toastTimer); toastTimer=setTimeout(()=>t.className="toast "+(kind||""),2600);
}

/* ── loop ────────────────────────────────────────────────────────────────── */
async function refresh(){
  const s = await fetchSnapshot();
  if(s) render(s);
}
$("#refreshBtn").addEventListener("click", refresh);
refresh();
setInterval(refresh, REFRESH_MS);
