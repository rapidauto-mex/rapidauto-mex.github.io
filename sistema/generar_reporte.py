"""Genera el resumen financiero de Rapidauto como un HTML cifrado con contraseña.

Uso:  python3 generar_reporte.py datos.json salida.html CONTRASEÑA

datos.json:
{
  "empresa": "Rapidauto",
  "actualizado": "2026-11-04",
  "modo": "semanal" | "diario",
  "puntos": [
    {"fecha": "2026-11-02",                       # semanal: el lunes; diario: la fecha de corte (cierre) del reporte
     "deuda": {"Covalto": 182000000, ...},
     "caja": 23181772.88, "fecha_caja": "2026-11-02",   # caja puede omitirse si no hay dato a esa fecha
     "cartera": 414487494.84, "corte_cartera": "2026-11-01",
     "colocacion": {"monto": 10077014.2, "creditos": 55, "desde": "2026-10-26", "hasta": "2026-11-01"} | null,
     "en_curso": {"monto": 2045335.43, "creditos": 13, "desde": "2026-11-02", "hasta": "2026-11-03"} | null   # opcional, solo diario
    }, ...
  ]
}
(Por compatibilidad también acepta "semanas" con "lunes" en lugar de "puntos"/"fecha".)

El navegador muestra un selector de fecha: en modo "semanal" solo se puede ver un lunes;
en modo "diario", cualquier día con datos. El contenido se comprime y se cifra con
AES-256-GCM (llave PBKDF2-SHA256, 310,000 iteraciones). Sin la contraseña no se ve
ninguna cifra, aunque alguien lea el código fuente.
"""
import base64, gzip, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 310_000

PAGINA = r'''<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>__TITULO__</title>
<link rel="icon" type="image/png" href="assets/favicon.png">
<link rel="preload" href="assets/fonts/google-sans-500.woff2" as="font" type="font/woff2" crossorigin>
<style>
@font-face{font-family:"Google Sans";src:url(assets/fonts/google-sans-400.woff2) format("woff2");font-weight:400;font-display:swap}
@font-face{font-family:"Google Sans";src:url(assets/fonts/google-sans-500.woff2) format("woff2");font-weight:500;font-display:swap}
@font-face{font-family:"Google Sans";src:url(assets/fonts/google-sans-700.woff2) format("woff2");font-weight:600 700;font-display:swap}
:root{--bg:#F6F5FB;--card:#fff;--ink:#1d1934;--muted:#6b6880;--line:#E4E2EA;--acc:#623DE9;--acc2:#A08AF3;--lav:#EAE7F9;--sky:#7DC7F2;--skyt:#2B7BB9;--menta:#B1FF96;--mentat:#3d8a24;--gris:#D0CDCE;--gris2:#D9D8DB;--neg:#c0392b;--hd:#623DE9;--hdt:#fff;--sombra:0 1px 2px rgba(29,25,52,.04),0 4px 16px rgba(98,61,233,.06)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#13111d;--card:#1c1a29;--ink:#eceaf5;--muted:#a19db3;--line:#2f2b42;--acc:#A08AF3;--acc2:#7d66e0;--lav:#2a2448;--sky:#7DC7F2;--skyt:#7DC7F2;--menta:#B1FF96;--mentat:#B1FF96;--gris:#36333f;--gris2:#2c2a35;--neg:#ef8a7c;--hd:#4b2ec4;--hdt:#fff;--sombra:none}}
:root[data-theme="dark"]{--bg:#13111d;--card:#1c1a29;--ink:#eceaf5;--muted:#a19db3;--line:#2f2b42;--acc:#A08AF3;--acc2:#7d66e0;--lav:#2a2448;--sky:#7DC7F2;--skyt:#7DC7F2;--menta:#B1FF96;--mentat:#B1FF96;--gris:#36333f;--gris2:#2c2a35;--neg:#ef8a7c;--hd:#4b2ec4;--hdt:#fff;--sombra:none}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Google Sans",-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:1000px;margin:0 auto;padding:28px 18px 48px}
.logo{display:block;height:44px;width:auto}
.barra{height:4px;border-radius:4px;margin:18px 0 22px;background:linear-gradient(90deg,var(--acc) 0 55%,var(--acc2) 55% 75%,var(--sky) 75% 90%,var(--menta) 90%)}
h1{font-size:30px;margin:0 0 2px;letter-spacing:-.015em;color:var(--acc);font-weight:700;line-height:1.15}
h2{display:flex;align-items:center;gap:10px;font-size:16px;margin:36px 0 12px;color:var(--acc);font-weight:600}
h2::before{content:"";width:4px;height:18px;border-radius:2px;background:var(--acc2)}
.meta{color:var(--muted);margin:2px 0 0;font-weight:500}
.top{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;justify-content:space-between}
.ctl{display:flex;flex-direction:column;gap:4px;font-size:12.5px;color:var(--muted);font-weight:500}
.ctl input{font:inherit;font-size:15px;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink);min-width:180px;box-shadow:var(--sombra)}
.ctl input:focus{outline:2px solid var(--acc2);border-color:var(--acc2)}
#fnota{min-height:18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:14px;margin-top:22px}
td.pend{color:var(--muted);font-style:italic}
.tile{background:var(--card);border:1px solid var(--line);border-top:5px solid var(--acc);border-radius:14px;padding:16px 18px 18px;box-shadow:var(--sombra)}
.tile.sky{border-top-color:var(--sky)}.tile.lila{border-top-color:var(--acc2)}.tile.menta{border-top-color:var(--menta)}
.tile.dest{background:var(--lav)}
.tile .t{font-size:13px;color:var(--muted);font-weight:500}
.tile .v{font-size:30px;font-weight:700;font-variant-numeric:tabular-nums;margin:4px 0 6px;letter-spacing:-.01em}
.delta{display:block;font-size:12.5px;color:var(--muted)}.delta.up{color:var(--acc);font-weight:500}.delta.down{color:var(--neg);font-weight:500}
.tabla{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--sombra)}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:10px 14px;text-align:right;white-space:nowrap;border-bottom:1px solid var(--line)}
th:first-child,td:first-child{text-align:left;position:sticky;left:0;background:var(--card)}
thead th,thead th:first-child{background:var(--hd);color:var(--hdt);font-size:12.5px;font-weight:600;border-bottom:0}
td.sub{padding-left:26px;color:var(--muted)}
tr.tot td,tr.tot td:first-child{font-weight:700;background:var(--gris2)}
tr.var td,tr.var td:first-child{background:var(--lav);color:var(--acc);font-weight:600}
tr.grp td,tr.grp td:first-child{background:var(--gris);font-weight:600;color:var(--ink);font-size:12px;letter-spacing:.04em;text-transform:uppercase;padding-top:7px;padding-bottom:7px}
tbody tr:last-child td{border-bottom:0}
svg{width:100%;height:auto;background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--sombra)}
.l-car,.l-deu{fill:none;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}.l-car{stroke:var(--acc)}.l-deu{stroke:var(--sky)}
.pt-car{fill:var(--acc)}.pt-deu{fill:var(--sky)}
.lbl-car{fill:var(--acc);font-size:12px;font-weight:700}.lbl-deu{fill:var(--skyt);font-size:12px;font-weight:700}
.ejes text{fill:var(--muted);font-size:11px}
.nota{color:var(--muted);background:var(--card);border:1px dashed var(--line);border-radius:14px;padding:16px;margin:0}
footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);font-size:12.5px;color:var(--muted);display:flex;align-items:center;gap:10px}
footer img{height:20px;width:auto;opacity:.9}
#candado{max-width:380px;margin:12vh auto 0;padding:32px 28px 28px;text-align:center;background:var(--card);border:1px solid var(--line);border-radius:18px;box-shadow:var(--sombra)}
#candado .logo{height:52px;margin:0 auto 18px}
#candado h1{font-size:22px}
#candado p{color:var(--muted);margin:4px 0 20px}
#candado .pwbox{position:relative}
#candado input{width:100%;font:inherit;padding:12px 46px 12px 14px;font-size:16px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--ink)}
#candado input:focus{outline:2px solid var(--acc2);border-color:var(--acc2)}
#candado .ojo{position:absolute;right:4px;top:50%;transform:translateY(-50%);width:40px;height:40px;border:0;background:none;color:var(--muted);cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0}
#candado .ojo:focus-visible{outline:2px solid var(--acc2);border-radius:6px}
#candado button[type=submit]{width:100%;margin-top:12px;padding:12px;font:inherit;font-size:15px;font-weight:600;border:0;border-radius:10px;background:#623DE9;color:#fff;cursor:pointer}
#candado button[type=submit]:hover{background:#5230d4}
#error{color:var(--neg);font-size:13.5px;min-height:20px;margin-top:10px}
.badge{display:inline-block;margin:6px 0 2px;padding:3px 10px;border-radius:999px;background:var(--sky);color:#0d2b40;font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
/* Estilo minimalista */
:root{--bg:#fff;--grp:#F6F5FB}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--grp:#24213a}}
:root[data-theme="dark"]{--grp:#24213a}
main{max-width:1040px}
.logo{height:40px}
h1{color:var(--ink);font-size:34px;margin-top:22px}
h1::after{content:"";display:block;width:56px;height:4px;border-radius:2px;background:var(--acc);margin-top:10px}
.meta{margin-top:10px}
.tiles{border:1px solid var(--line);border-radius:16px;overflow:hidden;background:var(--line);grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1px}
.tile{border:0;border-radius:0;box-shadow:none;padding:20px 22px}
.tile .t{text-transform:uppercase;letter-spacing:.06em;font-size:11.5px;font-weight:600;display:flex;align-items:center;gap:8px}
.tile .t::before{content:"";flex:none;width:10px;height:10px;border-radius:3px;background:var(--acc)}
.tile.sky .t::before{background:var(--sky)}.tile.lila .t::before{background:var(--acc2)}.tile.menta .t::before{background:var(--menta);box-shadow:inset 0 0 0 1px #8fd973}
.tile.dest{background:var(--lav)}
.tile .v{font-size:32px}
h2{color:var(--ink)}h2::before{background:var(--acc)}
.tabla,svg,.ctl input{box-shadow:none}
thead th,thead th:first-child{background:var(--card);color:var(--acc);border-bottom:2px solid var(--acc);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
tr.grp td,tr.grp td:first-child{background:var(--grp);color:var(--acc)}
#candado{box-shadow:0 8px 30px rgba(29,25,52,.08)}
#candado h1{margin-top:0}#candado h1::after{margin:10px auto 0}
</style></head>
<body>
<form id="candado" autocomplete="off">
  <img class="logo" src="assets/logo.png" alt="RapidAuto">__BADGE__
  <h1>__H1__</h1>
  <p>Contenido confidencial. Ingresa la contraseña.</p>
  <div class="pwbox"><input id="pw" type="password" placeholder="Contraseña" aria-label="Contraseña" autocapitalize="none" autocorrect="off" autocomplete="off" spellcheck="false" autofocus>
  <button type="button" class="ojo" id="ojo" aria-label="Mostrar contraseña" aria-pressed="false"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><line id="tacha" x1="3" y1="3" x2="21" y2="21"/></svg></button></div>
  <button type="submit">Ver reporte</button>
  <div id="error" role="alert"></div>
</form>
<main id="reporte" hidden></main>
<script>
const P={salt:"__SALT__",iv:"__IV__",data:"__DATA__",iter:__ITER__};
const b=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const MES=["ene","feb","mar","abr","may","jun","jul","ago","sep","oct","nov","dic"];
const DIA=["domingo","lunes","martes","miércoles","jueves","viernes","sábado"];
const dt=s=>{const[a,m,d]=s.split("-").map(Number);return new Date(Date.UTC(a,m-1,d))};
const ff=(s,an=true)=>{const d=dt(s);return d.getUTCDate()+" "+MES[d.getUTCMonth()]+(an?" "+d.getUTCFullYear():"")};
const esL=s=>dt(s).getUTCDay()===1;
const esc=t=>String(t).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const pesos=x=>"$"+Math.round(x).toLocaleString("en-US");
const mdp=x=>"$"+(x/1e6).toLocaleString("en-US",{minimumFractionDigits:1,maximumFractionDigits:1})+" M";
const deu=p=>Object.values(p.deuda).reduce((a,c)=>a+c,0);
const esD=s=>dt(s).getUTCDay()===0;
const pz=x=>x==null?"—":pesos(x),mz=x=>x==null?"—":mdp(x);
const dcorto=s=>DIA[dt(s).getUTCDay()].slice(0,3)+" "+ff(s,false);
let D,VS,PC={};
const iso=d=>d.toISOString().slice(0,10);
function diaDe(p){const C=p.corte_cartera;if(!C)return null;const ec=p.en_curso,se=p.colocacion,q=PC[iso(new Date(dt(C).getTime()-864e5))],qe=q&&q.en_curso;
  if(ec&&ec.desde===C)return{monto:ec.monto,creditos:ec.creditos};
  if(se&&se.hasta===C)return qe&&qe.desde===se.desde?{monto:se.monto-qe.monto,creditos:se.creditos-qe.creditos}:null;
  if(ec&&qe&&qe.desde===ec.desde)return{monto:ec.monto-qe.monto,creditos:ec.creditos-qe.creditos};
  return null}
function delta(a,b,inv){if(a==null||b==null)return"";const d=a-b;if(Math.abs(d)<0.5)return`<span class="delta">sin cambio vs ${VS}</span>`;
  const bueno=(d>0)!==!!inv;return`<span class="delta ${bueno?"up":"down"}">${d>0?"+":"−"}${mdp(Math.abs(d)).slice(1)} vs ${VS}</span>`}
const tile=(t,v,extra,sub,cls)=>`<div class="tile ${cls||""}"><div class="t">${t}</div><div class="v">${v}</div>${sub||""}${extra||""}</div>`;
const rango=c=>c&&c.desde&&c.hasta?ff(c.desde,false)+" – "+ff(c.hasta,false):"";
function grafica(cols){
  if(cols.length<2)return'<p class="nota">La gráfica de tendencia aparece a partir de la segunda semana capturada.</p>';
  const W=640,H=220,Pd=36,car=cols.map(p=>p.cartera),de=cols.map(deu),all=car.concat(de);
  const lo=Math.min(...all)*0.95,hi=Math.max(...all)*1.03,n=cols.length;
  const X=i=>Pd+i*(W-2*Pd)/(n-1),Y=v=>H-Pd-(v-lo)/(hi-lo)*(H-2*Pd);
  const ln=vs=>vs.map((v,i)=>X(i).toFixed(1)+","+Y(v).toFixed(1)).join(" ");
  const et=cols.map((p,i)=>`<text x="${X(i).toFixed(1)}" y="${H-10}" text-anchor="middle">${ff(p.fecha,false)}</text>`).join("");
  return`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Capital de cartera vs saldo de deuda"><polyline class="l-car" points="${ln(car)}"/><polyline class="l-deu" points="${ln(de)}"/>
  <text class="lbl-car" x="${X(n-1).toFixed(1)}" y="${(Y(car[n-1])-8).toFixed(1)}" text-anchor="end">Cartera ${mdp(car[n-1])}</text>
  <text class="lbl-deu" x="${X(n-1).toFixed(1)}" y="${(Y(de[n-1])+16).toFixed(1)}" text-anchor="end">Deuda ${mdp(de[n-1])}</text><circle class="pt-car" cx="${X(n-1).toFixed(1)}" cy="${Y(car[n-1]).toFixed(1)}" r="4.5"/><circle class="pt-deu" cx="${X(n-1).toFixed(1)}" cy="${Y(de[n-1]).toFixed(1)}" r="4.5"/><g class="ejes">${et}</g></svg>`}
function pintar(sel){
  const pts=D.p, diario=D.m==="diario";
  let i=-1;pts.forEach((p,k)=>{if(p.fecha<=sel)i=k});if(i<0)i=0;
  const act=pts[i];
  let cols;
  if(diario){cols=pts.filter(p=>esD(p.fecha)&&p.fecha<=act.fecha).slice(-8);if(!esD(act.fecha))cols.push(act)}
  else cols=pts.filter(p=>p.fecha<=act.fecha).slice(-8);
  const ant=cols.length>1?cols[cols.length-2]:null;
  VS=diario&&!esD(act.fecha)&&ant?"cierre "+dcorto(ant.fecha):"sem. anterior";
  const nota=document.getElementById("fnota");
  nota.textContent=act.fecha!==sel?(diario?"No hay reporte de ese día; se muestra el cierre del "+DIA[dt(act.fecha).getUTCDay()]+" "+ff(act.fecha,false)+".":"Sin datos ese día; se muestra el lunes "+ff(act.fecha,false)+"."):"";
  document.getElementById("sub").textContent=(diario?"Al cierre del "+DIA[dt(act.fecha).getUTCDay()]+" "+ff(act.fecha):"Semana del lunes "+ff(act.fecha))+" · Actualizado "+ff(D.a);
  const dA=deu(act),dB=ant?deu(ant):null,af=act.cartera/dA,afB=ant?ant.cartera/dB:null;
  let dAf="";if(afB!=null){const x=af-afB;dAf=`<span class="delta ${x>=0?"up":"down"}">${x>=0?"+":"−"}${Math.abs(x).toFixed(2)}x vs ${VS}</span>`}
  const c=act.colocacion,cB=ant&&ant.colocacion;
  let vC="Pendiente",sC="",dC="";
  if(c){vC=mdp(c.monto);sC=`<div class="delta">${c.creditos.toLocaleString("en-US")} créditos · ${rango(c)}</div>`;dC=delta(c.monto,cB?cB.monto:null)}
  const dd=diario?diaDe(act):null;
  if(dd)sC+=`<div class="delta">Del día (${ff(act.corte_cartera,false)}): ${mdp(dd.monto)} · ${dd.creditos} créd.</div>`;
  if(diario&&act.en_curso&&act.en_curso.creditos)sC+=`<div class="delta">En curso (${rango(act.en_curso)}): ${mdp(act.en_curso.monto)} · ${act.en_curso.creditos} créd.</div>`;
  document.getElementById("tiles").innerHTML=[
    tile("Capital de cartera",mdp(act.cartera),delta(act.cartera,ant?ant.cartera:null),act.corte_cartera?`<div class="delta">Corte ${ff(act.corte_cartera,false)}</div>`:""),
    tile("Colocación semanal",vC,dC,sC,"sky"),
    tile("Saldo de deuda",mdp(dA),delta(dA,dB,true),"","lila"),
    tile("Saldo en caja",mz(act.caja),delta(act.caja,ant?ant.caja:null),act.fecha_caja?`<div class="delta">Al ${ff(act.fecha_caja,false)}</div>`:"","menta"),
    tile("Aforo cartera/deuda",af.toFixed(2)+"x",dAf,"","dest")].join("");
  const ac=Object.keys(act.deuda),n=cols.length+1,g=t=>`<tr class="grp"><td colspan="${n}">${t}</td></tr>`;
  const fila=(cl,l,f)=>`<tr${cl?` class="${cl}"`:""}><td${cl==="sub"?' class="sub"':""}>${l}</td>${cols.map(f).join("")}</tr>`;
  const cel=(p,k,fm)=>p.colocacion?`<td>${fm(p.colocacion[k])}</td>`:'<td class="pend">Pendiente</td>';
  let h=g("Deuda");
  ac.forEach(a=>{h+=`<tr><td class="sub">${esc(a)}</td>${cols.map(p=>`<td>${pesos(p.deuda[a]||0)}</td>`).join("")}</tr>`});
  h+=`<tr class="tot"><td>Saldo deuda</td>${cols.map(p=>`<td>${pesos(deu(p))}</td>`).join("")}</tr>`;
  h+=g("Caja y cartera");
  h+=`<tr><td>Saldo en caja</td>${cols.map(p=>`<td>${pz(p.caja)}</td>`).join("")}</tr>`;
  h+=`<tr><td>Capital de cartera</td>${cols.map(p=>`<td>${pesos(p.cartera)}</td>`).join("")}</tr>`;
  h+=`<tr class="var"><td class="sub">Aforo cartera / deuda</td>${cols.map(p=>`<td>${(p.cartera/deu(p)).toFixed(2)}x</td>`).join("")}</tr>`;
  h+=g("Colocación semana previa (lun–dom)");
  h+=`<tr><td>Monto colocado ($)</td>${cols.map(p=>cel(p,"monto",pesos)).join("")}</tr>`;
  h+=`<tr><td class="sub">Créditos colocados (#)</td>${cols.map(p=>cel(p,"creditos",x=>x.toLocaleString("en-US"))).join("")}</tr>`;
  if(diario){h+=g("Colocación del día (fecha de corte)");
    h+=`<tr><td>Monto colocado ($)</td>${cols.map(p=>{const x=diaDe(p);return x?`<td>${pesos(x.monto)}</td>`:'<td class="pend">—</td>'}).join("")}</tr>`;
    h+=`<tr><td class="sub">Créditos colocados (#)</td>${cols.map(p=>{const x=diaDe(p);return x?`<td>${x.creditos}</td>`:'<td class="pend">—</td>'}).join("")}</tr>`}
  const th=cols.map(p=>`<th>${diario?dcorto(p.fecha):ff(p.fecha)}</th>`).join("");
  document.getElementById("tabla").innerHTML=`<table><thead><tr><th>Concepto</th>${th}</tr></thead><tbody>${h}</tbody></table>`;
  document.getElementById("graf").innerHTML=grafica(cols);
}
function montar(){
  const m=document.getElementById("reporte"),pts=D.p,diario=D.m==="diario";
  m.innerHTML=`<div class="top"><header><img class="logo" src="assets/logo.png" alt="RapidAuto"><h1>${diario?"Resumen financiero diario":"Resumen financiero semanal"}</h1><p class="meta" id="sub"></p></header>
  <label class="ctl">${diario?"Ver cierre del día":"Ver semana (lunes)"}<input type="date" id="f" min="${pts[0].fecha}" max="${pts[pts.length-1].fecha}" value="${pts[pts.length-1].fecha}"${diario?"":' step="7"'}><span id="fnota"></span></label></div>
  <section class="tiles" id="tiles"></section><section><h2>${diario?"Cierres semanales (domingo) y día elegido":"Histórico semanal"}</h2><div class="tabla" id="tabla"></div></section>
  <section><h2>Cartera vs deuda</h2><div id="graf"></div></section><footer><img src="assets/favicon.png" alt="">Información confidencial · RapidAuto</footer>`;
  const f=document.getElementById("f");
  f.addEventListener("change",()=>{if(f.value)pintar(f.value)});
  pintar(f.value);m.hidden=false;
}
document.getElementById("ojo").addEventListener("click",()=>{const i=document.getElementById("pw"),o=document.getElementById("ojo"),ver=i.type==="password";
  i.type=ver?"text":"password";o.setAttribute("aria-pressed",ver);o.setAttribute("aria-label",ver?"Ocultar contraseña":"Mostrar contraseña");
  document.getElementById("tacha").style.display=ver?"none":"";i.focus()});
document.getElementById("candado").addEventListener("submit",async e=>{
  e.preventDefault();
  const err=document.getElementById("error");
  if(!(window.crypto&&crypto.subtle)||typeof DecompressionStream==="undefined"){err.textContent="Este visor no puede abrir el reporte. Descarga el archivo y ábrelo en Chrome, Safari o Edge.";return}
  err.textContent="Verificando…";
  let plano;
  try{
    const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(document.getElementById("pw").value.trim()),"PBKDF2",false,["deriveKey"]);
    const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:b(P.salt),iterations:P.iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["decrypt"]);
    plano=await crypto.subtle.decrypt({name:"AES-GCM",iv:b(P.iv)},key,b(P.data));
  }catch(x){err.textContent="Contraseña incorrecta.";return}
  try{
    const txt=await new Response(new Blob([plano]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
    D=JSON.parse(txt);D.p.sort((a,c)=>a.fecha<c.fecha?-1:1);D.p.forEach(p=>{if(p.corte_cartera)PC[p.corte_cartera]=p});
    document.getElementById("candado").remove();montar();
  }catch(x){err.textContent="Tu navegador no puede abrir este reporte. Ábrelo con Chrome, Edge o Safari actualizados."}
});
</script>
</body></html>'''


def cargar(d):
    pts = d.get("puntos")
    if pts is None:
        pts = [dict(s, fecha=s["lunes"]) for s in d["semanas"]]
    limpios = []
    for p in pts:
        q = {k: p.get(k) for k in ("fecha", "deuda", "caja", "fecha_caja", "cartera", "corte_cartera", "colocacion", "en_curso")}
        limpios.append({k: v for k, v in q.items() if v is not None})
    limpios.sort(key=lambda p: p["fecha"])
    return {"e": d.get("empresa", "Rapidauto"), "a": d["actualizado"], "m": d.get("modo", "semanal"), "p": limpios}


def main(entrada, salida, password):
    with open(entrada, encoding="utf-8") as fh:
        datos = json.load(fh)
    plano = gzip.compress(json.dumps(cargar(datos), ensure_ascii=False, separators=(",", ":")).encode("utf-8"), 9, mtime=0)
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode("utf-8"))
    cifrado = AESGCM(key).encrypt(iv, plano, None)
    e = lambda x: base64.b64encode(x).decode()
    diario = datos.get("modo") == "diario"
    pagina = (PAGINA.replace("__TITULO__", "Resumen diario Rapidauto" if diario else "Resumen semanal Rapidauto")
              .replace("__H1__", "Resumen financiero diario" if diario else "Resumen financiero semanal")
              .replace("__BADGE__", "")
              .replace("__SALT__", e(salt)).replace("__IV__", e(iv))
              .replace("__DATA__", e(cifrado)).replace("__ITER__", str(ITER)))
    with open(salida, "w", encoding="utf-8") as fh:
        fh.write(pagina)


if __name__ == "__main__":
    main(*sys.argv[1:4])
