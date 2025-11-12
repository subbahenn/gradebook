// ===== Noten-Mapping (inkl. typografischem Minus) =====
const SYMBOL_TO_VALUE = { "+++":1, "++":2, "+":3, "o":4, "-":5, "--":6, "−":5, "−−":6 };
const DISPLAY_MINUS = s => s.replaceAll("-", "−");
const NORM_SYMBOL = s => s.replaceAll("−", "-");

// ===== Krypto/IndexedDB (AES-GCM-Vault) =====
const DB_NAME = "oralGradesDB_secure_v6";
const DB_VERSION = 1;
// Stores: users(id, username unique, salt, passHash, encDataKey, keyIv), vault(id, userId, kind, iv, data b64)

function toB64(ab){ return btoa(String.fromCharCode(...new Uint8Array(ab))); }
function fromB64(b64){ const bin=atob(b64); const u8=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u8[i]=bin.charCodeAt(i); return u8.buffer; }
function randBytes(n){ const a=new Uint8Array(n); crypto.getRandomValues(a); return a; }

async function pbkdf2Key(pass, saltBytes){
  const enc=new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt: saltBytes, iterations: 250000, hash:"SHA-256" },
    baseKey,
    { name:"AES-GCM", length:256 },
    true, ["encrypt","decrypt"]
  );
}
async function aesGcmEncrypt(key, dataObj){
  const iv = randBytes(12);
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(dataObj));
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, data);
  return { iv: btoa(String.fromCharCode(...iv)), data: btoa(String.fromCharCode(...new Uint8Array(ct))) };
}
async function aesGcmDecrypt(key, payload){
  const iv = new Uint8Array(atob(payload.iv).split("").map(c=>c.charCodeAt(0)));
  const ct = new Uint8Array(atob(payload.data).split("").map(c=>c.charCodeAt(0)));
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}
async function importRawAesKey(bytes){ return crypto.subtle.importKey("raw", bytes, "AES-GCM", true, ["encrypt","decrypt"]); }

// IDB helpers
function openDB(){
  return new Promise((res, rej)=>{
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = ()=>{
      const db = req.result;
      if (!db.objectStoreNames.contains("users")){
        const s = db.createObjectStore("users", { keyPath:"id" });
        s.createIndex("by_username","username",{unique:true});
      }
      if (!db.objectStoreNames.contains("vault")){
        const v = db.createObjectStore("vault", { keyPath:"id" });
        v.createIndex("by_user","userId");
      }
    };
    req.onerror = ()=> rej(req.error);
    req.onsuccess = ()=> res(req.result);
  });
}
function os(db, store, mode="readonly"){ return db.transaction(store, mode).objectStore(store); }
function dbGetByIndex(db, store, index, key){
  return new Promise((res, rej)=>{
    const req = os(db, store).index(index).get(key);
    req.onsuccess = ()=> res(req.result || null);
    req.onerror = ()=> rej(req.error);
  });
}
function dbGetAllByUser(db, store, userId){
  return new Promise((res, rej)=>{
    const idx = os(db, store).index("by_user");
    const req = idx.openCursor(IDBKeyRange.only(userId));
    const out=[]; req.onsuccess = e=>{ const c=e.target.result; if (c){ out.push(c.value); c.continue(); } else res(out); };
    req.onerror = ()=> rej(req.error);
  });
}
function dbPut(db, store, val){ return new Promise((res, rej)=>{ const r=os(db,store,"readwrite").put(val); r.onsuccess=()=>res(val); r.onerror=()=>rej(r.error); }); }
function dbAdd(db, store, val){ return new Promise((res, rej)=>{ const r=os(db,store,"readwrite").add(val); r.onsuccess=()=>res(val); r.onerror=()=>rej(r.error); }); }
function dbDelete(db, store, key){ return new Promise((res, rej)=>{ const r=os(db,store,"readwrite").delete(key); r.onsuccess=()=>res(); r.onerror=()=>rej(r.error); }); }

// ===== Session/State =====
const elAuth = document.getElementById("view-auth");
const appHeader = document.getElementById("appHeader");
const appMain = document.getElementById("appMain");
const appTitle = document.getElementById("appTitle");

const loginForm = document.getElementById("loginForm");
const loginUser = document.getElementById("loginUser");
const loginPass = document.getElementById("loginPass");
const rememberUser = document.getElementById("rememberUser");
const registerForm = document.getElementById("registerForm");
const regUser = document.getElementById("regUser");
const regPass = document.getElementById("regPass");
const logoutBtn = document.getElementById("logoutBtn");

const tabs = document.querySelectorAll(".tab-btn");
const views = document.querySelectorAll(".view");
const themeToggle = document.getElementById("themeToggle");
const todayDisplay = document.getElementById("todayDisplay");

const classSelectRecord = document.getElementById("classSelectRecord");
const studentList = document.getElementById("studentList");
const hintNoClass = document.getElementById("hintNoClass");
const dateFrom = document.getElementById("dateFrom");
const dateTo = document.getElementById("dateTo");
const btnH1 = document.getElementById("btnH1");
const btnH2 = document.getElementById("btnH2");
const sortModeSel = document.getElementById("sortMode");

const formGlobalYear = document.getElementById("formGlobalYear");
const globalYearStart = document.getElementById("globalYearStart");
const globalH2Start = document.getElementById("globalH2Start");
const globalYearEnd = document.getElementById("globalYearEnd");

const formClass = document.getElementById("formClass");
const classNameEl = document.getElementById("className");
const classSubject = document.getElementById("classSubject");
const classTeacher = document.getElementById("classTeacher");
const yearStartEl = document.getElementById("yearStart");
const h2StartEl = document.getElementById("h2Start");
const yearEndEl = document.getElementById("yearEnd");
const studentNames = document.getElementById("studentNames");
const csvImportCreate = document.getElementById("csvImportCreate");
const btnCsvImportCreate = document.getElementById("btnCsvImportCreate");
const classList = document.getElementById("classList");

const classSelectOverview = document.getElementById("classSelectOverview");
const studentSelectOverview = document.getElementById("studentSelectOverview");
const overviewFrom = document.getElementById("overviewFrom");
const overviewTo = document.getElementById("overviewTo");
const btnH1Overview = document.getElementById("btnH1Overview");
const btnH2Overview = document.getElementById("btnH2Overview");
const overviewTableBody = document.getElementById("overviewTableBody");
const overviewStats = document.getElementById("overviewStats");

const classSelectSeating = document.getElementById("classSelectSeating");
const roomNameInput = document.getElementById("roomNameInput");
const seatingPreset = document.getElementById("seatingPreset");
const seatingRows = document.getElementById("seatingRows");
const seatingCols = document.getElementById("seatingCols");
const seatingAisles = document.getElementById("seatingAisles");
const btnBuildGrid = document.getElementById("btnBuildGrid");
const btnClearSeating = document.getElementById("btnClearSeating");
const btnExportPDFSeating = document.getElementById("btnExportPDFSeating");
const seatingPalette = document.getElementById("seatingPalette");
const seatingGrid = document.getElementById("seatingGrid");

const popover = document.getElementById("gradePopover");
const popoverStudent = document.getElementById("popoverStudent");
const popoverCancel = document.getElementById("popoverCancel");
const toastEl = document.getElementById("toast");

// In-Memory, entschlüsselt
let db = null, dataKey = null, currentUser = null;
let state = { settings:null, classes:[], students:[], entries:[] };
let currentClassId = null;
let seatingSelectedStudentId = null;
let popoverTarget = null;

// ===== Utils =====
function uid(prefix="id"){ return `${prefix}_${Math.random().toString(36).slice(2,9)}${Date.now().toString(36)}`; }
function splitName(name){ const p=name.trim().split(/\s+/); if (p.length===1) return {first:p[0], last:p[0]}; return {first:p.slice(0,-1).join(" "), last:p[p.length-1]}; }
function todayISO(){ return new Date().toISOString().slice(0,10); }
function todayLocal(){ return new Date().toLocaleDateString("de-DE", {weekday:"short", year:"numeric", month:"2-digit", day:"2-digit"}); }
function dateMinusOne(iso){ const d=new Date(iso); d.setDate(d.getDate()-1); return d.toISOString().slice(0,10); }
function within(d,f,t){ if(!f && !t) return true; if(f && d<f) return false; if(t && d>t) return false; return true; }
function mean(a){ if(!a||a.length===0) return null; return a.reduce((s,x)=>s+x,0)/a.length; }
function fmtMean(x){ if(x==null) return "—"; return (Math.round(x*10)/10).toFixed(1).replace(".",","); }
function defaultGlobalYear(){ const now=new Date(); const y = now.getMonth()>=7 ? now.getFullYear() : now.getFullYear()-1; return { yearStart:`${y}-08-01`, h2Start:`${y+1}-02-01`, yearEnd:`${y+1}-07-31` }; }
function classSemesterRanges(cls){ const gy=state.settings?.globalYear || defaultGlobalYear(); const from1=cls?.yearStart||gy.yearStart; const from2=cls?.h2Start||gy.h2Start; const end=cls?.yearEnd||gy.yearEnd; return { h1:{from:from1,to:dateMinusOne(from2)}, h2:{from:from2,to:end} }; }
function pickCurrentSemesterRange(cls){ const t=todayISO(); const {h1,h2}=classSemesterRanges(cls); return (t>=h2.from && t<=h2.to)?h2:h1; }
function escapeHtml(s){ return String(s??"").replace(/[&<>"']/g, m=> ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

// Durchschnitt → Farbklasse (für Listen; Sitzplan bleibt neutral)
function gradeClass(avg){
  if (avg==null || Math.abs(avg-4) < 0.051) return "grade-neutral";
  if (avg<=2) return "grade-a";
  if (avg<=3) return "grade-b";
  if (avg<4) return "grade-c";
  if (avg<=5) return "grade-d";
  return "grade-e";
}

// ===== Auth / Vault =====
async function register(username, password){
  const exists = await dbGetByIndex(db,"users","by_username",username);
  if (exists) throw new Error("Benutzername bereits vergeben.");
  const id = uid("usr");
  const salt = randBytes(16);
  const passHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${toB64(salt)}:${password}`));
  const kdfKey = await pbkdf2Key(password, salt);
  const rawDataKey = randBytes(32);
  const wrapped = await aesGcmEncrypt(kdfKey, { key: toB64(rawDataKey) });
  const user = { id, username, salt: toB64(salt), passHash: toB64(passHash), encDataKey: wrapped.data, keyIv: wrapped.iv, createdAt: new Date().toISOString() };
  await dbAdd(db, "users", user);
  const dk = await importRawAesKey(rawDataKey);
  await saveEncrypted("settings", { userId:id, theme:"light", sortModeByClass:{}, globalYear: defaultGlobalYear() }, id, dk);
}
async function login(username, password){
  const user = await dbGetByIndex(db,"users","by_username",username);
  if (!user) throw new Error("Unbekannter Benutzer.");
  const passHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${user.salt}:${password}`));
  if (toB64(passHash) !== user.passHash) throw new Error("Falsches Passwort.");
  const kdfKey = await pbkdf2Key(password, fromB64(user.salt));
  const raw = await aesGcmDecrypt(kdfKey, { iv:user.keyIv, data:user.encDataKey });
  dataKey = await importRawAesKey(fromB64(raw.key));
  currentUser = { id:user.id, username:user.username };
}
async function saveEncrypted(kind, obj, id, overrideKey=null){
  const key = overrideKey || dataKey;
  const payload = { ...obj, id: id || obj.id || uid(kind) };
  const enc = await aesGcmEncrypt(key, payload);
  const item = { id: payload.id, userId: payload.userId || currentUser.id, kind, iv: enc.iv, data: enc.data };
  await dbPut(db, "vault", item);
  return payload.id;
}
async function deleteEncrypted(id){ await dbDelete(db, "vault", id); }
async function loadAllDecrypted(){
  const items = await dbGetAllByUser(db, "vault", currentUser.id);
  const out = { settings:null, classes:[], students:[], entries:[] };
  for (const it of items){
    const obj = await aesGcmDecrypt(dataKey, { iv: it.iv, data: it.data });
    if (it.kind==="settings") out.settings = obj;
    else if (it.kind==="class") out.classes.push(obj);
    else if (it.kind==="student") out.students.push(obj);
    else if (it.kind==="entry") out.entries.push(obj);
  }
  state = out;
  if (!state.settings) state.settings = { userId: currentUser.id, theme:"light", sortModeByClass:{}, globalYear: defaultGlobalYear(), id: uid("set") };
}

// ===== UI Boot =====
todayDisplay.textContent = todayLocal();
function applyTheme(){ document.body.setAttribute("data-theme", state.settings?.theme || "light"); }
themeToggle.addEventListener("click", async ()=>{
  state.settings.theme = (state.settings.theme==="dark") ? "light" : "dark";
  await saveEncrypted("settings", state.settings, state.settings.id);
  applyTheme();
});
logoutBtn.addEventListener("click", ()=>{
  currentUser=null; dataKey=null; state={settings:null,classes:[],students:[],entries:[]};
  appHeader.classList.add("hidden"); appMain.classList.add("hidden"); elAuth.classList.remove("hidden");
});

// Remember username
(function restoreRemembered(){
  const u = localStorage.getItem("oralGrades.remember.username");
  if (u) { loginUser.value = u; rememberUser.checked = true; }
})();
registerForm.addEventListener("submit", async (e)=>{
  e.preventDefault();
  try{
    await register(regUser.value.trim(), regPass.value);
    showToast("Benutzer angelegt. Bitte anmelden.");
    regUser.value=""; regPass.value="";
  }catch(err){ showToast(err.message || "Registrierung fehlgeschlagen."); }
});
loginForm.addEventListener("submit", async (e)=>{
  e.preventDefault();
  try{
    await login(loginUser.value.trim(), loginPass.value);
    if (rememberUser.checked) localStorage.setItem("oralGrades.remember.username", loginUser.value.trim());
    else localStorage.removeItem("oralGrades.remember.username");
    await loadAllDecrypted();
    elAuth.classList.add("hidden"); appHeader.classList.remove("hidden"); appMain.classList.remove("hidden");
    initAfterLogin();
  }catch(err){ showToast(err.message || "Login fehlgeschlagen."); }
});

// ===== Domain helpers =====
function getClasses(){ return state.classes; }
function getClass(id){ return state.classes.find(c=>c.id===id); }
function getStudentsByClass(classId){ return state.students.filter(s=>s.classId===classId).sort((a,b)=>(a.sortIndex||0)-(b.sortIndex||0)); }
function getStudentName(id){ return state.students.find(s=>s.id===id)?.name ?? "—"; }
function getClassName(id){ return getClass(id)?.name ?? "—"; }
function getSeating(classId){
  const c=getClass(classId); if (!c) return {rows:5,cols:6,preset:"free",disabled:[],roomName:"",cells:{}, aisles:[]};
  c.seating = c.seating || { rows:5, cols:6, preset:"free", disabled:[], roomName:"", cells:{}, aisles:[] };
  c.seating.aisles ||= [];
  return c.seating;
}
async function updateEncrypted(kind, obj){ await saveEncrypted(kind, obj, obj.id); }

// ===== Titel je aktiver Ansicht =====
function updateAppTitle(){
  const activeId = document.querySelector(".view.active")?.id || "view-erfassen";
  const nameRecord = getClassName(currentClassId) || "—";
  const nameOverview = getClassName(classSelectOverview.value) || nameRecord;
  const nameSeating = getClassName(classSelectSeating.value) || nameRecord;

  if (activeId === "view-verwaltung") {
    appTitle.textContent = "Verwaltung";
  } else if (activeId === "view-uebersicht") {
    appTitle.textContent = `Übersicht der Klasse ${nameOverview}`;
  } else if (activeId === "view-sitzplan") {
    appTitle.textContent = `Sitzplan der Klasse ${nameSeating}`;
  } else {
    appTitle.textContent = `Mündliche Noten der Klasse ${nameRecord}`;
  }
}

// ===== Routing =====
function showView(sel){
  views.forEach(v=>v.classList.remove("active"));
  document.querySelector(sel)?.classList.add("active");
  tabs.forEach(t=>t.setAttribute("aria-selected", String(t.dataset.view===sel)));
  if (sel==="#view-erfassen"){
    populateClassSelects(); setDefaultDatesForRecord(); initDefaultSortModeForClass(); renderStudentList(); highlightSemesterButtons();
  } else if (sel==="#view-verwaltung"){
    renderGlobalYearForm(); renderClassList();
  } else if (sel==="#view-uebersicht"){
    populateClassSelects(); setDefaultDatesForOverview(); renderOverview(); highlightSemesterButtons(true);
  } else if (sel==="#view-sitzplan"){
    populateClassSelects(); classSelectSeating.value=currentClassId||classSelectSeating.value; renderSeatingControlsFromClass(); renderSeating();
  }
  updateAppTitle();
}
tabs.forEach(btn=> btn.addEventListener("click", ()=> showView(btn.dataset.view)));

// ===== Populate selects =====
function populateClassSelects(){
  const classes=getClasses();
  const fills=[classSelectRecord,classSelectOverview,classSelectSeating];
  for (const sel of fills){
    sel.innerHTML=""; if (classes.length===0){ const o=document.createElement("option"); o.value=""; o.textContent="— keine —"; sel.appendChild(o); continue; }
    for (const c of classes){ const o=document.createElement("option"); o.value=c.id; o.textContent=`${c.name} · ${c.subject||"Fach"} (${c.teacher||"—"})`; sel.appendChild(o); }
  }
  if (classes.length>0){
    if (!currentClassId || !classes.some(c
