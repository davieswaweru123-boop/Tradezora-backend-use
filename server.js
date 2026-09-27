import express from "express";
import crypto from "crypto";
import WebSocket from "ws";

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.DERIV_CLIENT_ID;
const REDIRECT_URI = process.env.DERIV_REDIRECT_URI || "https://tradezora-backend-use-1.onrender.com/auth/callback";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://davieswaweru123-boop.github.io/Tradezora-/";
const FRONTEND_ORIGIN = new URL(FRONTEND_URL).origin;

const oauthSessions = new Map();
const userSessions = new Map();
const connectionCodes = new Map();
const tradingSockets = new Map();
const tradeHistories = new Map();
let requestCounter = 1000;

function base64url(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomId() { return base64url(crypto.randomBytes(32)); }
function codeChallenge(verifier) { return base64url(crypto.createHash("sha256").update(verifier).digest()); }

function addCors(res) {
  res.setHeader("Access-Control-Allow-Origin", FRONTEND_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-TradeZora-Session");
}
app.use((req, res, next) => {
  addCors(res);
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json());

app.get("/", (req, res) => res.json({name:"TradeZora Backend",status:"online",message:"TradeZora backend is running."}));
app.get("/health", (req, res) => res.json({status:"ok"}));

app.get("/auth/login", (req, res) => {
  if (!CLIENT_ID) return res.status(500).json({error:"DERIV_CLIENT_ID is not configured on the server."});
  const state = randomId();
  const verifier = randomId();
  oauthSessions.set(state, {codeVerifier: verifier, createdAt: Date.now()});
  const url = new URL("https://auth.deriv.com/oauth2/auth");
  url.searchParams.set("response_type","code");
  url.searchParams.set("client_id",CLIENT_ID);
  url.searchParams.set("redirect_uri",REDIRECT_URI);
  url.searchParams.set("scope","trade");
  url.searchParams.set("state",state);
  url.searchParams.set("code_challenge",codeChallenge(verifier));
  url.searchParams.set("code_challenge_method","S256");
  res.redirect(url.toString());
});

app.get("/auth/callback", async (req, res) => {
  const {code,state,error,error_description} = req.query;
  if (error) return res.status(400).json({error,error_description});
  if (!code || !state) return res.status(400).json({error:"Missing authorization code or state."});
  const oauth = oauthSessions.get(state);
  if (!oauth) return res.status(400).json({error:"Invalid or expired OAuth state."});
  oauthSessions.delete(state);
  try {
    const tokenResponse = await fetch("https://auth.deriv.com/oauth2/token", {
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded"},
      body:new URLSearchParams({
        grant_type:"authorization_code", client_id:CLIENT_ID, code,
        code_verifier:oauth.codeVerifier, redirect_uri:REDIRECT_URI
      })
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error("Token exchange failed:", tokenData);
      return res.status(tokenResponse.status || 500).json({error:"Deriv token exchange failed"});
    }
    const sessionId = randomId();
    userSessions.set(sessionId, {
      accessToken: tokenData.access_token,
      expiresAt: Date.now() + ((tokenData.expires_in || 3600) * 1000)
    });
    const connectionCode = randomId();
    connectionCodes.set(connectionCode, {sessionId, expiresAt:Date.now()+120000});
    const redirectUrl = new URL(FRONTEND_URL);
    redirectUrl.searchParams.set("connected","1");
    redirectUrl.searchParams.set("connection_code",connectionCode);
    console.log("Deriv OAuth connected successfully.");
    res.redirect(302, redirectUrl.toString());
  } catch (err) {
    console.error("OAuth callback error:", err);
    res.status(500).json({error:"OAuth callback failed."});
  }
});

app.post("/api/session/exchange", (req,res) => {
  const code = req.body?.connection_code;
  const item = connectionCodes.get(code);
  if (!item || item.expiresAt < Date.now()) {
    if (code) connectionCodes.delete(code);
    return res.status(401).json({error:"Invalid or expired connection code."});
  }
  connectionCodes.delete(code);
  const session = userSessions.get(item.sessionId);
  if (!session || session.expiresAt < Date.now()) {
    userSessions.delete(item.sessionId);
    return res.status(401).json({error:"Session expired. Please reconnect Deriv."});
  }
  console.log("TradeZora session exchanged successfully.");
  res.json({session_id:item.sessionId,expires_at:session.expiresAt});
});

function requireSession(req,res) {
  const sessionId = req.get("X-TradeZora-Session");
  const session = userSessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    if (sessionId) userSessions.delete(sessionId);
    res.status(401).json({error:"Not connected. Please connect Deriv again."});
    return null;
  }
  return {sessionId,session};
}

async function getDemoAccount(session) {
  const r = await fetch("https://api.derivws.com/trading/v1/options/accounts", {
    headers:{"Authorization":`Bearer ${session.accessToken}`,"Content-Type":"application/json"}
  });
  const raw = await r.json();
  if (!r.ok) throw new Error("Deriv account request failed.");
  const accounts = Array.isArray(raw?.data) ? raw.data : raw?.data ? [raw.data] : [];
  return accounts.find(a => String(a?.account_type || "").toLowerCase() === "demo") || null;
}

async function getTradingSocket(sessionId, session, accountId) {
  const old = tradingSockets.get(sessionId);
  if (old && old.accountId === accountId && old.ws.readyState === WebSocket.OPEN) return old;
  if (old) { try { old.ws.close(); } catch {} tradingSockets.delete(sessionId); }

  const otpResponse = await fetch(
    `https://api.derivws.com/trading/v1/options/accounts/${encodeURIComponent(accountId)}/otp`,
    {method:"POST",headers:{"Authorization":`Bearer ${session.accessToken}`}}
  );
  const otpRaw = await otpResponse.json();
  if (!otpResponse.ok || !otpRaw?.data?.url) {
    console.error("Trading OTP failed:", JSON.stringify(otpRaw));
    throw new Error("Could not create the Deriv demo trading connection.");
  }

  const ws = new WebSocket(otpRaw.data.url);
  const entry = {ws,accountId,pending:new Map()};
  tradingSockets.set(sessionId,entry);

  ws.on("message", raw => {
    let data;
    try { data = JSON.parse(raw.toString()); } catch { return; }
    const id = data?.req_id;
    if (id && entry.pending.has(id)) {
      const p = entry.pending.get(id);
      entry.pending.delete(id);
      clearTimeout(p.timer);
      if (data.error) p.reject(new Error(data.error.message || "Deriv trading request failed."));
      else p.resolve(data);
    }
  });
  ws.on("close", () => {
    if (tradingSockets.get(sessionId) === entry) tradingSockets.delete(sessionId);
    for (const [id,p] of entry.pending) {
      clearTimeout(p.timer); p.reject(new Error("Deriv trading connection closed."));
      entry.pending.delete(id);
    }
  });
  ws.on("error", e => console.error("Trading WebSocket error:", e.message));

  await new Promise((resolve,reject) => {
    const timer = setTimeout(() => reject(new Error("Deriv trading connection timed out.")),10000);
    ws.once("open",()=>{clearTimeout(timer);resolve();});
    ws.once("error",e=>{clearTimeout(timer);reject(e);});
  });
  console.log("Demo trading WebSocket connected:",accountId);
  return entry;
}

function sendTradingRequest(entry,payload,timeoutMs=12000) {
  return new Promise((resolve,reject) => {
    if (entry.ws.readyState !== WebSocket.OPEN) return reject(new Error("Deriv trading connection is not open."));
    const req_id = ++requestCounter;
    const timer = setTimeout(()=>{entry.pending.delete(req_id);reject(new Error("Deriv trading request timed out."));},timeoutMs);
    entry.pending.set(req_id,{resolve,reject,timer});
    entry.ws.send(JSON.stringify({...payload,req_id}));
  });
}

app.get("/api/account", async (req,res) => {
  const auth = requireSession(req,res); if (!auth) return;
  try {
    const r = await fetch("https://api.derivws.com/trading/v1/options/accounts", {
      headers:{"Authorization":`Bearer ${auth.session.accessToken}`,"Content-Type":"application/json"}
    });
    const raw = await r.json();
    console.log("Deriv account API status:",r.status);
    if (!r.ok) return res.status(r.status).json({error:"Deriv account request failed",details:raw});
    const accounts = Array.isArray(raw?.data) ? raw.data : raw?.data ? [raw.data] : [];
    const demo = accounts.find(a=>String(a?.account_type||"").toLowerCase()==="demo");
    const selected = demo || accounts[0] || null;
    console.log("TradeZora account loaded:",selected?.account_id||"no account",selected?.account_type||"unknown");
    res.json({
      success:true,accounts,account:selected,
      balance:selected?.balance??null,currency:selected?.currency??null,
      account_type:selected?.account_type??null,account_id:selected?.account_id??null,raw
    });
  } catch(err) {
    console.error("Account request error:",err);
    res.status(502).json({error:"Could not reach Deriv account service."});
  }
});

// DEMO ONLY: real accounts are deliberately rejected.
app.post("/api/trading/connect", async (req,res) => {
  const auth = requireSession(req,res); if (!auth) return;
  try {
    const demo = await getDemoAccount(auth.session);
    if (!demo?.account_id) return res.status(400).json({error:"No Deriv demo Options account was found."});
    if (String(demo.account_type).toLowerCase() !== "demo")
      return res.status(403).json({error:"TradeZora demo trading only allows demo accounts."});
    await getTradingSocket(auth.sessionId,auth.session,demo.account_id);
    res.json({success:true,mode:"demo",account_id:demo.account_id,currency:demo.currency||null});
  } catch(err) {
    console.error("Demo trading connect error:",err);
    res.status(502).json({error:err.message||"Could not connect to Deriv demo trading."});
  }
});

app.get("/api/trading/symbols", async (req,res) => {
  const ws = new WebSocket("wss://api.derivws.com/trading/v1/options/ws/public");
  try {
    const data = await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error("Market data request timed out.")),10000);
      ws.on("open",()=>ws.send(JSON.stringify({active_symbols:"brief",req_id:1})));
      ws.on("message",raw=>{
        try {
          const d=JSON.parse(raw.toString());
          if(d?.error){clearTimeout(timer);return reject(new Error(d.error.message||"Could not load symbols."));}
          if(d?.msg_type==="active_symbols"){clearTimeout(timer);resolve(d);}
        } catch {}
      });
      ws.on("error",e=>{clearTimeout(timer);reject(e);});
    });
    const all=Array.isArray(data.active_symbols)?data.active_symbols:[];
    const symbols=all.filter(x=>{
      const n=String(x?.underlying_symbol_name||"").toLowerCase();
      const s=String(x?.underlying_symbol||"").toUpperCase();
      return n.includes("volatility")||n.includes("crash")||n.includes("boom")||s.includes("RDBULL")||s.includes("RDBEAR");
    });
    res.json({success:true,symbols});
  } catch(err) {
    res.status(502).json({error:err.message||"Could not load trading symbols."});
  } finally { try{ws.close();}catch{} }
});

app.get("/api/trading/tick", async (req,res) => {
  const symbol=String(req.query.symbol||"").trim();
  if(!/^[A-Za-z0-9_]{2,30}$/.test(symbol)) return res.status(400).json({error:"Invalid symbol."});
  const ws=new WebSocket("wss://api.derivws.com/trading/v1/options/ws/public");
  try {
    const data=await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error("Tick request timed out.")),10000);
      ws.on("open",()=>ws.send(JSON.stringify({ticks:symbol,req_id:1})));
      ws.on("message",raw=>{
        try {
          const d=JSON.parse(raw.toString());
          if(d?.error){clearTimeout(timer);return reject(new Error(d.error.message||"Could not load price."));}
          if(d?.msg_type==="tick"){clearTimeout(timer);resolve(d);}
        } catch {}
      });
      ws.on("error",e=>{clearTimeout(timer);reject(e);});
    });
    res.json({success:true,symbol:data.tick?.symbol||symbol,quote:data.tick?.quote??null,epoch:data.tick?.epoch??null});
  } catch(err) { res.status(502).json({error:err.message||"Could not load price."}); }
  finally { try{ws.close();}catch{} }
});

app.post("/api/trading/proposal", async (req,res) => {
  const auth=requireSession(req,res); if(!auth)return;
  try {
    const demo=await getDemoAccount(auth.session);
    if(!demo?.account_id)return res.status(400).json({error:"No demo account available."});
    const {underlying_symbol,contract_type,amount,duration,duration_unit,barrier}=req.body||{};
    const stake=Number(amount), dur=Number(duration);
    if(!underlying_symbol||!contract_type)return res.status(400).json({error:"Symbol and contract type are required."});
    if(!Number.isFinite(stake)||stake<=0)return res.status(400).json({error:"Stake must be greater than zero."});
    if(!Number.isFinite(dur)||dur<=0)return res.status(400).json({error:"Duration must be greater than zero."});
    const type=String(contract_type).toUpperCase();
    if(!new Set(["CALL","PUT","DIGITOVER","DIGITUNDER"]).has(type))return res.status(400).json({error:"This demo contract type is not supported."});
const proposalRequest={
  proposal:1,
  amount:stake,
  basis:"stake",
  contract_type:type,
  currency:demo.currency||"USD",
  duration:dur,
  duration_unit:duration_unit||"s",
  underlying_symbol:String(underlying_symbol)
};
app.post("/api/trading/proposal", async (req,res) => {
  const auth=requireSession(req,res); if(!auth)return;

  try {
    const demo=await getDemoAccount(auth.session);
    if(!demo?.account_id)return res.status(400).json({error:"No demo account available."});

    const {underlying_symbol,contract_type,amount,duration,duration_unit,barrier}=req.body||{};

    const stake=Number(amount);
    const dur=Number(duration);
    const type=String(contract_type).toUpperCase();

    if(!underlying_symbol||!contract_type)
      return res.status(400).json({error:"Symbol and contract type are required."});

    if(!Number.isFinite(stake)||stake<=0)
      return res.status(400).json({error:"Stake must be greater than 0."});

    if(!Number.isFinite(dur)||dur<=0)
      return res.status(400).json({error:"Duration must be greater than 0."});

    if(!new Set(["CALL","PUT","DIGITOVER","DIGITUNDER"]).has(type))
      return res.status(400).json({error:"This demo contract type is not supported."});

    const proposalRequest={
      proposal:1,
      amount:stake,
      basis:"stake",
      contract_type:type,
      currency:demo.currency||"USD",
      duration:dur,
      duration_unit:duration_unit||"s",
      underlying_symbol:String(underlying_symbol)
    };

    if(type==="DIGITOVER" || type==="DIGITUNDER"){
      const digit=Number(barrier);

      if(!Number.isInteger(digit)||digit<0||digit>9){
        return res.status(400).json({error:"Barrier must be a digit from 0 to 9."});
      }

      proposalRequest.barrier=digit;
    }

    const entry=await getTradingSocket(auth.sessionId,auth.session,demo.account_id);
    const result=await sendTradingRequest(entry,proposalRequest);

    res.json({success:true,proposal:result.proposal||null});

  } catch(err) {
    console.error("Proposal error:",err);
    res.status(502).json({error:err.message||"Could not get a demo trade proposal."});
  }
});
