const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const clean = (v, n=200) => String(v ?? "").trim().slice(0,n);
const digits = v => String(v ?? "").replace(/\D/g,"");
function validCPF(v) {
  const c=digits(v); if(c.length!==11 || /^(\d)\1{10}$/.test(c)) return false;
  let s=0; for(let i=0;i<9;i++) s+=Number(c[i])*(10-i);
  let d=(s*10)%11; if(d===10)d=0; if(d!==Number(c[9]))return false;
  s=0; for(let i=0;i<10;i++)s+=Number(c[i])*(11-i);
  d=(s*10)%11; if(d===10)d=0; return d===Number(c[10]);
}
const hex = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const randomHex = (n=32) => hex(crypto.getRandomValues(new Uint8Array(n)));
async function digest(v){return hex(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(v)));}
async function passwordHash(password,saltHex){
  const salt=Uint8Array.from(saltHex.match(/.{2}/g),x=>parseInt(x,16));
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},key,256));
}
const setCookie = token => "session="+token+"; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800";
const clearCookie = "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
const validEmail = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const protocol = () => String(new Date().getFullYear())+crypto.getRandomValues(new Uint32Array(1))[0].toString().padStart(10,"0");
async function readBody(req){
  if(!(req.headers.get("content-type")||"").includes("application/json")) throw new Error("Envie os dados em formato JSON.");
  return req.json();
}
async function register(req,env){
  const d=await readBody(req), cpf=digits(d.cpf), email=clean(d.email,180).toLowerCase(), pass=String(d.password||"");
  if(!validCPF(cpf))return json({error:"CPF inválido. Confira os números digitados."},400);
  if(!validEmail(email))return json({error:"Informe um e-mail válido."},400);
  if(pass.length<10||pass.length>128)return json({error:"A senha deve ter entre 10 e 128 caracteres."},400);
  const required=["nome","rg","nascimento","sexo","nacionalidade","mae","cep","estado","logradouro","numero","bairro","cidade","telefone","escola","ano","tipo-escola","concorrencia"];
  if(required.some(k=>!clean(d[k],300)))return json({error:"Preencha todos os campos obrigatórios."},400);
  if(d.privacyConsent!==true)return json({error:"É necessário confirmar a leitura do aviso de privacidade."},400);
  const year=Number(d.ano); if(!Number.isInteger(year)||year<1950||year>new Date().getFullYear()+1)return json({error:"Ano de conclusão do Ensino Médio inválido."},400);
  const choices=[1,2,3].map(n=>({n,course:clean(d["curso"+n],180),location:clean(d["local"+n],180),modality:clean(d["modalidade"+n],40)})).filter(x=>x.course);
  if(!choices.length||!choices[0].location||!choices[0].modality)return json({error:"Informe a primeira opção de curso, local e modalidade."},400);
  if(choices.some(x=>!x.location||!["Presencial","Semipresencial","Online (EAD)"].includes(x.modality)))return json({error:"Confira local e modalidade das opções de curso."},400);
  const cid=crypto.randomUUID(), aid=crypto.randomUUID(), p=protocol(), salt=randomHex(16), hash=await passwordHash(pass,salt), now=new Date().toISOString();
  try{
    await env.DB.batch([
      env.DB.prepare("INSERT INTO candidates (id,full_name,social_name,cpf,rg,birth_date,sex,nationality,mother_name,father_name,cep,state_uf,street,street_number,address_complement,neighborhood,city,phone,email,high_school_name,high_school_completion_year,high_school_type,password_hash,password_salt,account_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'active')")
      .bind(cid,clean(d.nome,180),clean(d.social,180),cpf,clean(d.rg,40),clean(d.nascimento,10),clean(d.sexo,40),clean(d.nacionalidade,80),clean(d.mae,180),clean(d.pai,180),digits(d.cep),clean(d.estado,2).toUpperCase(),clean(d.logradouro,180),clean(d.numero,30),clean(d.complemento,100),clean(d.bairro,100),clean(d.cidade,100),digits(d.telefone),email,clean(d.escola,180),year,clean(d["tipo-escola"],20),hash,salt),
      env.DB.prepare("INSERT INTO applications (id,protocol,candidate_id,competition_type,privacy_notice_version,privacy_consent_at) VALUES (?,?,?,?,?,?)").bind(aid,p,cid,clean(d.concorrencia,60),"2026-11-09-v1",now),
      ...choices.map(x=>env.DB.prepare("INSERT INTO course_choices (id,application_id,preference_order,course_name,study_location,study_modality) VALUES (?,?,?,?,?,?)").bind(crypto.randomUUID(),aid,x.n,x.course,x.location,x.modality)),
      env.DB.prepare("INSERT INTO application_events (id,application_id,actor_type,event_type,description) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(),aid,"system","application_received","Inscrição recebida pelo sistema.")
    ]);
  }catch(e){
    if(String(e).includes("UNIQUE")||String(e).includes("constraint"))return json({error:"Já existe cadastro com este CPF. Utilize a Área do Candidato ou procure o Polo."},409);
    console.error("registration_error",e);return json({error:"Não foi possível concluir o cadastro. Tente novamente mais tarde."},500);
  }
  const token=randomHex(32), tokenHash=await digest(token), expires=new Date(Date.now()+28800000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (id,subject_id,subject_type,token_hash,expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(),cid,"candidate",tokenHash,expires).run();
  return json({message:"Cadastro recebido.",protocol:p,next:"/candidato.html"},201,{"set-cookie":setCookie(token)});
}
async function login(req,env){
  const d=await readBody(req),cpf=digits(d.cpf),pass=String(d.password||"");
  if(!validCPF(cpf)||!pass)return json({error:"CPF ou senha inválidos."},400);
  const c=await env.DB.prepare("SELECT id,password_hash,password_salt,account_status FROM candidates WHERE cpf=?").bind(cpf).first();
  if(!c||c.account_status!=="active"||await passwordHash(pass,c.password_salt)!==c.password_hash)return json({error:"CPF ou senha inválidos."},401);
  const token=randomHex(32), expires=new Date(Date.now()+28800000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (id,subject_id,subject_type,token_hash,expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(),c.id,"candidate",await digest(token),expires).run();
  return json({message:"Acesso autorizado."},200,{"set-cookie":setCookie(token)});
}
async function sessionCandidate(req,env){
  const token=(req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("session="))?.slice(8);
  if(!token)return null;
  const s=await env.DB.prepare("SELECT subject_id FROM sessions WHERE token_hash=? AND subject_type='candidate' AND expires_at>?").bind(await digest(token),new Date().toISOString()).first();
  return s?.subject_id||null;
}
async function me(req,env){
  const id=await sessionCandidate(req,env);if(!id)return json({error:"Sessão expirada. Entre novamente."},401);
  const a=await env.DB.prepare("SELECT a.id,a.protocol,a.application_status,a.payment_status,a.fee_amount_cents,a.payment_due_date,a.exam_location,a.exam_room,a.exam_date,a.exam_time,a.result_status,a.created_at,c.full_name FROM applications a JOIN candidates c ON c.id=a.candidate_id WHERE c.id=? ORDER BY a.created_at DESC LIMIT 1").bind(id).first();
  if(!a)return json({error:"Inscrição não encontrada."},404);
  const choices=await env.DB.prepare("SELECT preference_order,course_name,study_location,study_modality FROM course_choices WHERE application_id=? ORDER BY preference_order").bind(a.id).all();
  delete a.id;return json({candidate:{name:a.full_name},application:a,choices:choices.results||[]});
}
async function logout(req,env){
  const token=(req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("session="))?.slice(8);
  if(token)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
  return json({message:"Sessão encerrada."},200,{"set-cookie":clearCookie});
}
export default {async fetch(req,env){
  const url=new URL(req.url),origin=req.headers.get("Origin");
  if(origin&&origin!==url.origin)return json({error:"Origem não autorizada."},403);
  try{
    if(url.pathname==="/api/health"&&req.method==="GET"){const r=await env.DB.prepare("SELECT 1 AS ok").first();return json({status:"online",database:r?.ok===1?"connected":"unavailable"});}
    if(url.pathname==="/api/register"&&req.method==="POST")return await register(req,env);
    if(url.pathname==="/api/login"&&req.method==="POST")return await login(req,env);
    if(url.pathname==="/api/me"&&req.method==="GET")return await me(req,env);
    if(url.pathname==="/api/logout"&&req.method==="POST")return await logout(req,env);
    return json({error:"Rota não encontrada."},404);
  }catch(e){console.error("api_error",e);return json({error:e.message==="Envie os dados em formato JSON."?e.message:"Erro interno. Tente novamente."},500);}
}};
