const BUILD_ID = "admin-panel-expanded-2026-11-12-1";
const ADMIN_ID = "administrador1";
const ADMIN_PASSWORD_HASH = "5da2f01fe41716da7f83b9a0211c2990e13a088f75422c98c384d9379feffe1d";
const json = (data, status = 200) => Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
const text = (value, max = 250) => typeof value === "string" ? value.trim().slice(0, max) : "";
const required = value => typeof value === "string" && value.trim().length > 0;
const random = n => crypto.getRandomValues(new Uint8Array(n));
const b64 = bytes => { const a = new Uint8Array(bytes); let s = ""; for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, "0")).join("");
async function sha256(value) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}
function validCpf(value) {
  const cpf = value.replace(/\D/g, "");
  if (!/^\d{11}$/.test(cpf) || /(\d)\1{10}/.test(cpf)) return false;
  const calc = (base, factor) => { let sum = 0; for (const digit of base) sum += Number(digit) * factor--; const r = (sum * 10) % 11; return r === 10 ? 0 : r; };
  return calc(cpf.slice(0, 9), 10) === Number(cpf[9]) && calc(cpf.slice(0, 10), 11) === Number(cpf[10]);
}
function validEmail(value) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
async function passwordKey(password, salt, iterations = 100000, onStep = () => {}) {
  onStep("pbkdf2-import");
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
  onStep("pbkdf2-derive-key");
  // PBKDF2 deriveKey(AES-GCM-256) gera exatamente a mesma chave que deriveBits(256)
  // seguido de importKey(AES-GCM), preservando os registros já criptografados.
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function seal(data, password, onStep = () => {}) {
  onStep("generate-salt-and-iv");
  const salt = random(16), iv = random(12);
  const key = await passwordKey(password, salt, 100000, onStep);
  onStep("aes-gcm-encrypt");
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(data)));
  onStep("encode-encrypted-record");
  return { version: 1, iterations: 100000, salt: b64(salt), iv: b64(iv), cipher: b64(cipher) };
}
async function unseal(record, password) {
  const iterations = Number.isInteger(record.iterations) ? record.iterations : 310000;
  const key = await passwordKey(password, unb64(record.salt), iterations);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(record.iv) }, key, unb64(record.cipher));
  return JSON.parse(new TextDecoder().decode(plain));
}
function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}
async function readBody(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 20000) throw new Error("SIZE");
  const raw = await request.text();
  if (raw.length > 20000) throw new Error("SIZE");
  return JSON.parse(raw);
}
async function createApplication(request, env) {
  if (!env.VESTIBULAR_KV) return json({ error: "Armazenamento KV não está configurado." }, 503);
  if (!sameOrigin(request)) return json({ error: "Origem não autorizada." }, 403);
  let body;
  try { body = await readBody(request); } catch (error) {
    return json({ error: error.message === "SIZE" ? "Formulário muito grande." : "Envie os dados em formato válido." }, error.message === "SIZE" ? 413 : 400);
  }
  const p = body.personal || {}, a = body.address || {}, s = body.school || {};
  const cpf = text(p.cpf, 30).replace(/\D/g, "");
  const email = text(p.email, 180).toLowerCase();
  const password = typeof body.password === "string" ? body.password : "";
  const requiredValues = [p.fullName,p.rg,p.birthDate,p.sex,p.nationality,p.motherName,a.cep,a.state,a.street,a.number,a.neighborhood,a.city,p.phone,email,s.name,s.completionYear,s.type,body.competitionType];
  if (!requiredValues.every(required) || !validCpf(cpf) || !validEmail(email) || password.length < 10 || password.length > 128) {
    return json({ error: "Confira os campos obrigatórios, o CPF, o e-mail e a senha (mínimo de 10 caracteres)." }, 400);
  }
  if (!/^\d{4}$/.test(String(s.completionYear)) || !["Ampla concorrência","Cotas"].includes(body.competitionType)) return json({ error: "Confira o ano de conclusão e a modalidade de concorrência." }, 400);
  const choices = Array.isArray(body.choices) ? body.choices : [];
  if (choices.length < 1 || choices.length > 3 || choices.some(c => !required(c.course) || !required(c.location) || !["Presencial","Semipresencial","Online (EAD)"].includes(c.mode))) return json({ error: "Informe de uma a três opções de curso com local e modalidade." }, 400);
  if (new Set(choices.map(c => text(c.course,180).toLowerCase())).size !== choices.length) return json({ error: "Não repita o mesmo curso nas opções." }, 400);
  const cpfKey = "cpf:" + await sha256(cpf);
  let step = "cpf-index-check";
  try {
    if (await env.VESTIBULAR_KV.get(cpfKey)) return json({ error: "Já existe uma inscrição com este CPF. Se você já se inscreveu, acesse a Área do Candidato." }, 409);
    step = "build-application";
    const protocol = "UF2027-" + hex(random(6)).toUpperCase();
    const application = {
      protocol, createdAt: new Date().toISOString(), status: "Inscrição recebida",
      personal: {
        fullName: text(p.fullName,180), cpf, rg: text(p.rg,60), birthDate: text(p.birthDate,10),
        sex: text(p.sex,40), socialName: text(p.socialName,180), nationality: text(p.nationality,80),
        motherName: text(p.motherName,180), fatherName: text(p.fatherName,180),
        phone: text(p.phone,30), email
      },
      address: { cep:text(a.cep,12), state:text(a.state,2).toUpperCase(), street:text(a.street,180), number:text(a.number,30), complement:text(a.complement,100), neighborhood:text(a.neighborhood,100), city:text(a.city,100) },
      school: { name:text(s.name,180), completionYear:String(s.completionYear), type:text(s.type,30) },
      competitionType: body.competitionType,
      choices: choices.map(c => ({ course:text(c.course,180), location:text(c.location,120), mode:c.mode }))
    };
    step = "encrypt-application";
    const encrypted = await seal(application, password, substage => { step = "encrypt-application:" + substage; });
    step = "write-application";
    await env.VESTIBULAR_KV.put("application:" + protocol, JSON.stringify(encrypted));
    if (ADMIN_PASSWORD_HASH) {
      const adminEncrypted = await seal(application, ADMIN_PASSWORD_HASH);
      await env.VESTIBULAR_KV.put("admin-application:" + protocol, JSON.stringify(adminEncrypted));
    }
    step = "write-cpf-index";
    await env.VESTIBULAR_KV.put(cpfKey, protocol);
    return json({ ok:true, protocol, message:"Inscrição registrada com sucesso. Guarde seu protocolo." }, 201);
  } catch (error) {
    console.error("application_save_failed", step, error?.name || "Error", error?.message || "unknown");
    return json({ error:"Falha interna ao salvar a inscrição.", code:"KV_WRITE_OR_ENCRYPTION_ERROR", diagnostic:{ stage:step, errorName:error?.name || "Error", build:BUILD_ID } }, 500);
  }
}
async function cryptoDiagnostic(request) {
  const iterations = Number(new URL(request.url).searchParams.get("iterations") || "100000");
  const allowedIterations = [1000, 10000, 50000, 100000, 100001, 101250, 102500, 105000, 110000, 125000, 135000, 150000, 200000, 310000];
  if (!allowedIterations.includes(iterations)) return json({ ok:false, build:BUILD_ID, error:"Use um valor permitido de iterações." }, 400);
  let stage = "pbkdf2-import";
  try {
    const password = new TextEncoder().encode("diagnostico-temporario-nao-usar-em-producao");
    const salt = new Uint8Array(16);
    salt.fill(7);
    const material = await crypto.subtle.importKey("raw", password, { name: "PBKDF2" }, false, ["deriveKey"]);
    stage = "pbkdf2-derive-key";
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    stage = "aes-gcm-encrypt";
    const iv = new Uint8Array(12);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode("teste"));
    stage = "aes-gcm-decrypt";
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
    if (new TextDecoder().decode(decrypted) !== "teste") throw new Error("ROUNDTRIP_MISMATCH");
    return json({ ok: true, build: BUILD_ID, iterations, crypto: "pbkdf2-and-aes-gcm-ok" });
  } catch (error) {
    return json({ ok: false, build: BUILD_ID, stage, errorName: error?.name || "Error" }, 500);
  }
}
async function candidateLogin(request, env) {
  if (!env.VESTIBULAR_KV) return json({ error:"Armazenamento KV não está configurado." }, 503);
  if (!sameOrigin(request)) return json({ error:"Origem não autorizada." }, 403);
  let body;
  try { body = await readBody(request); } catch { return json({ error:"Dados de acesso inválidos." }, 400); }
  const cpf = text(body.cpf,30).replace(/\D/g,"");
  const password = typeof body.password === "string" ? body.password : "";
  if (!validCpf(cpf) || password.length < 1 || password.length > 128) return json({ error:"CPF ou senha incorretos." }, 401);
  try {
    const protocol = await env.VESTIBULAR_KV.get("cpf:" + await sha256(cpf));
    if (!protocol) return json({ error:"CPF ou senha incorretos." }, 401);
    const stored = await env.VESTIBULAR_KV.get("application:" + protocol);
    if (!stored) return json({ error:"Inscrição não localizada. Procure o atendimento." }, 404);
    const application = await unseal(JSON.parse(stored), password);
    if (application.personal.cpf !== cpf) return json({ error:"CPF ou senha incorretos." }, 401);
    const { cpf: hiddenCpf, rg, ...personal } = application.personal;
    const updatedStatus = await env.VESTIBULAR_KV.get("application-status:" + protocol);
    return json({ ok:true, application:{ protocol:application.protocol, createdAt:application.createdAt, status:updatedStatus || application.status, personal, school:application.school, competitionType:application.competitionType, choices:application.choices } });
  } catch {
    return json({ error:"CPF ou senha incorretos." }, 401);
  }
}

async function authenticateCandidate(cpfInput, password, env) {
  const cpf = text(cpfInput,30).replace(/\D/g,"");
  if (!validCpf(cpf) || typeof password !== "string" || !password || password.length > 128) throw new Error("AUTH");
  const protocol = await env.VESTIBULAR_KV.get("cpf:" + await sha256(cpf));
  if (!protocol) throw new Error("AUTH");
  const stored = await env.VESTIBULAR_KV.get("application:" + protocol);
  if (!stored) throw new Error("AUTH");
  const application = await unseal(JSON.parse(stored), password);
  if (application.personal.cpf !== cpf) throw new Error("AUTH");
  return application;
}
async function candidateProof(request, env) {
  if (!env.VESTIBULAR_KV) return json({error:"Armazenamento de inscrições não está configurado."},503);
  if (!sameOrigin(request)) return json({error:"Origem não autorizada."},403);
  try {
    const form = await request.formData();
    const app = await authenticateCandidate(form.get("cpf"),form.get("password"),env);
    const file = form.get("proof");
    if (!(file instanceof File) || !file.size) return json({error:"Selecione um comprovante."},400);
    if (file.size > 5*1024*1024) return json({error:"O arquivo deve ter no máximo 5 MB."},413);
    const allowed = {"application/pdf":"pdf","image/jpeg":"jpg","image/png":"png"};
    const ext = allowed[file.type];
    if (!ext) return json({error:"Formato não permitido. Envie PDF, JPG ou PNG."},415);
    const bytes = new Uint8Array(await file.arrayBuffer());
    const fileBase64 = b64(bytes);
    // Arquivos de até 5 MB ficam abaixo do limite de 25 MiB por valor do Cloudflare KV.
    const fileKey = "payment-proof-file:" + app.protocol;
    await env.VESTIBULAR_KV.put(fileKey,fileBase64);
    const metaKey = "payment-proof-meta:"+app.protocol;
    const metadata = {protocol:app.protocol,fileKey,fileName:text(file.name,160),contentType:file.type,size:file.size,status:"Pendente",submittedAt:new Date().toISOString(),reviewedAt:null,reviewNote:"",storage:"kv"};
    await env.VESTIBULAR_KV.put(metaKey,JSON.stringify(metadata));
    return json({ok:true,proof:{status:metadata.status,fileName:metadata.fileName,submittedAt:metadata.submittedAt}});
  } catch(e) {
    if(e.message==="AUTH") return json({error:"CPF ou senha incorretos."},401);
    console.error("payment_proof_upload_failed",e?.name||"Error",e?.message||"unknown");
    return json({error:"Não foi possível salvar o comprovante no armazenamento do vestibular."},500);
  }
}
async function candidateProofStatus(request,env) {
  if(!env.VESTIBULAR_KV) return json({error:"Armazenamento indisponível."},503);
  try {
    const body=await request.json();
    const app=await authenticateCandidate(body.cpf,body.password,env);
    const proof=await env.VESTIBULAR_KV.get("payment-proof-meta:"+app.protocol,"json");
    return json({ok:true,proof:proof?{status:proof.status,fileName:proof.fileName,submittedAt:proof.submittedAt,reviewNote:proof.reviewNote||""}:null});
  } catch { return json({error:"CPF ou senha incorretos."},401); }
}
async function createAdminSession(request,env) {
  
  if (!sameOrigin(request)) return json({error:"Origem não autorizada."},403);
  let body; try { body=await readBody(request); } catch { return json({error:"Dados inválidos."},400); }
  if (body.id !== ADMIN_ID || typeof body.password !== "string" || await sha256(body.password) !== ADMIN_PASSWORD_HASH) return json({error:"ID ou senha incorretos."},401);
  const token=b64(random(32));
  await env.VESTIBULAR_KV.put("admin-session:"+await sha256(token),"1",{expirationTtl:28800});
  return json({ok:true,token,expiresIn:28800});
}
async function adminAuthorized(request,env) {
  const auth=request.headers.get("Authorization")||"";
  if (!auth.startsWith("Bearer ")) return false;
  const token=auth.slice(7);
  if (!token || token.length>200) return false;
  return !!(await env.VESTIBULAR_KV.get("admin-session:"+await sha256(token)));
}
async function adminApi(request,env) {
  if (!env.VESTIBULAR_KV) return json({error:"KV não configurado."},503);
  const url=new URL(request.url);
  if(url.pathname==="/api/admin/login"&&request.method==="POST") return createAdminSession(request,env);
  if(!(await adminAuthorized(request,env))) return json({error:"Sessão administrativa inválida ou expirada."},401);
  if(request.method==="GET"&&url.pathname==="/api/admin/applications") {
    const listed=await env.VESTIBULAR_KV.list({prefix:"admin-application:",limit:1000}),applications=[];
    for(const item of listed.keys) {
      try {
        const record=await env.VESTIBULAR_KV.get(item.name);
        if(!record) continue;
        const app=await unseal(JSON.parse(record),ADMIN_PASSWORD_HASH);
        const proof=await env.VESTIBULAR_KV.get("payment-proof-meta:"+app.protocol,"json");
        const status=await env.VESTIBULAR_KV.get("application-status:"+app.protocol);
        applications.push({...app,status:status||app.status,paymentProof:proof?{status:proof.status,fileName:proof.fileName,submittedAt:proof.submittedAt}:null});
      } catch(e) { console.error("admin_application_read_failed",item.name,e?.name||"Error"); }
    }
    applications.sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt)));
    return json({ok:true,applications});
  }
  if(request.method==="GET"&&url.pathname==="/api/admin/overview") {
    const listed=await env.VESTIBULAR_KV.list({prefix:"admin-application:",limit:1000});
    const total=listed.keys.length;
    const proofsListed=await env.VESTIBULAR_KV.list({prefix:"payment-proof-meta:",limit:1000});
    let pending=0,approved=0,rejected=0,proofTotal=0;
    for(const item of proofsListed.keys){const p=await env.VESTIBULAR_KV.get(item.name,"json");if(!p)continue;proofTotal++;if(p.status==="Pendente")pending++;if(p.status==="Aprovado")approved++;if(p.status==="Recusado")rejected++;}
    return json({ok:true,total,proofTotal,pending,approved,rejected});
  }
  const historyMatch=url.pathname.match(/^\/api\/admin\/applications\/([A-Za-z0-9-]+)\/history$/);
  if(request.method==="GET"&&historyMatch) {
    const history=await env.VESTIBULAR_KV.get("admin-history:"+historyMatch[1],"json")||[];
    return json({ok:true,history});
  }
  const notesMatch=url.pathname.match(/^\/api\/admin\/applications\/([A-Za-z0-9-]+)\/notes$/);
  if(request.method==="GET"&&notesMatch) {
    const notes=await env.VESTIBULAR_KV.get("admin-notes:"+notesMatch[1],"json")||[];
    return json({ok:true,notes});
  }
  if(request.method==="POST"&&notesMatch) {
    let body;try{body=await request.json();}catch{return json({error:"Dados inválidos."},400);}
    const note=text(body.note,1000);if(!note)return json({error:"Escreva uma observação."},400);
    const key="admin-notes:"+notesMatch[1],notes=await env.VESTIBULAR_KV.get(key,"json")||[];
    notes.unshift({note,createdAt:new Date().toISOString()});await env.VESTIBULAR_KV.put(key,JSON.stringify(notes.slice(0,100)));
    return json({ok:true});
  }
  if(request.method==="PATCH"&&url.pathname.startsWith("/api/admin/applications/")&&!url.pathname.endsWith("/history")&&!url.pathname.endsWith("/notes")) {
    const protocol=decodeURIComponent(url.pathname.split("/").pop());
    if(!/^UF2027-[A-F0-9]+$/.test(protocol)) return json({error:"Protocolo inválido."},400);
    let body;try{body=await request.json();}catch{return json({error:"Dados inválidos."},400);}
    const key="admin-application:"+protocol,record=await env.VESTIBULAR_KV.get(key);
    if(!record)return json({error:"Cadastro não disponível no painel administrativo."},404);
    let app;try{app=await unseal(JSON.parse(record),ADMIN_PASSWORD_HASH);}catch{return json({error:"Não foi possível abrir o cadastro."},500);}
    const changes=[];
    if(body.status!==undefined){
      const status=text(body.status,80),allowed=["Inscrição recebida","Pagamento pendente","Pagamento aprovado","Inscrição em análise","Aprovado","Reprovado","Classificado","Desclassificado"];
      if(!allowed.includes(status))return json({error:"Situação inválida."},400);
      const old=await env.VESTIBULAR_KV.get("application-status:"+protocol)||app.status;
      if(old!==status){await env.VESTIBULAR_KV.put("application-status:"+protocol,status);changes.push("Situação: "+old+" → "+status);}
    }
    if(body.personal&&typeof body.personal==="object"){
      for(const field of ["fullName","phone","email","rg","socialName","motherName","fatherName"]){
        if(body.personal[field]!==undefined){const value=text(body.personal[field],field==="email"?180:180);if(value!==app.personal[field]){changes.push(field+" atualizado");app.personal[field]=value;}}
      }
    }
    if(body.address&&typeof body.address==="object"){
      for(const field of ["cep","state","street","number","complement","neighborhood","city"]){
        if(body.address[field]!==undefined){const value=text(body.address[field],180);if(value!==app.address[field]){changes.push("Endereço: "+field+" atualizado");app.address[field]=value;}}
      }
    }
    if(Array.isArray(body.choices)&&body.choices.length>=1&&body.choices.length<=3){
      if(body.choices.every(c=>required(c.course)&&required(c.location)&&["Presencial","Semipresencial","Online (EAD)"].includes(c.mode))){
        app.choices=body.choices.map(c=>({course:text(c.course,180),location:text(c.location,120),mode:c.mode}));changes.push("Opções de curso atualizadas");
      }else return json({error:"Confira as opções de curso."},400);
    }
    if(changes.length){
      await env.VESTIBULAR_KV.put(key,JSON.stringify(await seal(app,ADMIN_PASSWORD_HASH)));
      const hkey="admin-history:"+protocol,history=await env.VESTIBULAR_KV.get(hkey,"json")||[];
      history.unshift({createdAt:new Date().toISOString(),changes});
      await env.VESTIBULAR_KV.put(hkey,JSON.stringify(history.slice(0,100)));
    }
    return json({ok:true,changes});
  }
  if(request.method==="PATCH"&&url.pathname.startsWith("/api/admin/applications/")) {
    const protocol=decodeURIComponent(url.pathname.split("/").pop());
    if(!/^UF2027-[A-F0-9]+$/.test(protocol)) return json({error:"Protocolo inválido."},400);
    let body;try{body=await request.json();}catch{return json({error:"Dados inválidos."},400);}
    const status=text(body.status,80),allowed=["Inscrição recebida","Pagamento pendente","Pagamento aprovado","Inscrição em análise","Aprovado","Reprovado","Classificado","Desclassificado"];
    if(!allowed.includes(status)) return json({error:"Situação inválida."},400);
    if(!(await env.VESTIBULAR_KV.get("admin-application:"+protocol))) return json({error:"Cadastro não disponível no painel administrativo."},404);
    await env.VESTIBULAR_KV.put("application-status:"+protocol,status);
    return json({ok:true,status});
  }
  if(request.method==="GET"&&url.pathname==="/api/admin/payment-proofs") {
    const listed=await env.VESTIBULAR_KV.list({prefix:"payment-proof-meta:",limit:1000}),proofs=[];
    for(const item of listed.keys){const p=await env.VESTIBULAR_KV.get(item.name,"json");if(p)proofs.push({protocol:p.protocol,fileName:p.fileName,size:p.size,status:p.status,submittedAt:p.submittedAt,reviewedAt:p.reviewedAt,reviewNote:p.reviewNote||""});}
    proofs.sort((a,b)=>String(b.submittedAt).localeCompare(String(a.submittedAt)));
    return json({ok:true,proofs});
  }
  const fileMatch=url.pathname.match(/^\/api\/admin\/payment-proofs\/([A-Za-z0-9-]+)\/file$/);
  if(request.method==="GET"&&fileMatch) {
    const p=await env.VESTIBULAR_KV.get("payment-proof-meta:"+fileMatch[1],"json");
    if(!p)return json({error:"Comprovante não encontrado."},404);
    if(p.storage==="kv"||p.fileKey) {
      const encoded=await env.VESTIBULAR_KV.get(p.fileKey||"payment-proof-file:"+fileMatch[1]);
      if(!encoded)return json({error:"Arquivo do comprovante não encontrado no KV."},404);
      const bytes=unb64(encoded),type=text(p.contentType||"application/octet-stream",100),name=text(p.fileName||"comprovante",160).replace(/["\\\r\n]/g,"_");
      return new Response(bytes,{headers:{"Content-Type":type,"Content-Disposition":'inline; filename="'+name+'"',"Cache-Control":"no-store"}});
    }
    if(p.objectKey&&env.PAYMENT_PROOFS){const obj=await env.PAYMENT_PROOFS.get(p.objectKey);if(!obj)return json({error:"Arquivo não encontrado."},404);const headers=new Headers();obj.writeHttpMetadata(headers);headers.set("Content-Disposition",'inline; filename="'+String(p.fileName).replace(/["\\\r\n]/g,"_")+'"');headers.set("Cache-Control","no-store");return new Response(obj.body,{headers});}
    return json({error:"Arquivo não encontrado."},404);
  }
  const proofStatus=url.pathname.match(/^\/api\/admin\/payment-proofs\/([A-Za-z0-9-]+)$/);
  if(request.method==="PATCH"&&proofStatus) {
    let body;try{body=await request.json();}catch{return json({error:"Dados inválidos."},400);}
    if(!["Aprovado","Recusado","Pendente"].includes(body.status))return json({error:"Status inválido."},400);
    const key="payment-proof-meta:"+proofStatus[1],p=await env.VESTIBULAR_KV.get(key,"json");
    if(!p)return json({error:"Comprovante não encontrado."},404);
    p.status=body.status;p.reviewNote=text(body.note,500);p.reviewedAt=new Date().toISOString();
    await env.VESTIBULAR_KV.put(key,JSON.stringify(p));
    return json({ok:true,status:p.status});
  }
  return json({error:"Rota administrativa não encontrada."},404);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/crypto-test" && request.method === "GET") return cryptoDiagnostic(request);
    if (url.pathname === "/api/health" && request.method === "GET") {
      return json({ ok:!!env.VESTIBULAR_KV, storage:env.VESTIBULAR_KV ? "kv-connected" : "kv-not-configured", d1Configured:!!env.DB, build:BUILD_ID, service:"Vestibular UniFil 2027" }, env.VESTIBULAR_KV ? 200 : 503);
    }
    if (url.pathname === "/api/applications" && request.method === "POST") return createApplication(request, env);
    if (url.pathname === "/api/candidate/login" && request.method === "POST") return candidateLogin(request, env);
    if (url.pathname === "/api/candidate/payment-proof" && request.method === "POST") return candidateProof(request, env);
    if (url.pathname === "/api/candidate/payment-proof/status" && request.method === "POST") return candidateProofStatus(request, env);
    if (url.pathname.startsWith("/api/admin/")) return adminApi(request, env);
    if (url.pathname.startsWith("/api/")) return json({ error:"Rota não encontrada." },404);
    return env.ASSETS.fetch(request);
  }
};