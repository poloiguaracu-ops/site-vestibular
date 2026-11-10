const json = (data, status = 200) => Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
const text = (value, max = 250) => typeof value === "string" ? value.trim().slice(0, max) : "";
const required = value => typeof value === "string" && value.trim().length > 0;
const random = n => crypto.getRandomValues(new Uint8Array(n));
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
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
async function passwordKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(data, password) {
  const salt = random(16), iv = random(12), key = await passwordKey(password, salt);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(data)));
  return { version: 1, salt: b64(salt), iv: b64(iv), cipher: b64(cipher) };
}
async function unseal(record, password) {
  const key = await passwordKey(password, unb64(record.salt));
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
  try {
    if (await env.VESTIBULAR_KV.get(cpfKey)) return json({ error: "Já existe uma inscrição com este CPF. Se você já se inscreveu, acesse a Área do Candidato." }, 409);
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
    const encrypted = await seal(application, password);
    await env.VESTIBULAR_KV.put("application:" + protocol, JSON.stringify(encrypted));
    await env.VESTIBULAR_KV.put(cpfKey, protocol);
    return json({ ok:true, protocol, message:"Inscrição de teste registrada. Guarde seu protocolo." }, 201);
  } catch (error) {
    console.error("application_save_failed", error?.name || "Error", error?.message || "unknown");
    return json({ error:"Falha interna ao salvar a inscrição. Consulte os registros do Worker.", code:"KV_WRITE_OR_ENCRYPTION_ERROR" }, 500);
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
    return json({ ok:true, application:{ protocol:application.protocol, createdAt:application.createdAt, status:application.status, personal, school:application.school, competitionType:application.competitionType, choices:application.choices } });
  } catch {
    return json({ error:"CPF ou senha incorretos." }, 401);
  }
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health" && request.method === "GET") {
      return env.VESTIBULAR_KV ? json({ ok:true, storage:"kv-connected", service:"Vestibular UniFil 2027" }) : json({ ok:false, storage:"not-configured", service:"Vestibular UniFil 2027" },503);
    }
    if (url.pathname === "/api/applications" && request.method === "POST") return createApplication(request, env);
    if (url.pathname === "/api/candidate/login" && request.method === "POST") return candidateLogin(request, env);
    if (url.pathname.startsWith("/api/")) return json({ error:"Rota não encontrada." },404);
    return env.ASSETS.fetch(request);
  }
};