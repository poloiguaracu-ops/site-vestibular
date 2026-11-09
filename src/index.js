const json = (data, status = 200) => Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
const text = (value, max = 250) => typeof value === "string" ? value.trim().slice(0, max) : "";
const required = (value) => typeof value === "string" && value.trim().length > 0;
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const hex = (bytes) => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, "0")).join("");
const random = (n = 16) => crypto.getRandomValues(new Uint8Array(n));

async function hmacHex(secret, value) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}
async function encryptValue(secret, value) {
  const raw = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error("DATA_ENCRYPTION_KEY deve conter uma chave base64 de 32 bytes.");
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = random(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return "v1." + b64(iv) + "." + b64(encrypted);
}
async function passwordHash(password) {
  const salt = random(16);
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, material, 256);
  return "pbkdf2-sha256$310000$" + b64(salt) + "$" + b64(bits);
}
function validCpf(value) {
  const cpf = value.replace(/\D/g, "");
  if (!/^\d{11}$/.test(cpf) || /^(\d)\1{10}$/.test(cpf)) return false;
  const calc = (base, factor) => { let sum = 0; for (const digit of base) sum += Number(digit) * factor--; const r = (sum * 10) % 11; return r === 10 ? 0 : r; };
  return calc(cpf.slice(0,9),10) === Number(cpf[9]) && calc(cpf.slice(0,10),11) === Number(cpf[10]);
}
function validEmail(value) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }

async function createApplication(request, env) {
  if (!env.DB) return json({ error: "Banco de dados não configurado." }, 503);
  if (!env.CPF_HASH_KEY || !env.DATA_ENCRYPTION_KEY) return json({ error: "A configuração segura do sistema ainda não foi concluída. Nenhum dado foi registrado." }, 503);
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) return json({ error: "Origem não autorizada." }, 403);
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 20000) return json({ error: "Formulário muito grande." }, 413);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Envie os dados em formato válido." }, 400); }
  const p = body.personal || {}, address = body.address || {}, school = body.school || {};
  const cpf = text(p.cpf, 30).replace(/\D/g, "");
  const email = text(p.email, 180).toLowerCase();
  const password = typeof body.password === "string" ? body.password : "";
  const requiredValues = [p.fullName,p.rg,p.birthDate,p.sex,p.nationality,p.motherName,address.cep,address.state,address.street,address.number,address.neighborhood,address.city,p.phone,email,school.name,school.completionYear,school.type,body.competitionType];
  if (!requiredValues.every(required) || !validCpf(cpf) || !validEmail(email) || password.length < 10 || password.length > 128) {
    return json({ error: "Confira os campos obrigatórios, o CPF, o e-mail e a senha (mínimo de 10 caracteres)." }, 400);
  }
  if (!["Ampla concorrência","Cotas"].includes(body.competitionType)) return json({ error: "Modalidade de concorrência inválida." }, 400);
  const choices = Array.isArray(body.choices) ? body.choices : [];
  if (choices.length < 1 || choices.length > 3 || choices.some(c => !required(c.course) || !required(c.location) || !["Presencial","Semipresencial","Online (EAD)"].includes(c.mode))) {
    return json({ error: "Informe de uma a três opções de curso com local e modalidade." }, 400);
  }
  if (new Set(choices.map(c => text(c.course,180).toLowerCase())).size !== choices.length) return json({ error: "Não repita o mesmo curso nas opções." }, 400);
  const id = crypto.randomUUID();
  const applicationId = crypto.randomUUID();
  const protocol = "UF2027-" + hex(random(5)).toUpperCase();
  try {
    const cpfHash = await hmacHex(env.CPF_HASH_KEY, cpf);
    const [cpfEncrypted, rgEncrypted, passHash] = await Promise.all([
      encryptValue(env.DATA_ENCRYPTION_KEY, cpf),
      encryptValue(env.DATA_ENCRYPTION_KEY, text(p.rg,60)),
      passwordHash(password)
    ]);
    const statements = [
      env.DB.prepare(`INSERT INTO candidates (id,full_name,cpf_lookup_hash,cpf_encrypted,rg_encrypted,birth_date,sex,social_name,nationality,mother_name,father_name,cep,state,street,street_number,complement,neighborhood,city,phone,email,school_name,high_school_completion_year,school_type,password_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .bind(id,text(p.fullName,180),cpfHash,cpfEncrypted,rgEncrypted,text(p.birthDate,10),text(p.sex,40),text(p.socialName,180)||null,text(p.nationality,80),text(p.motherName,180),text(p.fatherName,180)||null,text(address.cep,12),text(address.state,2).toUpperCase(),text(address.street,180),text(address.number,30),text(address.complement,100)||null,text(address.neighborhood,100),text(address.city,100),text(p.phone,30),email,text(school.name,180),Number(school.completionYear),text(school.type,30),passHash),
      env.DB.prepare("INSERT INTO applications (id,protocol,candidate_id,competition_type) VALUES (?,?,?,?)").bind(applicationId,protocol,id,body.competitionType),
      ...choices.map((c,i)=>env.DB.prepare("INSERT INTO application_choices (application_id,preference_order,course_name,study_location,study_mode) VALUES (?,?,?,?,?)").bind(applicationId,i+1,text(c.course,180),text(c.location,120),c.mode))
    ];
    await env.DB.batch(statements);
    return json({ ok: true, protocol, message: "Inscrição registrada. Guarde seu protocolo." }, 201);
  } catch (error) {
    if (String(error?.message || "").includes("UNIQUE")) return json({ error: "Já existe uma inscrição com este CPF. Se você já se inscreveu, procure a equipe do vestibular." }, 409);
    return json({ error: "Não foi possível concluir a inscrição. Tente novamente ou procure o atendimento." }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health" && request.method === "GET") {
      try {
        const result = await env.DB.prepare("SELECT 1 AS connected").first();
        return json({ ok: true, database: result?.connected === 1 ? "connected" : "unavailable", service: "Vestibular UniFil 2027" });
      } catch { return json({ ok: false, database: "error", message: "Não foi possível consultar o banco de dados." }, 503); }
    }
    if (url.pathname === "/api/applications" && request.method === "POST") return createApplication(request, env);
    if (url.pathname.startsWith("/api/")) return json({ error: "Rota não encontrada." }, 404);
    return env.ASSETS.fetch(request);
  }
};
