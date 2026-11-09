const courses = ["Acupuntura","Administração","Análise e Desenvolvimento de Sistemas","Banco de Dados","Ciências Contábeis","Ciência de Dados e Inteligência Artificial","Ciências Econômicas","Comércio Exterior","Comunicação Social – Publicidade e Propaganda","Desenvolvimento e Gestão de Startups","Educação Especial e Inclusiva","Engenharia de Software","Estudos Psicanalíticos e Sociais","Geografia","Gestão Comercial","Gestão do Esporte e Alto Rendimento","Gestão Financeira","Gestão Pública","Gestão de Recursos Humanos","História","Inteligência Artificial","Internet das Coisas","Letras – Inglês/Português","Logística","Marketing","Matemática","Mídias Sociais Digitais","Ministério Pastoral","Pedagogia","Pedagogia (Magistério)","Processos Gerenciais","Relações Internacionais","Segurança Cibernética","Sociologia","Tecnologia em Jogos Digitais","Teologia","Ciências Biológicas","Massoterapia","Educação Física","Artes Visuais","Podologia","Estudos Teóricos Psicanalíticos e Sociais (Psicanálise)","Estética e Cosmética"];
const grid = document.querySelector("#course-grid");
const search = document.querySelector("#course-search");
const count = document.querySelector("#course-count");
function renderCourses(query = "") {
  const filtered = courses.filter(course => course.toLocaleLowerCase("pt-BR").includes(query.toLocaleLowerCase("pt-BR")));
  grid.innerHTML = filtered.map(course => '<div class="course-item"></div>').join("");
  [...grid.children].forEach((el, i) => el.textContent = filtered[i]);
  count.textContent = query ? `${filtered.length} curso(s) encontrado(s)` : `${courses.length} opções previstas`;
}
renderCourses();
search.addEventListener("input", e => renderCourses(e.target.value));
const toggle = document.querySelector(".menu-toggle");
const nav = document.querySelector(".main-nav");
toggle.addEventListener("click", () => { const open = nav.classList.toggle("open"); toggle.setAttribute("aria-expanded", String(open)); });
nav.querySelectorAll("a").forEach(link => link.addEventListener("click", () => { nav.classList.remove("open"); toggle.setAttribute("aria-expanded","false"); }));