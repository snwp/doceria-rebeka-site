/* ============================================================
   API DO PAINEL — KON BOLOS
   ------------------------------------------------------------
   Antes, a equipe e o catálogo viviam no localStorage: tudo
   ficava preso no navegador de quem editou. Aqui os dois passam
   a morar no servidor (Netlify Blobs), então quem você cadastra
   entra de qualquer computador ou celular, e o que a equipe edita
   aparece para os clientes.

   Também é aqui que a permissão passa a valer de verdade: a
   checagem do navegador só esconde botão, esta aqui é a que conta.
   ============================================================ */

import { getStore, getDeployStore } from "@netlify/blobs";
import { createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";

/* O administrador geral é fixo: não pode ser removido nem rebaixado
   por ninguém. Dá pra trocar sem mexer no código definindo a variável
   de ambiente KON_ADMIN no painel do Netlify. */
const ADMIN_GERAL = (Netlify.env.get("KON_ADMIN") || "witor.lemos7@gmail.com").toLowerCase();

const CHAVES_PERMISSAO = ["editar", "fotos", "criar", "excluir", "equipe"];
const DIAS_DE_SESSAO   = 30;
const SENHA_MINIMA     = 6;

/* ------------------------------------------------------------
   Armazenamento
   Em produção usa o store global (os dados reais da loja). Em
   deploy preview usa um store do próprio deploy, pra teste nunca
   encostar no catálogo que está no ar.
   ------------------------------------------------------------ */
function loja(nome: string) {
  const producao = (Netlify as any).context?.deploy?.context === "production";
  const opcoes = { name: nome, consistency: "strong" as const };
  return producao ? getStore(opcoes) : getDeployStore(opcoes);
}

const dados = () => loja("konbolos");
const fotos = () => loja("konbolos-fotos");

/* ------------------------------------------------------------
   Segredo que assina as sessões
   Nasce sozinho no primeiro acesso e fica guardado. Se você definir
   KON_SEGREDO no Netlify, ele manda — trocar o valor derruba todas
   as sessões abertas, que é o jeito de "expulsar todo mundo".
   ------------------------------------------------------------ */
async function segredo(): Promise<string> {
  const doAmbiente = Netlify.env.get("KON_SEGREDO");
  if (doAmbiente) return doAmbiente;

  const store = dados();
  const guardado = await store.get("segredo");
  if (guardado) return guardado;

  const novo = randomBytes(32).toString("hex");
  await store.set("segredo", novo);
  return novo;
}

/* ------------------------------------------------------------
   Senhas — nunca guardadas em texto puro
   ------------------------------------------------------------ */
function embaralhar(senha: string, sal: string): string {
  return pbkdf2Sync(senha, sal, 120000, 32, "sha256").toString("hex");
}

function criarSenha(senha: string) {
  const sal = randomBytes(16).toString("hex");
  return { sal, hash: embaralhar(senha, sal) };
}

function senhaConfere(senha: string, registro: any): boolean {
  if (!registro || !registro.sal || !registro.hash) return false;
  const tentativa = Buffer.from(embaralhar(senha, registro.sal), "hex");
  const guardada  = Buffer.from(registro.hash, "hex");
  if (tentativa.length !== guardada.length) return false;
  return timingSafeEqual(tentativa, guardada);
}

/* ------------------------------------------------------------
   Sessão — um bilhete assinado que o navegador guarda
   ------------------------------------------------------------ */
const paraBase64url = (txt: string) => Buffer.from(txt, "utf8").toString("base64url");
const deBase64url   = (txt: string) => Buffer.from(txt, "base64url").toString("utf8");

async function assinarSessao(email: string) {
  const corpo  = JSON.stringify({ e: email, exp: Date.now() + DIAS_DE_SESSAO * 864e5 });
  const pacote = paraBase64url(corpo);
  const firma  = createHmac("sha256", await segredo()).update(pacote).digest("base64url");
  return pacote + "." + firma;
}

/* Devolve o e-mail de quem está logado, ou null. As permissões NÃO
   vêm do bilhete: são lidas na hora, para que tirar o acesso de
   alguém tenha efeito imediato, sem esperar a sessão vencer. */
async function donoDaSessao(token: unknown): Promise<string | null> {
  if (typeof token !== "string" || token.indexOf(".") < 1) return null;
  const [pacote, firma] = token.split(".");

  const esperada = createHmac("sha256", await segredo()).update(pacote).digest("base64url");
  const a = Buffer.from(firma || "", "utf8");
  const b = Buffer.from(esperada, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

  try {
    const corpo = JSON.parse(deBase64url(pacote));
    if (!corpo.exp || corpo.exp < Date.now()) return null;
    return String(corpo.e || "").toLowerCase() || null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   Equipe
   ------------------------------------------------------------ */
type Registro = { sal: string; hash: string };
type Pessoa   = { email: string; funcao: string; permissoes: Record<string, boolean>; senha?: Registro };
type Quadro   = { admin: Registro | null; pessoas: Pessoa[] };

async function lerEquipe(): Promise<Quadro> {
  const guardado = await dados().get("equipe", { type: "json" });
  if (!guardado) return { admin: null, pessoas: [] };
  return {
    admin: guardado.admin || null,
    pessoas: Array.isArray(guardado.pessoas) ? guardado.pessoas : []
  };
}

const gravarEquipe = (quadro: Quadro) => dados().setJSON("equipe", quadro);

const ehAdmin = (email: string) => email.toLowerCase() === ADMIN_GERAL;

const todasPermissoes = () =>
  Object.fromEntries(CHAVES_PERMISSAO.map(k => [k, true])) as Record<string, boolean>;

/* O que esse e-mail pode fazer hoje. null = não tem acesso nenhum. */
function permissoesDe(email: string, quadro: Quadro) {
  if (ehAdmin(email)) return { funcao: "Administrador geral", permissoes: todasPermissoes() };
  const p = quadro.pessoas.find(x => (x.email || "").toLowerCase() === email.toLowerCase());
  if (!p) return null;
  return { funcao: p.funcao || "Equipe", permissoes: p.permissoes || {} };
}

/* Só o que pode ir para o navegador: a senha embaralhada fica aqui. */
const limpar = (p: Pessoa) => ({
  email: p.email,
  funcao: p.funcao || "Equipe",
  permissoes: p.permissoes || {},
  temSenha: !!p.senha
});

/* ------------------------------------------------------------
   Catálogo
   ------------------------------------------------------------ */
async function lerCatalogo(): Promise<any[] | null> {
  const guardado = await dados().get("catalogo", { type: "json" });
  return Array.isArray(guardado) ? guardado : null;
}

/* Compara o catálogo que chegou com o que está gravado e diz qual
   permissão cada mudança exige. É isso que faz "pode editar mas não
   pode excluir" significar alguma coisa de verdade. */
function permissoesExigidas(antes: any[], depois: any[]): string[] {
  const exigidas = new Set<string>();
  const porId = (lista: any[]) => new Map(lista.map(p => [p.id, p]));
  const mapaAntes  = porId(antes);
  const mapaDepois = porId(depois);

  for (const id of mapaDepois.keys()) if (!mapaAntes.has(id))  exigidas.add("criar");
  for (const id of mapaAntes.keys())  if (!mapaDepois.has(id)) exigidas.add("excluir");

  const semFoto = (p: any) => { const c = { ...p }; delete c.img; return JSON.stringify(c); };

  for (const [id, novo] of mapaDepois) {
    const velho = mapaAntes.get(id);
    if (!velho) continue;
    if ((velho.img || "") !== (novo.img || "")) exigidas.add("fotos");
    if (semFoto(velho) !== semFoto(novo))       exigidas.add("editar");
  }
  return [...exigidas];
}

/* ------------------------------------------------------------
   Respostas
   ------------------------------------------------------------ */
const json = (corpo: any, status = 200) =>
  new Response(JSON.stringify(corpo), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
  });

const erro = (mensagem: string, status = 400) => json({ erro: mensagem }, status);

/* ============================================================
   ENTRADA
   ============================================================ */
export default async (req: Request) => {
  const caminho = new URL(req.url).pathname;

  /* ---------- fotos ---------- */
  if (caminho.startsWith("/api/foto/")) {
    if (req.method !== "GET") return erro("Método não suportado", 405);

    const chave = decodeURIComponent(caminho.slice("/api/foto/".length));
    const arquivo = await fotos().getWithMetadata(chave, { type: "arrayBuffer" });
    if (!arquivo) return new Response("Foto não encontrada", { status: 404 });

    return new Response(arquivo.data, {
      headers: {
        "content-type": String((arquivo.metadata as any)?.tipo || "image/jpeg"),
        // a chave é única por upload, então essa foto nunca muda de conteúdo
        "cache-control": "public, max-age=31536000, immutable"
      }
    });
  }

  /* ---------- catálogo público: é o que o cliente vê ---------- */
  if (caminho === "/api/catalogo" && req.method === "GET") {
    return json({ lista: await lerCatalogo() });
  }

  if (req.method !== "POST") return erro("Método não suportado", 405);

  let corpo: any;
  try { corpo = await req.json(); } catch { return erro("Pedido inválido"); }

  /* ---------- envio de foto ---------- */
  if (caminho === "/api/foto") {
    const quem = await donoDaSessao(corpo.token);
    if (!quem) return erro("Sessão expirada. Entre de novo.", 401);

    const acessoFoto = permissoesDe(quem, await lerEquipe());
    if (!acessoFoto || !(acessoFoto.permissoes.fotos || acessoFoto.permissoes.criar)) {
      return erro("Você não tem permissão pra trocar fotos.", 403);
    }

    const dataUrl = String(corpo.dataUrl || "");
    const parte = dataUrl.match(/^data:(image\/[a-z+.-]+);base64,(.+)$/i);
    if (!parte) return erro("Formato de imagem não reconhecido.");

    const bytes = Buffer.from(parte[2], "base64");
    if (bytes.length > 4 * 1024 * 1024) return erro("Essa foto é grande demais. Use uma menor.");

    const extensao = parte[1] === "image/png" ? "png" : parte[1] === "image/webp" ? "webp" : "jpg";
    const chave = randomBytes(12).toString("hex") + "." + extensao;
    await fotos().set(chave, bytes, { metadata: { tipo: parte[1] } });

    return json({ url: "/api/foto/" + chave });
  }

  if (caminho !== "/api/painel") return erro("Endereço desconhecido", 404);

  const acao = String(corpo.acao || "");
  const quadro = await lerEquipe();

  /* ---------- primeiro acesso: o admin cria a própria senha ---------- */
  if (acao === "estado") {
    return json({ precisaCriarSenha: !quadro.admin, admin: ADMIN_GERAL });
  }

  if (acao === "criar-senha-admin") {
    if (quadro.admin) return erro("A senha do administrador já foi criada.", 409);

    const senha = String(corpo.senha || "");
    if (senha.length < SENHA_MINIMA) return erro("A senha precisa de pelo menos " + SENHA_MINIMA + " caracteres.");

    quadro.admin = criarSenha(senha);
    await gravarEquipe(quadro);

    return json({
      token: await assinarSessao(ADMIN_GERAL),
      email: ADMIN_GERAL,
      funcao: "Administrador geral",
      permissoes: todasPermissoes()
    });
  }

  /* ---------- entrar ---------- */
  if (acao === "entrar") {
    const alvo  = String(corpo.email || "").trim().toLowerCase();
    const senha = String(corpo.senha || "");
    const recusa = () => erro("E-mail ou senha não conferem.", 401);

    if (ehAdmin(alvo)) {
      if (!quadro.admin) return erro("A senha do administrador ainda não foi criada.", 409);
      if (!senhaConfere(senha, quadro.admin)) return recusa();
      return json({
        token: await assinarSessao(alvo),
        email: alvo,
        funcao: "Administrador geral",
        permissoes: todasPermissoes()
      });
    }

    const pessoa = quadro.pessoas.find(p => (p.email || "").toLowerCase() === alvo);
    if (!pessoa || !senhaConfere(senha, pessoa.senha)) return recusa();

    return json({
      token: await assinarSessao(alvo),
      email: alvo,
      funcao: pessoa.funcao || "Equipe",
      permissoes: pessoa.permissoes || {}
    });
  }

  /* Daqui pra baixo, tudo exige estar logado. */
  const email = await donoDaSessao(corpo.token);
  if (!email) return erro("Sessão expirada. Entre de novo.", 401);

  const acesso = permissoesDe(email, quadro);
  if (!acesso) return erro("Seu acesso foi removido.", 403);

  const pode = (chave: string) => !!acesso.permissoes[chave];

  /* ---------- confirmar a sessão ao abrir a página ---------- */
  if (acao === "sessao") {
    return json({ email, funcao: acesso.funcao, permissoes: acesso.permissoes });
  }

  /* ---------- trocar a própria senha ---------- */
  if (acao === "trocar-minha-senha") {
    const atual = String(corpo.senhaAtual || "");
    const nova  = String(corpo.senhaNova || "");
    if (nova.length < SENHA_MINIMA) return erro("A senha nova precisa de pelo menos " + SENHA_MINIMA + " caracteres.");

    if (ehAdmin(email)) {
      if (!senhaConfere(atual, quadro.admin)) return erro("A senha atual não confere.", 403);
      quadro.admin = criarSenha(nova);
    } else {
      const pessoa = quadro.pessoas.find(p => (p.email || "").toLowerCase() === email);
      if (!pessoa || !senhaConfere(atual, pessoa.senha)) return erro("A senha atual não confere.", 403);
      pessoa.senha = criarSenha(nova);
    }

    await gravarEquipe(quadro);
    return json({ ok: true });
  }

  /* ---------- painel da equipe ---------- */
  if (acao === "equipe-listar") {
    if (!pode("equipe")) return erro("Você não tem permissão pra ver a equipe.", 403);
    return json({ pessoas: quadro.pessoas.map(limpar) });
  }

  if (acao === "equipe-salvar") {
    if (!pode("equipe")) return erro("Você não tem permissão pra mexer na equipe.", 403);

    const alvo = String(corpo.email || "").trim().toLowerCase();
    if (!alvo || alvo.indexOf("@") < 1) return erro("Coloque um e-mail válido.");
    if (ehAdmin(alvo)) return erro("Esse é o administrador geral — o acesso dele é fixo.");

    const permissoes: Record<string, boolean> = {};
    CHAVES_PERMISSAO.forEach(k => { if (corpo.permissoes && corpo.permissoes[k]) permissoes[k] = true; });

    const senha = String(corpo.senha || "");
    if (senha && senha.length < SENHA_MINIMA) return erro("A senha precisa de pelo menos " + SENHA_MINIMA + " caracteres.");

    const i = quadro.pessoas.findIndex(p => (p.email || "").toLowerCase() === alvo);

    if (i < 0) {
      // pessoa nova sem senha não conseguiria entrar de lugar nenhum
      if (!senha) return erro("Defina uma senha pra essa pessoa poder entrar.");
      quadro.pessoas.push({
        email: alvo,
        funcao: String(corpo.funcao || "").trim() || "Equipe",
        permissoes,
        senha: criarSenha(senha)
      });
    } else {
      quadro.pessoas[i].funcao = String(corpo.funcao || "").trim() || "Equipe";
      quadro.pessoas[i].permissoes = permissoes;
      if (senha) quadro.pessoas[i].senha = criarSenha(senha);
    }

    await gravarEquipe(quadro);
    return json({ pessoas: quadro.pessoas.map(limpar), criada: i < 0 });
  }

  if (acao === "equipe-remover") {
    if (!pode("equipe")) return erro("Você não tem permissão pra mexer na equipe.", 403);

    const alvo = String(corpo.email || "").trim().toLowerCase();
    if (ehAdmin(alvo)) return erro("O administrador geral não pode ser removido.");

    quadro.pessoas = quadro.pessoas.filter(p => (p.email || "").toLowerCase() !== alvo);
    await gravarEquipe(quadro);
    return json({ pessoas: quadro.pessoas.map(limpar) });
  }

  /* ---------- catálogo ---------- */
  if (acao === "catalogo-salvar") {
    const nova = corpo.lista;
    if (!Array.isArray(nova)) return erro("Catálogo inválido.");
    if (JSON.stringify(nova).length > 2 * 1024 * 1024) return erro("Catálogo grande demais.");

    // sem nada gravado ainda, o ponto de partida é o catálogo de fábrica
    const atual = (await lerCatalogo()) || (Array.isArray(corpo.padrao) ? corpo.padrao : []);
    const faltando = permissoesExigidas(atual, nova).filter(k => !pode(k));

    if (faltando.length) {
      const nomes: Record<string, string> = {
        editar:  "editar produtos",
        fotos:   "trocar fotos",
        criar:   "adicionar produtos",
        excluir: "excluir produtos"
      };
      return erro("Você não tem permissão pra " + faltando.map(k => nomes[k] || k).join(" e ") + ".", 403);
    }

    await dados().setJSON("catalogo", nova);
    return json({ ok: true });
  }

  if (acao === "catalogo-restaurar") {
    if (!pode("editar")) return erro("Você não tem permissão pra restaurar o catálogo.", 403);
    await dados().delete("catalogo");
    return json({ ok: true });
  }

  return erro("Ação desconhecida", 404);
};

export const config = {
  path: ["/api/painel", "/api/catalogo", "/api/foto", "/api/foto/:chave"]
};
