import "./style.css";
import { PasswordNeeded, open, signatureFields } from "./pdf.ts";
import { stamp } from "./stamp.ts";
import { check, parsePem } from "./verify.ts";

type TrustedSigner = { signer: string; issuer: string; fingerprint: string };

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const TRUST_KEY = "sigprint.trusted";

const asset = async (file: string) => {
  const response = await fetch(`${import.meta.env.BASE_URL}assets/${file}`);
  if (!response.ok) throw new Error(`missing assets/${file}`);
  return response;
};
const roots = asset("roots.pem").then(async (r) => parsePem(await r.text()));
const intermediates = asset("intermediates.pem").then(async (r) => parsePem(await r.text()));
const font = asset("nimbus-sans.ttf").then(async (r) => new Uint8Array(await r.arrayBuffer()));

const trusted = (): TrustedSigner[] => JSON.parse(localStorage.getItem(TRUST_KEY) ?? "[]");
const saveTrusted = (list: TrustedSigner[]) => {
  localStorage.setItem(TRUST_KEY, JSON.stringify(list));
  renderTrusted();
};

let outputUrl: string | undefined;

/** Show a modal and resolve with whether it was confirmed. */
function ask(id: string): Promise<boolean> {
  const dialog = $<HTMLDialogElement>(id);
  dialog.returnValue = "cancel";
  dialog.showModal();
  return new Promise((resolve) => dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok"), { once: true }));
}

function showDrop(message?: string) {
  $("result").hidden = true;
  $("drop").hidden = false;
  $("message").textContent = message ?? "";
  $("message").hidden = !message;
  renderTrusted();
}

function renderTrusted() {
  const list = trusted();
  $("signers").textContent = `Trusted signers (${list.length})`;
  $("signers").hidden = list.length === 0 || $("drop").hidden;
  $("trustlist").replaceChildren(
    ...list.map((t) => {
      const li = document.createElement("li");
      const text = document.createElement("span");
      text.textContent = t.signer;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove";
      remove.onclick = () => saveTrusted(trusted().filter((x) => x.fingerprint !== t.fingerprint));
      li.append(text, remove);
      return li;
    }),
  );
}

async function unlock(bytes: Uint8Array<ArrayBuffer>, fileName: string) {
  $("unlockname").textContent = fileName;
  for (let password: string | null = null; ; ) {
    try {
      return await open(bytes, password);
    } catch (error) {
      if (!(error instanceof PasswordNeeded)) throw error;
    }
    $("wrong").hidden = password === null;
    $<HTMLInputElement>("password").value = "";
    if (!(await ask("unlock"))) return null;
    password = $<HTMLInputElement>("password").value;
  }
}

async function openFile(file: File | undefined) {
  if (!file) return;
  showDrop();
  const fail = (message: string) => showDrop(`${file.name}: ${message}`);
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const doc = await unlock(bytes, file.name);
    if (!doc) return showDrop();
    const fields = signatureFields(doc);
    if (fields.length === 0) return fail("no digital signature in this PDF.");

    for (;;) {
      const results = await check(bytes, fields, {
        roots: await roots,
        intermediates: await intermediates,
        signers: trusted().map((t) => t.fingerprint),
      });
      if (results.some((r) => !r.intact)) return fail("signature invalid. The file was changed after signing or is damaged.");
      const stranger = results.find((r) => !r.trusted);
      if (!stranger) {
        if (!results.every((r) => r.valid)) return fail("content was added after it was signed.");
        const { pdf } = await stamp(doc, await font);
        if (outputUrl) URL.revokeObjectURL(outputUrl);
        outputUrl = URL.createObjectURL(new Blob([new Uint8Array(pdf)], { type: "application/pdf" }));
        $<HTMLIFrameElement>("preview").src = outputUrl;
        $<HTMLAnchorElement>("download").href = outputUrl;
        $<HTMLAnchorElement>("download").download = `${file.name.replace(/\.pdf$/i, "")}.verified.pdf`;
        $("verdict").textContent = `✓ Signed by ${results.map((r) => r.signer).join(", ")}`;
        $("verdict").title = results.map((r) => `${r.signer}\nIssued by ${r.issuer}\n${r.signedAt?.toLocaleString() ?? ""}\n${r.note}`).join("\n\n");
        $<HTMLAnchorElement>("openpdf").href = outputUrl;
        $("drop").hidden = true;
        $("signers").hidden = true;
        $("result").hidden = false;
        return;
      }
      $("trustsigner").textContent = stranger.signer;
      $("trustissuer").textContent = stranger.issuer;
      if (!(await ask("trust"))) return fail("signer not trusted.");
      saveTrusted([...trusted(), { signer: stranger.signer, issuer: stranger.issuer, fingerprint: stranger.fingerprint }]);
    }
  } catch (error) {
    console.error(error);
    fail(error instanceof Error ? error.message : String(error));
  }
}

const picker = $<HTMLInputElement>("file");
picker.onchange = () => {
  void openFile(picker.files?.[0]);
  picker.value = "";
};
$("another").onclick = () => picker.click();
$("print").onclick = () => $<HTMLIFrameElement>("preview").contentWindow?.print();
$("signers").onclick = () => $<HTMLDialogElement>("signerlist").showModal();
// Cancel is a plain button so that Enter submits the form instead of hitting Cancel first
for (const cancel of document.querySelectorAll<HTMLButtonElement>("dialog .cancel")) cancel.onclick = () => cancel.closest("dialog")?.close("cancel");

// phones mostly can't show a PDF inside the page; hand the file to the system viewer instead, which can print it
if (!navigator.pdfViewerEnabled) {
  $("result").classList.add("bare");
  $("preview").hidden = true;
  $("print").hidden = true;
  $("openpdf").hidden = false;
}

// the whole window is the drop target; the overlay also shields the PDF preview, which would otherwise swallow the drop
window.addEventListener("dragenter", (e) => {
  if (e.dataTransfer?.types.includes("Files")) $("overlay").hidden = false;
});
$("overlay").ondragleave = () => ($("overlay").hidden = true);
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => {
  e.preventDefault();
  $("overlay").hidden = true;
  void openFile(e.dataTransfer?.files[0]);
});

showDrop();
