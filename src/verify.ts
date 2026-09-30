import * as pkijs from "pkijs";
import type { SignatureField } from "./pdf.ts";

export type Trust = {
  roots: pkijs.Certificate[];
  /** Only help build a path to a root for PDFs that don't embed their chain; never trusted themselves. */
  intermediates: pkijs.Certificate[];
  /** SHA-256 fingerprints of signer certificates the user trusted by hand. */
  signers: string[];
};

export type SignatureResult = {
  field: string;
  signer: string;
  issuer: string;
  signedAt: Date | null;
  intact: boolean;
  coversWholeFile: boolean;
  trusted: boolean;
  valid: boolean;
  note: string;
  fingerprint: string;
};

export function parsePem(pem: string): pkijs.Certificate[] {
  return [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map(([, body]) =>
    pkijs.Certificate.fromBER(Uint8Array.from(atob(body.replace(/\s+/g, "")), (c) => c.charCodeAt(0))),
  );
}

const commonName = (dn: pkijs.RelativeDistinguishedNames) =>
  String(dn.typesAndValues.find((t) => t.type === "2.5.4.3")?.value.valueBlock.value ?? "unknown");

async function fingerprint(cert: pkijs.Certificate) {
  const digest = await crypto.subtle.digest("SHA-256", cert.toSchema().toBER(false));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The signed bytes and the CMS blob sitting in the gap between them, or null when the range does not frame the signature. */
function split(file: Uint8Array, [a, b, c, d]: number[]) {
  const gap = new TextDecoder("latin1").decode(file.subarray(a + b, c));
  if (a !== 0 || c + d > file.length || !/^<[0-9a-fA-F\s]*>$/.test(gap)) return null;
  const hex = gap.slice(1, -1).replace(/\s+/g, "");
  const cms = Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
  const signed = new Uint8Array(b + d);
  signed.set(file.subarray(a, a + b));
  signed.set(file.subarray(c, c + d), b);
  return { cms, signed, coversWholeFile: c + d === file.length };
}

async function chains(signer: pkijs.Certificate, embedded: pkijs.Certificate[], trust: Trust, at: Date) {
  if (at < signer.notBefore.value || at > signer.notAfter.value) return false;
  if (trust.signers.includes(await fingerprint(signer))) return true;
  const engine = new pkijs.CertificateChainValidationEngine({
    trustedCerts: trust.roots,
    certs: [...trust.intermediates, ...embedded.filter((c) => c !== signer), signer],
    checkDate: at,
  });
  return (await engine.verify()).result;
}

export async function check(file: Uint8Array, fields: SignatureField[], trust: Trust): Promise<SignatureResult[]> {
  const results: SignatureResult[] = [];
  for (const { field, byteRange, contents, signedAt } of fields) {
    const framed = split(file, byteRange);
    const content = pkijs.ContentInfo.fromBER(framed?.cms ?? contents);
    const data = new pkijs.SignedData({ schema: content.content });
    const embedded = (data.certificates ?? []).filter((c) => c instanceof pkijs.Certificate);
    const { sid } = data.signerInfos[0];
    const signer = embedded.find(
      (c) => sid instanceof pkijs.IssuerAndSerialNumber && c.issuer.isEqual(sid.issuer) && c.serialNumber.isEqual(sid.serialNumber),
    );
    if (!signer) throw new Error("the signature does not embed its signer certificate");

    const intact = framed ? await data.verify({ signer: 0, data: framed.signed.buffer, checkChain: false }).catch(() => false) : false;

    let trusted = false;
    let note = "";
    if (intact) {
      const now = new Date();
      trusted = await chains(signer, embedded, trust, now);
      if (!trusted && signedAt && signer.notAfter.value < now) {
        // Acrobat's default: judge the certificate at the time the signature was created
        trusted = await chains(signer, embedded, trust, signedAt);
        note = "signer certificate has since expired; validated as of signing time";
      }
    }
    results.push({
      field,
      signer: commonName(signer.subject),
      issuer: commonName(signer.issuer),
      signedAt,
      intact,
      coversWholeFile: framed?.coversWholeFile ?? false,
      trusted,
      valid: false,
      note: trusted ? note : "",
      fingerprint: await fingerprint(signer),
    });
  }
  // earlier signatures legitimately stop short of later ones, but something intact must cover the final file
  const covered = results.some((r) => r.intact && r.coversWholeFile);
  return results.map((r) => ({ ...r, valid: r.intact && r.trusted && covered }));
}
