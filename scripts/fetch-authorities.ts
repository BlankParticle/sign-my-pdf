// Refresh public/assets/roots.pem and intermediates.pem from the certificates published on cca.gov.in.
//
// Self-signed certificates become trust roots. Everything else is kept only if its signature chains
// to one of those roots, and is used for path building, never as a trust anchor.
//
//   node scripts/fetch-authorities.ts

import { writeFileSync } from "node:fs";
import * as pkijs from "pkijs";

const SITE = "https://cca.gov.in/";
const PAGES = ["root_certificate.html", ...["2022", "2022_SPL", "2015", "2014", "2011", "2007", "_under"].map((p) => `display_cert${p}.php`)];
const ASSETS = new URL("../public/assets/", import.meta.url);

/** The site serves DER, PEM, bare base64 and PKCS#7 under the same extensions. */
function parse(raw: Buffer): pkijs.Certificate[] {
  const text = raw.toString("latin1");
  const pems = [...text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map(([, body]) => Buffer.from(body, "base64"));
  for (const der of pems.length ? pems : [raw, Buffer.from(text, "base64")]) {
    try {
      if (pems.length) return pems.map((pem) => pkijs.Certificate.fromBER(pem));
      return [pkijs.Certificate.fromBER(der)];
    } catch {}
    try {
      const signed = new pkijs.SignedData({ schema: pkijs.ContentInfo.fromBER(der).content });
      const certs = (signed.certificates ?? []).filter((c) => c instanceof pkijs.Certificate);
      if (certs.length) return certs;
    } catch {}
  }
  return [];
}

const der = (cert: pkijs.Certificate) => Buffer.from(cert.toSchema().toBER(false));
const subject = (cert: pkijs.Certificate) => cert.subject.typesAndValues.map((t) => `${t.type}=${t.value.valueBlock.value}`).join(",");
const commonName = (cert: pkijs.Certificate) => String(cert.subject.typesAndValues.find((t) => t.type === "2.5.4.3")?.value.valueBlock.value);
const pem = (certs: pkijs.Certificate[]) =>
  certs
    .toSorted((a, b) => subject(a).localeCompare(subject(b)) || der(a).compare(der(b)))
    .map((c) => `-----BEGIN CERTIFICATE-----\n${der(c).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`)
    .join("");

const issuedBy = async (cert: pkijs.Certificate, issuer: pkijs.Certificate) =>
  cert.issuer.isEqual(issuer.subject) && (await cert.verify(issuer).catch(() => false));

// the site drops connections now and then
async function get(url: URL | string, attempts = 4): Promise<Response> {
  try {
    return await fetch(url);
  } catch (error) {
    if (attempts <= 1) throw error;
    await new Promise((resolve) => setTimeout(resolve, 2000));
    return get(url, attempts - 1);
  }
}

const links = new Set<string>();
for (const page of PAGES) {
  const html = await (await get(new URL(page, SITE))).text();
  for (const [, href] of html.matchAll(/href="([^"]+\.(?:cer|crt|pem|der|p7b))"/gi)) links.add(new URL(href, SITE).href);
}

const certs = new Map<string, pkijs.Certificate>();
for (const link of [...links].sort()) {
  const response = await get(link);
  const found = response.ok ? parse(Buffer.from(await response.arrayBuffer())) : [];
  if (found.length === 0) console.log(`skipped (unreadable): ${link}`);
  for (const cert of found) certs.set(der(cert).toString("base64"), cert);
}

const roots: pkijs.Certificate[] = [];
let rest: pkijs.Certificate[] = [];
for (const cert of certs.values()) ((await issuedBy(cert, cert)) ? roots : rest).push(cert);

const verified = [...roots];
for (;;) {
  const chained: pkijs.Certificate[] = [];
  for (const cert of rest) {
    for (const ca of verified) {
      if (await issuedBy(cert, ca)) {
        chained.push(cert);
        break;
      }
    }
  }
  if (chained.length === 0) break;
  verified.push(...chained);
  rest = rest.filter((c) => !chained.includes(c));
}
const intermediates = verified.filter((c) => !roots.includes(c));
for (const cert of rest) console.log(`dropped (does not chain to a CCA root): ${commonName(cert)}`);

writeFileSync(new URL("roots.pem", ASSETS), pem(roots));
writeFileSync(new URL("intermediates.pem", ASSETS), pem(intermediates));
console.log(`${roots.length} roots, ${intermediates.length} intermediates`);
for (const root of roots) console.log(`  root: ${commonName(root)}, expires ${root.notAfter.value.toISOString().slice(0, 10)}`);
