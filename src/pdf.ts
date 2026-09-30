import { PDFArray, PDFDict, PDFDocument, PDFHexString, PDFName, PDFNumber, PDFString, type PDFRef } from "@cantoo/pdf-lib";

export const name = PDFName.of;

export class PasswordNeeded extends Error {}

export async function open(bytes: Uint8Array, password: string | null): Promise<PDFDocument> {
  try {
    return await PDFDocument.load(bytes, { password: password ?? "", updateMetadata: false });
  } catch (error) {
    if (error instanceof Error && /password/i.test(error.message)) throw new PasswordNeeded();
    throw error;
  }
}

export type SignatureField = { field: string; byteRange: number[]; contents: Uint8Array<ArrayBuffer>; signedAt: Date | null };

export function signatureFields(doc: PDFDocument): SignatureField[] {
  const found: SignatureField[] = [];
  const visit = (ref: PDFRef | PDFDict, inherited: PDFName | undefined, prefix: string) => {
    const field = doc.context.lookup(ref, PDFDict);
    const type = (field.get(name("FT")) as PDFName | undefined) ?? inherited;
    const title = field.lookupMaybe(name("T"), PDFString)?.decodeText();
    const path = title ? (prefix ? `${prefix}.${title}` : title) : prefix;
    const kids = field.lookupMaybe(name("Kids"), PDFArray);
    const value = field.lookupMaybe(name("V"), PDFDict);
    if (type === name("Sig") && value) {
      const range = value.lookup(name("ByteRange"), PDFArray);
      const when = value.lookupMaybe(name("M"), PDFString);
      found.push({
        field: path,
        byteRange: range.asArray().map((n) => (n as PDFNumber).asNumber()),
        contents: new Uint8Array(value.lookup(name("Contents"), PDFHexString).asBytes()),
        signedAt: when ? when.decodeDate() : null,
      });
    }
    for (const kid of kids?.asArray() ?? []) visit(kid as PDFRef, type, path);
  };
  const fields = doc.catalog.lookupMaybe(name("AcroForm"), PDFDict)?.lookupMaybe(name("Fields"), PDFArray);
  for (const ref of fields?.asArray() ?? []) visit(ref as PDFRef, undefined, "");
  return found;
}
