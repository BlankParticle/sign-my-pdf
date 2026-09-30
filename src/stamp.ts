import {
  PDFArray,
  PDFDict,
  PDFNumber,
  PDFRawStream,
  PDFRef,
  decodePDFRawStream,
  type PDFDocument,
} from "@cantoo/pdf-lib";
import { nimbus } from "./nimbus.ts";
import { name } from "./pdf.ts";

const DS_VALID = `% DSDoubleValid
q
0.0852 0 0 0.0852 9.1 7.1 cm
0 J 0 j 4 M []0 d
1.5 i 
1 g
370 37 m
0 401 l
126 574 l
365 289 l
779 1000 l
944 876 l
h f
0 g
406 0 m
55 349 l
157 485 l
396 200 l
817 916 l
963 808 l
h f
0 G
0 0.7 0.23 rg
15 w
377 50 m
25 399 l
128 536 l
367 251 l
787 967 l
934 859 l
b
Q
`;

const STATUS_SPAN = 6.71;

const numbers = (dict: PDFDict, key: string) =>
  dict
    .lookup(name(key), PDFArray)
    .asArray()
    .map((n) => (n as PDFNumber).asNumber());

/** Swap the status layers to 'valid', embed the font and flatten signature widgets into the page. */
export async function stamp(
  doc: PDFDocument,
  font: Uint8Array,
): Promise<{ pdf: Uint8Array; stamped: number }> {
  const { context } = doc;
  const stream = (ref: PDFRef) => context.lookup(ref) as PDFRawStream;
  const rewrite = (ref: PDFRef, contents: string) => {
    const { dict } = stream(ref);
    dict.delete(name("Filter"));
    dict.delete(name("DecodeParms"));
    const bytes = new TextEncoder().encode(contents);
    dict.set(name("Length"), context.obj(bytes.length));
    context.assign(ref, PDFRawStream.of(dict, bytes));
  };
  const fontRef = context.register(
    context.obj({
      Type: "Font",
      Subtype: "TrueType",
      BaseFont: nimbus.name,
      Encoding: "WinAnsiEncoding",
      FirstChar: 32,
      LastChar: 255,
      Widths: nimbus.widths,
      FontDescriptor: context.register(
        context.obj({
          Type: "FontDescriptor",
          FontName: nimbus.name,
          Flags: 32,
          ItalicAngle: 0,
          StemV: 80,
          FontBBox: nimbus.bbox,
          Ascent: nimbus.ascent,
          Descent: nimbus.descent,
          CapHeight: nimbus.capHeight,
          FontFile2: context.register(context.flateStream(font, { Length1: font.length })),
        }),
      ),
    }),
  );

  let stamped = 0;
  for (const page of doc.getPages()) {
    const annots = page.node.Annots();
    if (!annots) continue;
    const keep: PDFRef[] = [];
    for (const ref of annots.asArray() as PDFRef[]) {
      const annot = context.lookup(ref, PDFDict);
      const appearance = annot.lookupMaybe(name("AP"), PDFDict)?.get(name("N"));
      if (annot.get(name("FT")) !== name("Sig") || !(appearance instanceof PDFRef)) {
        keep.push(ref);
        continue;
      }
      const ap = stream(appearance).dict;
      const frm = ap
        .lookupMaybe(name("Resources"), PDFDict)
        ?.lookupMaybe(name("XObject"), PDFDict)
        ?.get(name("FRM"));
      const layers =
        frm instanceof PDFRef
          ? stream(frm)
              .dict.lookupMaybe(name("Resources"), PDFDict)
              ?.lookupMaybe(name("XObject"), PDFDict)
          : undefined;
      const n1 = layers?.get(name("n1"));
      const n4 = layers?.get(name("n4"));
      if (
        layers &&
        n1 instanceof PDFRef &&
        new TextDecoder().decode(decodePDFRawStream(stream(n1)).decode()).startsWith("% DSUnknown")
      ) {
        rewrite(n1, DS_VALID);
        if (n4 instanceof PDFRef) {
          const [x0, y0, x1] = numbers(stream(n4).dict, "BBox");
          const size = (x1 - x0) / STATUS_SPAN;
          stream(n4).dict.set(name("Resources"), context.obj({ Font: { F1: fontRef } }));
          rewrite(
            n4,
            `BT\n1 0 0 1 ${x0} ${(y0 + 0.27 * size).toFixed(2)} Tm\n/F1 ${size.toFixed(2)} Tf\n(Signature valid)Tj\nET\n`,
          );
        }
        for (const layer of layers.values()) {
          const fonts = stream(layer as PDFRef)
            .dict.lookupMaybe(name("Resources"), PDFDict)
            ?.lookupMaybe(name("Font"), PDFDict);
          for (const [key, value] of fonts?.entries() ?? []) {
            const dict = context.lookup(value, PDFDict);
            if (
              dict.get(name("BaseFont")) === name("Helvetica") &&
              !dict.has(name("FontDescriptor"))
            )
              fonts!.set(key, fontRef);
          }
        }
        stamped += 1;
      }

      const [x0, y0, x1, y1] = numbers(annot, "Rect");
      const [bx0, by0, bx1, by1] = numbers(ap, "BBox");
      const sx = (x1 - x0) / (bx1 - bx0);
      const sy = (y1 - y0) / (by1 - by0);
      const xobject = page.node.newXObject("SigAP", appearance);
      page.node.normalize();
      page.node.wrapContentStreams(
        context.register(context.stream("q\n")),
        context.register(context.stream("\nQ\n")),
      );
      page.node.addContentStream(
        context.register(
          context.stream(
            `q ${sx} 0 0 ${sy} ${x0 - bx0 * sx} ${y0 - by0 * sy} cm ${xobject.toString()} Do Q\n`,
          ),
        ),
      );
    }
    page.node.set(name("Annots"), context.obj(keep));
  }
  doc.catalog.delete(name("AcroForm"));
  return { pdf: await doc.save(), stamped };
}
