ObjC.import("Foundation");
ObjC.import("Quartz");
ObjC.import("AppKit");

function nsString(value) {
  return $(value);
}

function fileManager() {
  return $.NSFileManager.defaultManager;
}

function ensureDirectory(path) {
  fileManager().createDirectoryAtPathWithIntermediateDirectoriesAttributesError(
    nsString(path),
    true,
    $(),
    null
  );
}

function pngDataFromImage(image) {
  const tiffData = image.TIFFRepresentation;
  const bitmap = $.NSBitmapImageRep.imageRepWithData(tiffData);
  return bitmap.representationUsingTypeProperties(
    $.NSBitmapImageFileTypePNG,
    $.NSDictionary.dictionary
  );
}

function outputPath(outDir, pageNumber) {
  const label = String(pageNumber).padStart(2, "0");
  return `${outDir}/page_${label}.png`;
}

function renderPage(page, outPath) {
  const bounds = page.boundsForBox($.kPDFDisplayBoxMediaBox);
  const width = Math.max(1200, Math.ceil(ObjC.unwrap(bounds.size.width) * 2.5));
  const height = Math.max(1500, Math.ceil(ObjC.unwrap(bounds.size.height) * 2.5));
  const image = page.thumbnailOfSizeForBox($.NSMakeSize(width, height), $.kPDFDisplayBoxMediaBox);
  const pngData = pngDataFromImage(image);
  pngData.writeToFileAtomically(nsString(outPath), true);
}

function run(argv) {
  if (argv.length !== 2) {
    throw new Error("usage: render_pdf_pages_native.js <pdf_path> <output_dir>");
  }

  const pdfPath = argv[0];
  const outDir = argv[1];

  ensureDirectory(outDir);

  const pdfUrl = $.NSURL.fileURLWithPath(nsString(pdfPath));
  const document = $.PDFDocument.alloc.initWithURL(pdfUrl);
  if (!document) {
    throw new Error(`Unable to open PDF: ${pdfPath}`);
  }

  const pageCount = ObjC.unwrap(document.pageCount);
  for (let index = 0; index < pageCount; index += 1) {
    const page = document.pageAtIndex(index);
    const outPath = outputPath(outDir, index + 1);
    renderPage(page, outPath);
    console.log(`Wrote ${outPath}`);
  }

  return `Rendered ${pageCount} pages`;
}
