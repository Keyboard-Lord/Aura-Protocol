const LOCAL_DEV_AUTHORIZATION_SIGNER_PUBLIC_KEY_HEX_V1 =
  "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const SAMPLE_AUTHORIZATION_NONCE_HEX_V1 =
  "5555555555555555555555555555555555555555555555555555555555555555";
const AUTHORIZATION_SIGN_CARRIER_VERSION_V1 = 1;

const state = {
  summary: null,
  markdown: "",
  html: "",
  burnSummary: null,
  transaction: null,
  publicStatement: null,
  notarizationRecord: null,
  composeRequest: null,
  authorizationSession: null,
  signerLauncher: null,
  authorizationSignCarrierResponse: null,
  authorizationSignResponse: null,
  authorizationSignScope: null,
  authorizationResponseError: null,
  activeTab: "markdown",
  activeMode: "compose",
  lastDerivedMode: null,
  lastInspectedRecordText: null,
  lastComposedDraftFingerprint: null,
};

const RECORD_JSON_STORAGE_KEY = "aura_notarization_workbench_v1.record_json";
const COMPOSE_REQUEST_STORAGE_KEY = "aura_notarization_workbench_v1.compose_request";
const PREVIEW_TAB_STORAGE_KEY = "aura_notarization_workbench_v1.preview_tab";
const ACTIVE_MODE_STORAGE_KEY = "aura_notarization_workbench_v1.active_mode";
const IDLE_STATUS_MESSAGE =
  "Ready to prepare authorization, complete compose, or inspect canonical record input.";
const STALE_INSPECT_STATUS_MESSAGE =
  "Record input changed. Inspect again to refresh canonical outputs.";
const STALE_COMPOSE_STATUS_MESSAGE =
  "Compose or authorization input changed. Prepare authorization again to refresh the signer session and downstream outputs.";
const STALE_SIGN_RESPONSE_STATUS_MESSAGE =
  "Authorization sign response changed. Complete compose again to refresh canonical outputs.";
const WORKBENCH_ACTION_LABELS = {
  clearWorkbench: "Clear Workbench",
  exportReceiptPair: "Export Receipt Pair",
  exportComposeBundle: "Export Compose Bundle",
  downloadExportBundleJson: "Download Export Bundle JSON",
  copyExportBundleJson: "Copy Export Bundle JSON",
  downloadSignCarrierRequest: "Download Sign Carrier Request",
  runLocalSigner: "Run Local Signer",
  loadGuidedSignerResponse: "Load Guided Signer Response",
  importSignCarrierResponse: "Import Sign Carrier Response",
  copySignRequestJson: "Copy Sign Request JSON",
  copyPayloadBytes: "Copy Payload Bytes Hex",
  localDevSign: "Local Dev Sign (Dev Only)",
  prepareAuthorization: "Prepare Authorization",
  completeCompose: "Complete Compose",
};
const RECEIPT_FILENAMES = {
  markdown: "aura_notarization_receipt.md",
  html: "aura_notarization_receipt.html",
};
const COMPOSE_BUNDLE_FILENAMES = {
  composeRequest: "compose-request.json",
  transaction: "transaction.json",
  publicStatement: "public-statement.json",
  notarizationRecord: "notarization-record.json",
  markdown: "receipt.md",
  html: "receipt.html",
};
const EXPORT_BUNDLE_JSON_FILENAME = "aura_notarization_compose_export_bundle.json";

const elements = {
  modeCompose: document.getElementById("mode-compose"),
  modeInspect: document.getElementById("mode-inspect"),
  composeSection: document.getElementById("compose-section"),
  inspectSection: document.getElementById("inspect-section"),
  composeRollupId: document.getElementById("compose-rollup-id"),
  composeAssetId: document.getElementById("compose-asset-id"),
  composeAnchorRoot: document.getElementById("compose-anchor-root"),
  composeInputs: document.getElementById("compose-inputs"),
  composeOutputs: document.getElementById("compose-outputs"),
  authorizationSignerPublicKey: document.getElementById("authorization-signer-public-key"),
  authorizationNonce: document.getElementById("authorization-nonce"),
  loadComposeSample: document.getElementById("load-compose-sample"),
  prepareAuthorization: document.getElementById("prepare-authorization"),
  downloadSignCarrierRequest: document.getElementById("download-sign-carrier-request"),
  runLocalSigner: document.getElementById("run-local-signer"),
  loadGuidedSignerResponse: document.getElementById("load-guided-signer-response"),
  importSignCarrierResponse: document.getElementById("import-sign-carrier-response"),
  importSignCarrierResponseFile: document.getElementById("import-sign-carrier-response-file"),
  copySignRequestJson: document.getElementById("copy-sign-request-json"),
  copyPayloadBytes: document.getElementById("copy-payload-bytes"),
  localDevSign: document.getElementById("local-dev-sign"),
  addInputRow: document.getElementById("add-input-row"),
  addOutputRow: document.getElementById("add-output-row"),
  composeTransaction: document.getElementById("compose-transaction"),
  authorizationStatus: document.getElementById("authorization-status"),
  authorizationSessionId: document.getElementById("authorization-session-id"),
  signerLauncherRequestPath: document.getElementById("signer-launcher-request-path"),
  signerLauncherResponsePath: document.getElementById("signer-launcher-response-path"),
  authorizationSignRequestPreview: document.getElementById("authorization-sign-request-preview"),
  authorizationPayloadBytesPreview: document.getElementById("authorization-payload-bytes-preview"),
  signerLauncherCommandPreview: document.getElementById("signer-launcher-command-preview"),
  authorizationResponseInput: document.getElementById("authorization-response-input"),
  clearAuthorizationResponse: document.getElementById("clear-authorization-response"),
  exportComposeBundle: document.getElementById("export-compose-bundle"),
  downloadExportBundleJson: document.getElementById("download-export-bundle-json"),
  copyExportBundleJson: document.getElementById("copy-export-bundle-json"),
  clearWorkbench: document.getElementById("clear-workbench"),
  loadSample: document.getElementById("load-sample"),
  fileInput: document.getElementById("file-input"),
  recordInput: document.getElementById("record-input"),
  inspectRecord: document.getElementById("inspect-record"),
  clearInspectDraft: document.getElementById("clear-inspect-draft"),
  status: document.getElementById("status"),
  summaryList: document.getElementById("summary-list"),
  markdownPreview: document.getElementById("markdown-preview"),
  htmlPreview: document.getElementById("html-preview"),
  copySummaryJson: document.getElementById("copy-summary-json"),
  copyRecordDigest: document.getElementById("copy-record-digest"),
  copyMarkdown: document.getElementById("copy-markdown"),
  copyHtml: document.getElementById("copy-html"),
  tabMarkdown: document.getElementById("tab-markdown"),
  tabHtml: document.getElementById("tab-html"),
  downloadMarkdown: document.getElementById("download-markdown"),
  downloadHtml: document.getElementById("download-html"),
  exportReceiptPair: document.getElementById("export-receipt-pair"),
  burnInputCount: document.getElementById("burn-input-count"),
  burnOutputCount: document.getElementById("burn-output-count"),
  burnAdmission: document.getElementById("burn-admission"),
  burnNotary: document.getElementById("burn-notary"),
  burnPriority: document.getElementById("burn-priority"),
  transactionPreview: document.getElementById("transaction-preview"),
  publicStatementPreview: document.getElementById("public-statement-preview"),
  notarizationRecordPreview: document.getElementById("notarization-record-preview"),
};

const DERIVED_ACTION_BUTTONS = [
  elements.copySummaryJson,
  elements.copyRecordDigest,
  elements.copyMarkdown,
  elements.copyHtml,
  elements.downloadMarkdown,
  elements.downloadHtml,
  elements.exportReceiptPair,
];

const SUMMARY_KEYS = [
  "summary_version",
  "record_version",
  "proof_statement_type",
  "proof_statement_label",
  "ack_digest_hex",
  "seal_payload_digest_hex",
  "udot_seed_digest_hex",
  "notarization_record_digest_hex",
];

const SUMMARY_LABELS = {
  summary_version: "Summary Version",
  record_version: "Record Version",
  proof_statement_type: "Proof Statement Type",
  proof_statement_label: "Proof Statement Label",
  ack_digest_hex: "Ack Digest",
  seal_payload_digest_hex: "Seal Payload Digest",
  udot_seed_digest_hex: "UDOT Seed Digest",
  notarization_record_digest_hex: "Notarization Record Digest",
};

elements.clearWorkbench.title =
  `${WORKBENCH_ACTION_LABELS.clearWorkbench} removes compose drafts, raw inspect input, authorization state, and derived outputs.`;
elements.exportReceiptPair.title =
  `${WORKBENCH_ACTION_LABELS.exportReceiptPair} downloads the current Markdown and HTML receipts.`;
elements.exportComposeBundle.title =
  `${WORKBENCH_ACTION_LABELS.exportComposeBundle} downloads the six-file canonical compose artifact set after a valid authorized compose.`;
elements.downloadExportBundleJson.title =
  `${WORKBENCH_ACTION_LABELS.downloadExportBundleJson} fetches the bounded server-backed compose bundle route as one JSON file.`;
elements.copyExportBundleJson.title =
  `${WORKBENCH_ACTION_LABELS.copyExportBundleJson} fetches the bounded server-backed compose bundle route and copies the exact JSON bundle to the clipboard.`;
elements.prepareAuthorization.title =
  `${WORKBENCH_ACTION_LABELS.prepareAuthorization} freezes the compose draft plus signer inputs into one bounded signer session.`;
elements.downloadSignCarrierRequest.title =
  `${WORKBENCH_ACTION_LABELS.downloadSignCarrierRequest} exports the file-based external signer carrier with session_id_hex plus the frozen sign request.`;
elements.runLocalSigner.title =
  `${WORKBENCH_ACTION_LABELS.runLocalSigner} prompts for a private key once, runs the same local signer helper over the deterministic carrier files, and does not store the key in workbench state.`;
elements.loadGuidedSignerResponse.title =
  `${WORKBENCH_ACTION_LABELS.loadGuidedSignerResponse} reads the deterministic local carrier response path written by the guided signer launcher flow.`;
elements.importSignCarrierResponse.title =
  `${WORKBENCH_ACTION_LABELS.importSignCarrierResponse} imports a file-based sign carrier response and checks that its session_id_hex matches the prepared session.`;
elements.copySignRequestJson.title =
  `${WORKBENCH_ACTION_LABELS.copySignRequestJson} copies the frozen signer request for an external signer workflow.`;
elements.copyPayloadBytes.title =
  `${WORKBENCH_ACTION_LABELS.copyPayloadBytes} copies the exact canonical authorization payload bytes that must be signed.`;
elements.localDevSign.title =
  `${WORKBENCH_ACTION_LABELS.localDevSign} uses a fixed local test key and is not the production signing model.`;
elements.composeTransaction.title =
  `${WORKBENCH_ACTION_LABELS.completeCompose} validates the signer response against the prepared session and completes the canonical compose path.`;

elements.modeCompose.addEventListener("click", () => switchMode("compose"));
elements.modeInspect.addEventListener("click", () => switchMode("inspect"));
elements.loadComposeSample.addEventListener("click", loadComposeSample);
elements.prepareAuthorization.addEventListener("click", prepareAuthorization);
elements.downloadSignCarrierRequest.addEventListener("click", downloadSignCarrierRequest);
elements.runLocalSigner.addEventListener("click", runLocalSigner);
elements.loadGuidedSignerResponse.addEventListener("click", loadGuidedSignerResponse);
elements.importSignCarrierResponse.addEventListener("click", importSignCarrierResponse);
elements.importSignCarrierResponseFile.addEventListener(
  "change",
  importSignCarrierResponseFile,
);
elements.copySignRequestJson.addEventListener("click", copySignRequestJson);
elements.copyPayloadBytes.addEventListener("click", copyPayloadBytes);
elements.localDevSign.addEventListener("click", localDevSign);
elements.addInputRow.addEventListener("click", () => {
  addInputRow();
  handleComposeDraftChange();
});
elements.addOutputRow.addEventListener("click", () => {
  addOutputRow();
  handleComposeDraftChange();
});
elements.composeTransaction.addEventListener("click", composeTransaction);
elements.exportComposeBundle.addEventListener("click", exportComposeBundle);
elements.downloadExportBundleJson.addEventListener("click", downloadExportBundleJson);
elements.copyExportBundleJson.addEventListener("click", copyExportBundleJson);
elements.clearWorkbench.addEventListener("click", resetWorkbench);
elements.loadSample.addEventListener("click", loadInspectSample);
elements.fileInput.addEventListener("change", importRecordJson);
elements.recordInput.addEventListener("input", handleRecordInputChange);
elements.inspectRecord.addEventListener("click", inspectRecord);
elements.clearInspectDraft.addEventListener("click", clearInspectDraft);
elements.copySummaryJson.addEventListener("click", copySummaryJson);
elements.copyRecordDigest.addEventListener("click", copyNotarizationRecordDigest);
elements.copyMarkdown.addEventListener("click", copyMarkdownReceipt);
elements.copyHtml.addEventListener("click", copyHtmlReceipt);
elements.tabMarkdown.addEventListener("click", () => switchTab("markdown"));
elements.tabHtml.addEventListener("click", () => switchTab("html"));
elements.downloadMarkdown.addEventListener("click", () =>
  downloadReceipt("markdown", RECEIPT_FILENAMES.markdown, state.markdown),
);
elements.downloadHtml.addEventListener("click", () =>
  downloadReceipt("html", RECEIPT_FILENAMES.html, state.html),
);
elements.exportReceiptPair.addEventListener("click", downloadReceiptPair);
elements.composeInputs.addEventListener("input", handleComposeDraftChange);
elements.composeOutputs.addEventListener("input", handleComposeDraftChange);
elements.composeInputs.addEventListener("click", handleRowButtonClick);
elements.composeOutputs.addEventListener("click", handleRowButtonClick);
elements.composeRollupId.addEventListener("input", handleComposeDraftChange);
elements.composeAssetId.addEventListener("input", handleComposeDraftChange);
elements.composeAnchorRoot.addEventListener("input", handleComposeDraftChange);
elements.authorizationSignerPublicKey.addEventListener("input", handleAuthorizationInputChange);
elements.authorizationNonce.addEventListener("input", handleAuthorizationInputChange);
elements.authorizationResponseInput.addEventListener(
  "input",
  handleAuthorizationResponseInputChange,
);
elements.clearAuthorizationResponse.addEventListener("click", clearAuthorizationResponse);

initializeWorkbench();

async function loadComposeSample() {
  try {
    setStatus("Loading compose sample fixture…", "idle");
    const response = await fetch("/api/compose/sample");
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Unable to load compose sample fixture.");
    }

    loadComposeDraft(payload, null);
    elements.authorizationSignerPublicKey.value =
      LOCAL_DEV_AUTHORIZATION_SIGNER_PUBLIC_KEY_HEX_V1;
    elements.authorizationNonce.value = SAMPLE_AUTHORIZATION_NONCE_HEX_V1;
    renderAuthorizationState();
    switchMode("compose");
    setStatus(
      "Loaded canonical compose sample and prefilled local dev signer inputs. Prepare authorization to continue.",
      "success",
    );
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function loadInspectSample() {
  try {
    setStatus("Loading canonical record sample…", "idle");
    const response = await fetch("/api/sample");
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Unable to load sample fixture.");
    }
    loadRecordInput(
      JSON.stringify(payload, null, 2),
      "Loaded canonical record wire JSON. Inspect to derive canonical outputs.",
    );
    switchMode("inspect");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function importRecordJson(event) {
  const [file] = event.target.files || [];
  if (!file) return;
  loadRecordInput(
    await file.text(),
    `Imported ${file.name}. Inspect to derive canonical outputs.`,
  );
  elements.fileInput.value = "";
  switchMode("inspect");
}

async function prepareAuthorization() {
  let payload;
  try {
    payload = buildPreparePayload();
  } catch (error) {
    clearPreparedAuthorizationState({ clearInputs: false });
    clearDerivedOutputs(false);
    setStatus(formatActionError("Prepare authorization", error), "error");
    return;
  }

  try {
    setStatus("Preparing frozen authorization session…", "idle");
    const response = await fetch("/api/compose/prepare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || "Unable to prepare authorization session.");
    }

    applyPreparedSession(body);
    try {
      await prepareGuidedSignerLauncher(body);
      setStatus(
        "Prepared authorization session. Guided signer files are ready below. Run Local Signer, use the guided helper command, or keep using the download/import fallback.",
        "success",
      );
    } catch (launcherError) {
      setStatus(
        `Prepared authorization session. Guided signer files were not written automatically: ${launcherError.message}. Run Local Signer or keep using the download/import flow.`,
        "idle",
      );
    }
  } catch (error) {
    clearPreparedAuthorizationState({ clearInputs: false });
    clearDerivedOutputs(false);
    setStatus(formatActionError("Prepare authorization", error), "error");
  }
}

async function prepareGuidedSignerLauncher(session) {
  const response = await fetch("/api/compose/signer-launcher/prepare", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(session),
  });
  const body = await response.json();
  if (!response.ok) {
    state.signerLauncher = null;
    renderAuthorizationState();
    throw new Error(body.error || "Unable to prepare guided signer files.");
  }

  state.signerLauncher = deepClone(body);
  renderAuthorizationState();
  return body;
}

function downloadSignCarrierRequest() {
  if (!state.authorizationSession) {
    setStatus(
      `Nothing to export yet. Run ${WORKBENCH_ACTION_LABELS.prepareAuthorization} first.`,
      "error",
    );
    return;
  }

  const carrierRequest = buildSignCarrierRequest(state.authorizationSession);
  downloadReceiptFile(
    buildSignCarrierRequestFilename(state.authorizationSession.session_id_hex),
    JSON.stringify(carrierRequest, null, 2),
    "application/json",
  );
  setStatus("Downloaded sign carrier request JSON.", "success");
}

function importSignCarrierResponse() {
  if (!state.authorizationSession) {
    setStatus(
      `Nothing to import yet. Run ${WORKBENCH_ACTION_LABELS.prepareAuthorization} first.`,
      "error",
    );
    return;
  }

  elements.importSignCarrierResponseFile.value = "";
  elements.importSignCarrierResponseFile.click();
}

async function loadGuidedSignerResponse() {
  if (!state.authorizationSession) {
    setStatus(
      `Nothing to load yet. Run ${WORKBENCH_ACTION_LABELS.prepareAuthorization} first.`,
      "error",
    );
    return;
  }

  try {
    setStatus("Loading guided signer response from the stable local path…", "idle");
    const response = await fetch("/api/compose/signer-launcher/load", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(state.authorizationSession),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || "Unable to load guided signer response.");
    }

    state.signerLauncher = deepClone(body.launcher);
    applyAuthorizationAttachmentResult({
      signCarrierResponse: body.sign_carrier_response,
      signScope:
        typeof body.launcher?.scope === "string" ? body.launcher.scope : null,
      inputText: JSON.stringify(body.sign_carrier_response, null, 2),
      freshStatusMessage: `Loaded guided signer response from ${body.launcher.response_path}. Complete compose to continue.`,
      staleStatusMessage:
        "Loaded guided signer response from the deterministic local path. Existing compose output is stale; complete compose again.",
    });
  } catch (error) {
    setStatus(formatActionError(WORKBENCH_ACTION_LABELS.loadGuidedSignerResponse, error), "error");
  }
}

async function importSignCarrierResponseFile(event) {
  const [file] = event.target.files || [];
  if (!file) return;

  try {
    const text = await file.text();
    const parsed = parseAuthorizationCarrierResponseInputValue(text);
    applyAuthorizationAttachmentResult({
      signCarrierResponse: parsed.signCarrierResponse,
      signScope: "external_file_carrier_v1",
      inputText: JSON.stringify(parsed.signCarrierResponse, null, 2),
      freshStatusMessage: `Imported ${file.name}. Complete compose to validate the carrier response and continue.`,
    });
  } catch (error) {
    setStatus(formatActionError("Import sign carrier response", error), "error");
  } finally {
    elements.importSignCarrierResponseFile.value = "";
  }
}

async function runLocalSigner() {
  if (!state.authorizationSession) {
    setStatus(
      `Nothing to sign yet. Run ${WORKBENCH_ACTION_LABELS.prepareAuthorization} first.`,
      "error",
    );
    return;
  }

  const privateKeyHex = window.prompt(
    "Enter the 64-hex Ed25519 private key for the local signer helper. It will be used once and not stored.",
    "",
  );
  if (privateKeyHex === null) {
    setStatus(`${WORKBENCH_ACTION_LABELS.runLocalSigner} cancelled.`, "idle");
    return;
  }

  try {
    const trimmedPrivateKeyHex = privateKeyHex.trim();
    if (!trimmedPrivateKeyHex) {
      throw new Error("Private key hex is required to run the local signer helper.");
    }

    setStatus("Running the local signer helper subprocess…", "idle");
    const response = await fetch("/api/compose/signer-launcher/run-local", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session: state.authorizationSession,
        private_key_hex: trimmedPrivateKeyHex,
      }),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || "Unable to run the local signer helper.");
    }

    state.signerLauncher = deepClone(body.launcher);
    applyAuthorizationAttachmentResult({
      signCarrierResponse: body.sign_carrier_response,
      signScope: typeof body.scope === "string" ? body.scope : null,
      inputText: JSON.stringify(body.sign_carrier_response, null, 2),
      freshStatusMessage:
        "Local signer helper completed and wrote the deterministic carrier response. Complete compose to continue.",
      staleStatusMessage:
        "Local signer helper completed. Existing compose output is stale; complete compose again.",
    });
  } catch (error) {
    setStatus(formatActionError(WORKBENCH_ACTION_LABELS.runLocalSigner, error), "error");
  }
}

async function localDevSign() {
  if (!state.authorizationSession) {
    setStatus(
      `Nothing to sign yet. Run ${WORKBENCH_ACTION_LABELS.prepareAuthorization} first.`,
      "error",
    );
    return;
  }

  try {
    setStatus("Requesting a local dev sign response…", "idle");
    const response = await fetch("/api/dev/sign", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(state.authorizationSession),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || "Unable to complete local dev signing.");
    }
    if (
      body.session_id_hex &&
      body.session_id_hex !== state.authorizationSession.session_id_hex
    ) {
      throw new Error("Local dev signer returned a mismatched session_id_hex.");
    }

    const signCarrierResponse = buildSignCarrierResponse(
      state.authorizationSession.session_id_hex,
      body.sign_response,
    );
    applyAuthorizationAttachmentResult({
      signCarrierResponse,
      signScope: typeof body.scope === "string" ? body.scope : null,
      inputText: JSON.stringify(signCarrierResponse, null, 2),
      freshStatusMessage:
        "Local dev signer returned a sign response. Complete compose to continue.",
      staleStatusMessage:
        "Local dev signer returned a new sign response. Existing compose output is stale; complete compose again.",
    });
  } catch (error) {
    setStatus(formatActionError("Local dev sign", error), "error");
  }
}

async function composeTransaction() {
  let payload;
  try {
    payload = buildCompletionPayload();
  } catch (error) {
    if (state.authorizationSession) {
      clearDerivedOutputs(true);
    } else {
      clearDerivedOutputs(false);
    }
    setStatus(formatActionError("Complete compose", error), "error");
    return;
  }

  try {
    setStatus("Validating authorization and completing canonical compose…", "idle");
    const response = await fetch("/api/compose/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || "Composition failed.");
    }

    applyDerivedResult(body, "compose", state.authorizationSession.compose_request);
    setStatus(
      "Authorized compose completed. Canonical transaction, record, and receipt previews updated.",
      "success",
    );
  } catch (error) {
    clearDerivedOutputs(Boolean(state.authorizationSession));
    setStatus(formatActionError("Complete compose", error), "error");
  }
}

async function inspectRecord() {
  try {
    setStatus("Validating canonical record wire and building receipt previews…", "idle");
    const recordInputText = elements.recordInput.value;
    const payload = JSON.parse(recordInputText);
    const response = await fetch("/api/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || "Inspection failed.");
    }

    applyDerivedResult(
      {
        summary: body.summary,
        markdown_receipt: body.markdown_receipt,
        html_receipt: body.html_receipt,
        burn_summary: null,
        transaction: null,
        public_statement: null,
        notarization_record: payload,
      },
      "inspect",
      recordInputText,
    );
    setStatus("Canonical summary and receipt previews updated.", "success");
  } catch (error) {
    clearDerivedOutputs(false);
    setStatus(formatInspectError(error), "error");
  }
}

async function downloadExportBundleJson() {
  if (!hasComposeBundleReady()) {
    setStatus(
      `Nothing to export yet. Build a canonical compose result before using ${WORKBENCH_ACTION_LABELS.downloadExportBundleJson}.`,
      "error",
    );
    return;
  }

  let payload;
  try {
    payload = buildCompletionPayload();
  } catch (error) {
    setStatus(formatActionError(WORKBENCH_ACTION_LABELS.downloadExportBundleJson, error), "error");
    return;
  }

  try {
    setStatus("Fetching bounded server-backed compose export bundle…", "idle");
    const response = await fetch("/api/compose/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || "Unable to fetch export bundle.");
    }
    downloadReceiptFile(
      EXPORT_BUNDLE_JSON_FILENAME,
      JSON.stringify(body, null, 2),
      "application/json",
    );
    setStatus(`${WORKBENCH_ACTION_LABELS.downloadExportBundleJson} completed.`, "success");
  } catch (error) {
    setStatus(
      error?.message || `${WORKBENCH_ACTION_LABELS.downloadExportBundleJson} failed.`,
      "error",
    );
  }
}

async function copyExportBundleJson() {
  if (!hasComposeBundleReady()) {
    setStatus(
      `Nothing to export yet. Build a canonical compose result before using ${WORKBENCH_ACTION_LABELS.copyExportBundleJson}.`,
      "error",
    );
    return;
  }

  let payload;
  try {
    payload = buildCompletionPayload();
  } catch (error) {
    setStatus(formatActionError(WORKBENCH_ACTION_LABELS.copyExportBundleJson, error), "error");
    return;
  }

  try {
    setStatus("Fetching bounded server-backed compose export bundle for copy…", "idle");
    const response = await fetch("/api/compose/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || "Unable to fetch export bundle.");
    }
    await copyText(
      JSON.stringify(body, null, 2),
      `${WORKBENCH_ACTION_LABELS.copyExportBundleJson} completed.`,
      `${WORKBENCH_ACTION_LABELS.copyExportBundleJson} failed.`,
    );
  } catch (error) {
    setStatus(
      error?.message || `${WORKBENCH_ACTION_LABELS.copyExportBundleJson} failed.`,
      "error",
    );
  }
}

async function copySignRequestJson() {
  const signRequest = state.authorizationSession?.authorization_sign_request;
  if (!signRequest) {
    setStatus(
      `Nothing to copy yet. Run ${WORKBENCH_ACTION_LABELS.prepareAuthorization} first.`,
      "error",
    );
    return;
  }
  await copyText(
    JSON.stringify(signRequest, null, 2),
    "Copied frozen sign request JSON.",
    "Unable to copy frozen sign request JSON.",
  );
}

async function copyPayloadBytes() {
  const payloadBytesHex =
    state.authorizationSession?.authorization_sign_request?.payload_bytes_hex;
  if (!payloadBytesHex) {
    setStatus(
      `Nothing to copy yet. Run ${WORKBENCH_ACTION_LABELS.prepareAuthorization} first.`,
      "error",
    );
    return;
  }
  await copyText(
    payloadBytesHex,
    "Copied frozen authorization payload bytes hex.",
    "Unable to copy frozen authorization payload bytes hex.",
  );
}

function clearAuthorizationResponse() {
  if (!state.authorizationSession && !elements.authorizationResponseInput.value.trim()) {
    renderAuthorizationState();
    return;
  }

  const hadComposeBundle = hasComposeBundleReady();
  clearAuthorizationResponseState({ clearInputText: true });
  if (hadComposeBundle && state.authorizationSession) {
    clearDerivedOutputs(true);
    setStatus(STALE_SIGN_RESPONSE_STATUS_MESSAGE, "idle");
    return;
  }

  renderAuthorizationState();
  setStatus(
    "Cleared authorization sign response. Complete compose is disabled until a valid response is attached.",
    "idle",
  );
}

function handleAuthorizationResponseInputChange() {
  const inputText = elements.authorizationResponseInput.value.trim();
  const hadComposeBundle = hasComposeBundleReady();
  clearAuthorizationResponseState({ clearInputText: false });

  if (!inputText) {
    if (hadComposeBundle && state.authorizationSession) {
      clearDerivedOutputs(true);
      setStatus(STALE_SIGN_RESPONSE_STATUS_MESSAGE, "idle");
      return;
    }
    renderAuthorizationState();
    return;
  }

  try {
    const parsed = parseAuthorizationResponseInputValue(inputText);
    attachAuthorizationCarrierResponse({
      signCarrierResponse: parsed.signCarrierResponse,
      signResponse: parsed.signResponse,
      signScope: parsed.signScope,
      inputText: null,
    });

    if (hadComposeBundle && state.authorizationSession) {
      clearDerivedOutputs(true);
      setStatus(STALE_SIGN_RESPONSE_STATUS_MESSAGE, "idle");
      return;
    }

    renderAuthorizationState();
  } catch (error) {
    state.authorizationResponseError =
      error?.message || "Authorization sign response JSON is not valid yet.";

    if (hadComposeBundle && state.authorizationSession) {
      clearDerivedOutputs(true);
      setStatus(STALE_SIGN_RESPONSE_STATUS_MESSAGE, "idle");
      return;
    }

    renderAuthorizationState();
  }
}

function applyPreparedSession(session) {
  state.authorizationSession = deepClone(session);
  state.signerLauncher = null;
  clearAuthorizationResponseState({ clearInputText: true });
  clearDerivedOutputs(true);
}

function attachAuthorizationCarrierResponse({
  signCarrierResponse = null,
  signResponse = null,
  signScope = null,
  inputText = null,
}) {
  state.authorizationSignCarrierResponse = signCarrierResponse
    ? deepClone(signCarrierResponse)
    : null;
  state.authorizationSignResponse = deepClone(
    signResponse ||
      signCarrierResponse?.authorization_sign_response ||
      null,
  );
  state.authorizationSignScope = signScope;
  state.authorizationResponseError = null;
  if (typeof inputText === "string") {
    elements.authorizationResponseInput.value = inputText;
  }
}

function applyAuthorizationAttachmentResult({
  signCarrierResponse = null,
  signResponse = null,
  signScope = null,
  inputText = null,
  freshStatusMessage = null,
  staleStatusMessage = STALE_SIGN_RESPONSE_STATUS_MESSAGE,
}) {
  const hadComposeBundle = hasComposeBundleReady();
  attachAuthorizationCarrierResponse({
    signCarrierResponse,
    signResponse,
    signScope,
    inputText,
  });

  if (hadComposeBundle && state.authorizationSession) {
    clearDerivedOutputs(true);
    setStatus(staleStatusMessage, "idle");
    return;
  }

  renderAuthorizationState();
  if (freshStatusMessage) {
    setStatus(freshStatusMessage, "success");
  }
}

function applyDerivedResult(body, mode, sourceFingerprint) {
  state.summary = body.summary;
  state.markdown = body.markdown_receipt;
  state.html = body.html_receipt;
  state.burnSummary = body.burn_summary || null;
  state.transaction = body.transaction || null;
  state.publicStatement = body.public_statement || null;
  state.notarizationRecord = body.notarization_record || null;
  state.composeRequest = mode === "compose" ? deepClone(sourceFingerprint) : null;
  state.lastDerivedMode = mode;
  state.lastInspectedRecordText =
    mode === "inspect" ? sourceFingerprint : JSON.stringify(body.notarization_record, null, 2);
  state.lastComposedDraftFingerprint =
    mode === "compose" ? stableStringify(sourceFingerprint) : null;

  if (body.notarization_record) {
    const recordText = JSON.stringify(body.notarization_record, null, 2);
    elements.recordInput.value = recordText;
    persistRecordInput();
  }

  renderSummary();
  renderCanonicalPath();
  renderPreviews();
  renderAuthorizationState();
  setActionAvailability(true);
}

function renderSummary() {
  const rows = SUMMARY_KEYS.map((key) => {
    const value = state.summary?.[key] ?? "—";
    return `<div><dt>${SUMMARY_LABELS[key]}</dt><dd>${escapeHtml(String(value))}</dd></div>`;
  }).join("");
  elements.summaryList.innerHTML = rows;
}

function renderCanonicalPath() {
  elements.burnInputCount.textContent = formatBurnField(state.burnSummary?.input_count);
  elements.burnOutputCount.textContent = formatBurnField(state.burnSummary?.output_count);
  elements.burnAdmission.textContent = formatBurnField(state.burnSummary?.admission_burn);
  elements.burnNotary.textContent = formatBurnField(state.burnSummary?.notary_burn);
  elements.burnPriority.textContent = formatBurnField(state.burnSummary?.priority_weight);
  elements.transactionPreview.textContent = formatJsonPreview(state.transaction);
  elements.publicStatementPreview.textContent = formatJsonPreview(state.publicStatement);
  elements.notarizationRecordPreview.textContent = formatJsonPreview(state.notarizationRecord);
}

function renderPreviews() {
  elements.markdownPreview.textContent = state.markdown || "";
  elements.htmlPreview.innerHTML = state.html || "";
  switchTab(state.activeTab);
}

function renderAuthorizationState() {
  const session = state.authorizationSession;
  const launcher = state.signerLauncher;
  const payload = session?.authorization_sign_request?.payload || null;
  const signerPublicKeyHex = payload?.signer_public_key_hex || "";
  const canLocalDevSign =
    Boolean(session) &&
    signerPublicKeyHex === LOCAL_DEV_AUTHORIZATION_SIGNER_PUBLIC_KEY_HEX_V1;

  let statusText = "Awaiting prepare";
  if (session) {
    if (state.authorizationResponseError) {
      statusText = state.authorizationResponseError;
    } else if (state.authorizationSignResponse) {
      if (state.authorizationSignCarrierResponse) {
        if (state.authorizationSignScope) {
          statusText = `Sign carrier response attached (${state.authorizationSignScope}). Ready to complete compose.`;
        } else {
          statusText = "Sign carrier response attached. Ready to complete compose.";
        }
      } else if (state.authorizationSignScope) {
        statusText = `Sign response attached (${state.authorizationSignScope}). Ready to complete compose.`;
      } else {
        statusText = "Sign response attached. Ready to complete compose.";
      }
    } else if (launcher) {
      statusText =
        "Prepared session ready. Run Local Signer, use the guided helper command below, or keep using the download/import fallback.";
    } else {
      statusText =
        "Prepared session ready. Run Local Signer or sign the frozen payload bytes, then attach the sign response.";
    }
  }

  elements.authorizationStatus.textContent = statusText;
  elements.authorizationSessionId.textContent = session?.session_id_hex || "—";
  elements.signerLauncherRequestPath.textContent = launcher?.request_path || "—";
  elements.signerLauncherResponsePath.textContent = launcher?.response_path || "—";
  elements.authorizationSignRequestPreview.textContent = formatJsonPreview(
    session?.authorization_sign_request,
  );
  elements.authorizationPayloadBytesPreview.textContent =
    session?.authorization_sign_request?.payload_bytes_hex || "";
  elements.signerLauncherCommandPreview.textContent =
    launcher?.signer_command ||
    (session
      ? "Guided signer files are not available yet. Prepare authorization again or use Download Sign Carrier Request."
      : "Prepare authorization to write the frozen carrier request to a stable local path and show the guided signer command.");

  elements.downloadSignCarrierRequest.disabled = !session;
  elements.runLocalSigner.disabled = !session;
  elements.loadGuidedSignerResponse.disabled = !session;
  elements.importSignCarrierResponse.disabled = !session;
  elements.copySignRequestJson.disabled = !session;
  elements.copyPayloadBytes.disabled = !session;
  elements.localDevSign.disabled = !canLocalDevSign;
  elements.composeTransaction.disabled =
    !session || !state.authorizationSignResponse || Boolean(state.authorizationResponseError);
  elements.clearAuthorizationResponse.disabled = !elements.authorizationResponseInput.value.trim();
}

function switchTab(tab) {
  state.activeTab = tab;
  persistPreviewTab();
  const showMarkdown = tab === "markdown";
  elements.tabMarkdown.classList.toggle("active", showMarkdown);
  elements.tabHtml.classList.toggle("active", !showMarkdown);
  elements.markdownPreview.classList.toggle("hidden", !showMarkdown);
  elements.htmlPreview.classList.toggle("hidden", showMarkdown);
}

function switchMode(mode) {
  state.activeMode = mode;
  persistActiveMode();
  const composeActive = mode === "compose";
  elements.modeCompose.classList.toggle("active", composeActive);
  elements.modeInspect.classList.toggle("active", !composeActive);
  elements.composeSection.classList.toggle("hidden", !composeActive);
  elements.inspectSection.classList.toggle("hidden", composeActive);
}

function downloadReceipt(kind, filename, content) {
  if (!content) {
    setStatus(
      `Nothing to export yet. Build or inspect a canonical record before downloading ${kind}.`,
      "error",
    );
    return;
  }
  downloadReceiptFile(filename, content, kind === "html" ? "text/html" : "text/markdown");
  setStatus(`Downloaded ${kind === "html" ? "HTML" : "Markdown"} receipt.`, "success");
}

function downloadReceiptPair() {
  if (!state.markdown || !state.html) {
    setStatus(
      `Nothing to export yet. Build or inspect a canonical record before using ${WORKBENCH_ACTION_LABELS.exportReceiptPair}.`,
      "error",
    );
    return;
  }
  downloadReceiptFile(RECEIPT_FILENAMES.markdown, state.markdown, "text/markdown");
  downloadReceiptFile(RECEIPT_FILENAMES.html, state.html, "text/html");
  setStatus(`${WORKBENCH_ACTION_LABELS.exportReceiptPair} completed (.md + .html).`, "success");
}

function exportComposeBundle() {
  if (!hasComposeBundleReady()) {
    setStatus(
      `Nothing to export yet. Build a canonical compose result before using ${WORKBENCH_ACTION_LABELS.exportComposeBundle}.`,
      "error",
    );
    return;
  }

  const bundle = buildComposeBundleFiles();
  for (const file of bundle) {
    downloadReceiptFile(file.filename, file.contents, file.mimeType);
  }
  setStatus(`${WORKBENCH_ACTION_LABELS.exportComposeBundle} completed (6 files).`, "success");
}

function downloadReceiptFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(link.href);
}

async function copySummaryJson() {
  if (!state.summary) {
    setStatus(
      "Nothing to copy yet. Build or inspect a canonical record before copying summary JSON.",
      "error",
    );
    return;
  }
  await copyText(
    JSON.stringify(state.summary, null, 2),
    "Copied canonical summary JSON.",
    "Unable to copy canonical summary JSON.",
  );
}

async function copyMarkdownReceipt() {
  if (!state.markdown) {
    setStatus(
      "Nothing to copy yet. Build or inspect a canonical record before copying Markdown.",
      "error",
    );
    return;
  }
  await copyText(state.markdown, "Copied Markdown receipt.", "Unable to copy Markdown receipt.");
}

async function copyNotarizationRecordDigest() {
  const digest = state.summary?.notarization_record_digest_hex;
  if (!digest) {
    setStatus(
      "Nothing to copy yet. Build or inspect a canonical record before copying the notarization record digest.",
      "error",
    );
    return;
  }
  await copyText(
    digest,
    "Copied notarization record digest.",
    "Unable to copy notarization record digest.",
  );
}

async function copyHtmlReceipt() {
  if (!state.html) {
    setStatus(
      "Nothing to copy yet. Build or inspect a canonical record before copying HTML.",
      "error",
    );
    return;
  }
  await copyText(state.html, "Copied HTML receipt.", "Unable to copy HTML receipt.");
}

async function copyText(text, successMessage, failureMessage) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      setStatus(successMessage, "success");
      return;
    }

    const helper = document.createElement("textarea");
    helper.value = text;
    helper.setAttribute("readonly", "");
    helper.style.position = "absolute";
    helper.style.left = "-9999px";
    document.body.appendChild(helper);
    helper.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(helper);
    if (!copied) {
      throw new Error("copy command was rejected");
    }
    setStatus(successMessage, "success");
  } catch (_) {
    setStatus(failureMessage, "error");
  }
}

function setStatus(message, tone) {
  elements.status.textContent = message;
  elements.status.className = `status ${tone}`;
}

function setActionAvailability(hasInspection) {
  for (const button of DERIVED_ACTION_BUTTONS) {
    button.disabled = !hasInspection;
  }
  elements.exportComposeBundle.disabled = !hasComposeBundleReady();
  elements.downloadExportBundleJson.disabled = !hasComposeBundleReady();
  elements.copyExportBundleJson.disabled = !hasComposeBundleReady();
}

function clearDerivedOutputs(preservePreparedSession) {
  state.summary = null;
  state.markdown = "";
  state.html = "";
  state.notarizationRecord = null;
  state.composeRequest = null;
  state.lastDerivedMode = null;
  state.lastInspectedRecordText = null;
  state.lastComposedDraftFingerprint = preservePreparedSession && state.authorizationSession
    ? stableStringify(state.authorizationSession.compose_request)
    : null;

  if (preservePreparedSession && state.authorizationSession) {
    state.burnSummary = deepClone(state.authorizationSession.burn_summary);
    state.transaction = deepClone(state.authorizationSession.transaction);
    state.publicStatement = deepClone(state.authorizationSession.public_statement);
  } else {
    state.burnSummary = null;
    state.transaction = null;
    state.publicStatement = null;
  }

  renderSummary();
  renderCanonicalPath();
  renderPreviews();
  renderAuthorizationState();
  setActionAvailability(false);
}

function clearAuthorizationResponseState({ clearInputText }) {
  state.authorizationSignCarrierResponse = null;
  state.authorizationSignResponse = null;
  state.authorizationSignScope = null;
  state.authorizationResponseError = null;
  if (clearInputText) {
    elements.authorizationResponseInput.value = "";
  }
}

function clearPreparedAuthorizationState({ clearInputs }) {
  state.authorizationSession = null;
  state.signerLauncher = null;
  clearAuthorizationResponseState({ clearInputText: true });
  elements.importSignCarrierResponseFile.value = "";
  if (clearInputs) {
    elements.authorizationSignerPublicKey.value = "";
    elements.authorizationNonce.value = "";
  }
  renderAuthorizationState();
}

function markInspectionStale(reason) {
  clearDerivedOutputs(false);
  setStatus(reason, "idle");
}

function markCompositionStale(reason) {
  clearPreparedAuthorizationState({ clearInputs: false });
  clearDerivedOutputs(false);
  setStatus(reason, "idle");
}

function persistRecordInput() {
  try {
    localStorage.setItem(RECORD_JSON_STORAGE_KEY, elements.recordInput.value);
  } catch (_) {
    // Keep the workbench usable even if local storage is unavailable.
  }
}

function restorePersistedRecordInput() {
  try {
    const stored = localStorage.getItem(RECORD_JSON_STORAGE_KEY);
    if (typeof stored === "string") {
      elements.recordInput.value = stored;
    }
  } catch (_) {
    // Keep the workbench usable even if local storage is unavailable.
  }
}

function persistComposeDraft() {
  try {
    localStorage.setItem(COMPOSE_REQUEST_STORAGE_KEY, JSON.stringify(readComposeDraftFromDom()));
  } catch (_) {
    // Keep the workbench usable even if local storage is unavailable.
  }
}

function restorePersistedComposeDraft() {
  try {
    const stored = localStorage.getItem(COMPOSE_REQUEST_STORAGE_KEY);
    if (!stored) return;
    loadComposeDraft(JSON.parse(stored), null);
  } catch (_) {
    ensureComposeRows();
  }
}

function persistPreviewTab() {
  try {
    localStorage.setItem(PREVIEW_TAB_STORAGE_KEY, state.activeTab);
  } catch (_) {
    // Keep the workbench usable even if local storage is unavailable.
  }
}

function restorePersistedPreviewTab() {
  try {
    const stored = localStorage.getItem(PREVIEW_TAB_STORAGE_KEY);
    if (stored === "markdown" || stored === "html") {
      state.activeTab = stored;
    }
  } catch (_) {
    // Keep the workbench usable even if local storage is unavailable.
  }
}

function persistActiveMode() {
  try {
    localStorage.setItem(ACTIVE_MODE_STORAGE_KEY, state.activeMode);
  } catch (_) {
    // Keep the workbench usable even if local storage is unavailable.
  }
}

function restorePersistedActiveMode() {
  try {
    const stored = localStorage.getItem(ACTIVE_MODE_STORAGE_KEY);
    if (stored === "compose" || stored === "inspect") {
      state.activeMode = stored;
    }
  } catch (_) {
    // Keep the workbench usable even if local storage is unavailable.
  }
}

function handleRecordInputChange() {
  persistRecordInput();
  if (
    state.lastDerivedMode === "inspect" &&
    state.lastInspectedRecordText !== null &&
    elements.recordInput.value !== state.lastInspectedRecordText
  ) {
    markInspectionStale(STALE_INSPECT_STATUS_MESSAGE);
  }
}

function handleComposeDraftChange() {
  persistComposeDraft();
  if (!state.authorizationSession) {
    return;
  }

  const currentComposeFingerprint = stableStringify(normalizeComposeDraft(readComposeDraftFromDom()));
  const preparedComposeFingerprint = stableStringify(state.authorizationSession.compose_request);
  if (currentComposeFingerprint !== preparedComposeFingerprint) {
    markCompositionStale(STALE_COMPOSE_STATUS_MESSAGE);
  }
}

function handleAuthorizationInputChange() {
  if (!state.authorizationSession) {
    renderAuthorizationState();
    return;
  }

  const payload = state.authorizationSession.authorization_sign_request?.payload;
  const signerChanged =
    elements.authorizationSignerPublicKey.value.trim() !== payload?.signer_public_key_hex;
  const nonceChanged =
    elements.authorizationNonce.value.trim() !== payload?.authorization_nonce_hex;
  if (signerChanged || nonceChanged) {
    markCompositionStale(STALE_COMPOSE_STATUS_MESSAGE);
    return;
  }

  renderAuthorizationState();
}

function handleRowButtonClick(event) {
  const button = event.target.closest("[data-action]");
  if (!button) return;

  const row = button.closest(".row-item");
  if (!row) return;

  if (button.dataset.action === "remove-input") {
    row.remove();
    ensureComposeRows();
    handleComposeDraftChange();
  }
  if (button.dataset.action === "remove-output") {
    row.remove();
    ensureComposeRows();
    handleComposeDraftChange();
  }
}

function loadRecordInput(text, statusMessage) {
  elements.recordInput.value = text;
  persistRecordInput();
  if (state.lastDerivedMode === "inspect") {
    clearDerivedOutputs(false);
  }
  if (statusMessage) {
    setStatus(statusMessage, "success");
  }
}

function loadComposeDraft(draft, statusMessage) {
  elements.composeRollupId.value = draft.rollup_id_hex || "";
  elements.composeAssetId.value = draft.asset_id_hex || "";
  elements.composeAnchorRoot.value = draft.anchor_state_root_hex || "";

  elements.composeInputs.innerHTML = "";
  elements.composeOutputs.innerHTML = "";
  const inputs = Array.isArray(draft.inputs) && draft.inputs.length > 0 ? draft.inputs : [{}];
  const outputs = Array.isArray(draft.outputs) && draft.outputs.length > 0 ? draft.outputs : [{}];
  for (const input of inputs) {
    addInputRow(input);
  }
  for (const output of outputs) {
    addOutputRow(output);
  }
  ensureComposeRows();
  persistComposeDraft();
  clearPreparedAuthorizationState({ clearInputs: false });
  clearDerivedOutputs(false);
  if (statusMessage) {
    setStatus(statusMessage, "success");
  }
}

function clearInspectDraft() {
  elements.recordInput.value = "";
  elements.fileInput.value = "";
  persistRecordInput();
  if (state.lastDerivedMode === "inspect") {
    clearDerivedOutputs(false);
  }
  setStatus("Cleared inspect draft JSON.", "idle");
}

function resetWorkbench() {
  elements.recordInput.value = "";
  elements.fileInput.value = "";
  elements.composeRollupId.value = "";
  elements.composeAssetId.value = "";
  elements.composeAnchorRoot.value = "";
  elements.composeInputs.innerHTML = "";
  elements.composeOutputs.innerHTML = "";
  ensureComposeRows();

  try {
    localStorage.removeItem(RECORD_JSON_STORAGE_KEY);
    localStorage.removeItem(COMPOSE_REQUEST_STORAGE_KEY);
  } catch (_) {
    // Keep the workbench usable even if local storage is unavailable.
  }

  clearPreparedAuthorizationState({ clearInputs: true });
  clearDerivedOutputs(false);
  switchMode("compose");
  switchTab("markdown");
  setStatus(IDLE_STATUS_MESSAGE, "idle");
}

function initializeWorkbench() {
  ensureComposeRows();
  restorePersistedRecordInput();
  restorePersistedComposeDraft();
  restorePersistedPreviewTab();
  restorePersistedActiveMode();
  clearPreparedAuthorizationState({ clearInputs: false });
  clearDerivedOutputs(false);
  switchTab(state.activeTab);
  switchMode(state.activeMode);

  if (elements.recordInput.value.length > 0 && state.activeMode === "inspect") {
    setStatus(
      "Restored the last canonical record wire JSON draft. Inspect to derive canonical outputs.",
      "idle",
    );
  } else if (hasComposeDraft()) {
    setStatus(
      "Restored the last compose draft. Fill signer inputs, prepare authorization, then complete compose.",
      "idle",
    );
  } else {
    setStatus(IDLE_STATUS_MESSAGE, "idle");
  }
}

function ensureComposeRows() {
  if (!elements.composeInputs.children.length) {
    addInputRow();
  }
  if (!elements.composeOutputs.children.length) {
    addOutputRow();
  }
}

function addInputRow(values = {}) {
  const row = document.createElement("div");
  row.className = "row-item";
  row.innerHTML = `
    <label class="field">
      <span>Nullifier</span>
      <input type="text" class="compose-input-nullifier" spellcheck="false" placeholder="64 lowercase hex chars" value="${escapeAttribute(values.nullifier_hex || "")}" />
    </label>
    <label class="field">
      <span>Note Commitment Reference</span>
      <input type="text" class="compose-input-reference" spellcheck="false" placeholder="64 lowercase hex chars" value="${escapeAttribute(values.note_commitment_reference_hex || "")}" />
    </label>
    <button type="button" class="row-remove" data-action="remove-input">Remove</button>
  `;
  elements.composeInputs.appendChild(row);
}

function addOutputRow(values = {}) {
  const row = document.createElement("div");
  row.className = "row-item output-row";
  row.innerHTML = `
    <label class="field">
      <span>Note Commitment</span>
      <input type="text" class="compose-output-commitment" spellcheck="false" placeholder="64 lowercase hex chars" value="${escapeAttribute(values.note_commitment_hex || "")}" />
    </label>
    <button type="button" class="row-remove" data-action="remove-output">Remove</button>
  `;
  elements.composeOutputs.appendChild(row);
}

function readComposeDraftFromDom() {
  return {
    rollup_id_hex: elements.composeRollupId.value.trim(),
    asset_id_hex: elements.composeAssetId.value.trim(),
    anchor_state_root_hex: elements.composeAnchorRoot.value.trim(),
    inputs: Array.from(elements.composeInputs.querySelectorAll(".row-item")).map((row) => ({
      nullifier_hex: row.querySelector(".compose-input-nullifier")?.value.trim() || "",
      note_commitment_reference_hex:
        row.querySelector(".compose-input-reference")?.value.trim() || "",
    })),
    outputs: Array.from(elements.composeOutputs.querySelectorAll(".row-item")).map((row) => ({
      note_commitment_hex: row.querySelector(".compose-output-commitment")?.value.trim() || "",
    })),
  };
}

function normalizeComposeDraft(draft) {
  return {
    rollup_id_hex: draft.rollup_id_hex,
    asset_id_hex: draft.asset_id_hex,
    anchor_state_root_hex: draft.anchor_state_root_hex,
    inputs: draft.inputs.filter(
      (entry) => entry.nullifier_hex || entry.note_commitment_reference_hex,
    ),
    outputs: draft.outputs.filter((entry) => entry.note_commitment_hex),
  };
}

function buildComposePayload() {
  const draft = normalizeComposeDraft(readComposeDraftFromDom());
  requireNonEmptyField("rollup_id_hex", draft.rollup_id_hex, "Rollup ID is required.");
  requireNonEmptyField("asset_id_hex", draft.asset_id_hex, "Asset ID is required.");
  requireNonEmptyField(
    "anchor_state_root_hex",
    draft.anchor_state_root_hex,
    "Anchor State Root is required.",
  );

  if (!draft.inputs.length) {
    throw new Error("At least one input is required.");
  }
  if (!draft.outputs.length) {
    throw new Error("At least one output is required.");
  }

  for (const [index, input] of draft.inputs.entries()) {
    requireNonEmptyField(
      `inputs[${index}].nullifier_hex`,
      input.nullifier_hex,
      `Input ${index + 1} nullifier is required.`,
    );
    requireNonEmptyField(
      `inputs[${index}].note_commitment_reference_hex`,
      input.note_commitment_reference_hex,
      `Input ${index + 1} note commitment reference is required.`,
    );
  }

  for (const [index, output] of draft.outputs.entries()) {
    requireNonEmptyField(
      `outputs[${index}].note_commitment_hex`,
      output.note_commitment_hex,
      `Output ${index + 1} note commitment is required.`,
    );
  }

  return draft;
}

function buildPreparePayload() {
  const compose_request = buildComposePayload();
  const signer_public_key_hex = elements.authorizationSignerPublicKey.value.trim();
  const authorization_nonce_hex = elements.authorizationNonce.value.trim();

  requireNonEmptyField(
    "signer_public_key_hex",
    signer_public_key_hex,
    "Signer Public Key is required before preparing authorization.",
  );
  requireNonEmptyField(
    "authorization_nonce_hex",
    authorization_nonce_hex,
    "Authorization Nonce is required before preparing authorization.",
  );

  return {
    compose_request,
    signer_public_key_hex,
    authorization_nonce_hex,
  };
}

function buildSignCarrierRequest(session) {
  return {
    carrier_version: AUTHORIZATION_SIGN_CARRIER_VERSION_V1,
    session_id_hex: session.session_id_hex,
    authorization_sign_request: deepClone(session.authorization_sign_request),
  };
}

function buildSignCarrierResponse(sessionIdHex, signResponse) {
  return {
    carrier_version: AUTHORIZATION_SIGN_CARRIER_VERSION_V1,
    session_id_hex: sessionIdHex,
    authorization_sign_response: deepClone(signResponse),
  };
}

function buildSignCarrierRequestFilename(sessionIdHex) {
  return `aura_authorization_sign_carrier_request_${sessionIdHex}.json`;
}

function buildCompletionPayload() {
  if (!state.authorizationSession) {
    throw new Error("Prepare authorization is required before complete compose.");
  }
  if (state.authorizationResponseError) {
    throw new Error(state.authorizationResponseError);
  }
  if (!state.authorizationSignResponse) {
    throw new Error("A valid authorization sign response is required before complete compose.");
  }

  if (state.authorizationSignCarrierResponse) {
    return {
      session: deepClone(state.authorizationSession),
      sign_carrier_response: deepClone(state.authorizationSignCarrierResponse),
    };
  }

  return {
    session: deepClone(state.authorizationSession),
    sign_response: deepClone(state.authorizationSignResponse),
  };
}

function parseAuthorizationCarrierResponseInputValue(inputText) {
  const parsed = JSON.parse(inputText);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Sign carrier response JSON must be an object.");
  }
  if (parsed.carrier_version !== AUTHORIZATION_SIGN_CARRIER_VERSION_V1) {
    throw new Error("Unsupported sign carrier response version.");
  }
  if (typeof parsed.session_id_hex !== "string") {
    throw new Error("Sign carrier response must include session_id_hex.");
  }
  if (
    !parsed.authorization_sign_response ||
    typeof parsed.authorization_sign_response !== "object" ||
    Array.isArray(parsed.authorization_sign_response)
  ) {
    throw new Error("Sign carrier response must include authorization_sign_response.");
  }
  if (
    state.authorizationSession &&
    parsed.session_id_hex !== state.authorizationSession.session_id_hex
  ) {
    throw new Error("Sign carrier response session_id_hex does not match the prepared session.");
  }

  return {
    signCarrierResponse: parsed,
  };
}

function parseAuthorizationResponseInputValue(inputText) {
  const parsed = JSON.parse(inputText);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Authorization sign response JSON must be an object.");
  }

  if ("authorization_sign_response" in parsed || "carrier_version" in parsed) {
    const signCarrierResponse = parseAuthorizationCarrierResponseInputValue(inputText)
      .signCarrierResponse;
    return {
      signCarrierResponse,
      signResponse: signCarrierResponse.authorization_sign_response,
      signScope: null,
    };
  }

  if ("sign_response" in parsed) {
    if (
      !parsed.sign_response ||
      typeof parsed.sign_response !== "object" ||
      Array.isArray(parsed.sign_response)
    ) {
      throw new Error("Signer result JSON must contain a sign_response object.");
    }
    if (
      state.authorizationSession &&
      typeof parsed.session_id_hex === "string" &&
      parsed.session_id_hex !== state.authorizationSession.session_id_hex
    ) {
      throw new Error("Signer result session_id_hex does not match the prepared session.");
    }
    const signCarrierResponse =
      typeof parsed.session_id_hex === "string"
        ? buildSignCarrierResponse(parsed.session_id_hex, parsed.sign_response)
        : null;
    return {
      signCarrierResponse,
      signResponse: parsed.sign_response,
      signScope: typeof parsed.scope === "string" ? parsed.scope : null,
    };
  }

  return {
    signCarrierResponse: null,
    signResponse: parsed,
    signScope: null,
  };
}

function buildComposeBundleFiles() {
  return [
    {
      filename: COMPOSE_BUNDLE_FILENAMES.composeRequest,
      contents: JSON.stringify(state.composeRequest, null, 2),
      mimeType: "application/json",
    },
    {
      filename: COMPOSE_BUNDLE_FILENAMES.transaction,
      contents: JSON.stringify(state.transaction, null, 2),
      mimeType: "application/json",
    },
    {
      filename: COMPOSE_BUNDLE_FILENAMES.publicStatement,
      contents: JSON.stringify(state.publicStatement, null, 2),
      mimeType: "application/json",
    },
    {
      filename: COMPOSE_BUNDLE_FILENAMES.notarizationRecord,
      contents: JSON.stringify(state.notarizationRecord, null, 2),
      mimeType: "application/json",
    },
    {
      filename: COMPOSE_BUNDLE_FILENAMES.markdown,
      contents: state.markdown,
      mimeType: "text/markdown",
    },
    {
      filename: COMPOSE_BUNDLE_FILENAMES.html,
      contents: state.html,
      mimeType: "text/html",
    },
  ];
}

function requireNonEmptyField(_field, value, message) {
  if (!value) {
    throw new Error(message);
  }
}

function hasComposeDraft() {
  const draft = normalizeComposeDraft(readComposeDraftFromDom());
  return Boolean(
    draft.rollup_id_hex ||
      draft.asset_id_hex ||
      draft.anchor_state_root_hex ||
      draft.inputs.length ||
      draft.outputs.length,
  );
}

function hasComposeBundleReady() {
  return Boolean(
    state.lastDerivedMode === "compose" &&
      state.composeRequest &&
      state.transaction &&
      state.publicStatement &&
      state.notarizationRecord &&
      state.markdown &&
      state.html,
  );
}

function formatInspectError(error) {
  if (error instanceof SyntaxError) {
    return "Inspect failed: input is not valid canonical JSON.";
  }
  const message = error?.message || "Inspection failed.";
  return message.startsWith("Inspect failed:") ? message : `Inspect failed: ${message}`;
}

function formatActionError(prefix, error) {
  const message = error?.message || `${prefix} failed.`;
  return message.startsWith(`${prefix} failed:`) ? message : `${prefix} failed: ${message}`;
}

function formatJsonPreview(value) {
  return value ? JSON.stringify(value, null, 2) : "";
}

function formatBurnField(value) {
  return value === null || value === undefined ? "—" : String(value);
}

function stableStringify(value) {
  return JSON.stringify(value);
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value);
}
