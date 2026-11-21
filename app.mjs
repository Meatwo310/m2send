import {
  certFromLink, createRecipient, decrypt, encrypt, importPrivateKey, pem, readPem,
  readRecipient, recipientLink,
} from "./cms.mjs";

const element = id => document.getElementById(id);
const status = element("status");
const maxFile = 16 * 1024 * 1024;
const maxText = 1024 * 1024;
let activeKey;
let ciphertext;
let plaintext;
let busy = false;
let recipientRevision = 0;

function report(message, error = false) {
  status.textContent = message;
  status.toggleAttribute("data-error", error);
}

function showPanel(name) {
  for (const button of document.querySelectorAll("[data-panel]")) {
    const selected = button.dataset.panel === name;
    button.setAttribute("aria-pressed", selected);
    element(button.dataset.panel).hidden = !selected;
  }
  report("");
}

async function run(button, operation, fallback) {
  if (busy) return;
  busy = true;
  button.disabled = true;
  report("処理中…");
  try {
    await operation();
  } catch {
    report(fallback, true);
  } finally {
    busy = false;
    button.disabled = false;
  }
}

function download(content, name, type = "application/octet-stream") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copy(id, label) {
  const field = element(id);
  try {
    await navigator.clipboard.writeText(field.value);
    report(label + "をコピーしました。");
  } catch {
    field.focus();
    field.select();
    report("選択した内容を手動でコピーしてください。");
  }
}

async function fingerprint(cert) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", cert));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join(":");
}

function certificate(value) {
  const input = value.trim();
  if (input.length > 12 * 1024) throw new Error("Certificate is too large");
  return input.startsWith("-----BEGIN ")
    ? readPem("CERTIFICATE", input)
    : certFromLink(input, location.href);
}

async function previewRecipient() {
  const revision = ++recipientRevision;
  const details = element("recipient-details");
  details.hidden = true;
  try {
    const cert = certificate(element("recipient").value);
    await readRecipient(cert);
    const value = await fingerprint(cert);
    if (revision === recipientRevision) {
      element("recipient-fingerprint").textContent = value;
      details.hidden = false;
    }
  } catch {
    // The input may be incomplete while the user types. Submit reports errors.
  }
}

function linkFromLocation() {
  if (!location.hash.startsWith("#v=")) return;
  const link = location.href;
  history.replaceState(null, "", location.pathname);
  showPanel("send");
  element("recipient").value = link;
  void previewRecipient();
}

async function fileBytes(id, limit) {
  const file = element(id).files[0];
  if (!file || file.size > limit) throw new Error("Missing or oversized file");
  return new Uint8Array(await file.arrayBuffer());
}

function readCiphertext(bytes) {
  return bytes[0] === 0x30 ? bytes : readPem("CMS", new TextDecoder().decode(bytes));
}

function clearDecrypted() {
  plaintext?.fill(0);
  plaintext = undefined;
  element("decrypted-text").value = "";
  element("decrypted").hidden = true;
}

function toggleMode(action) {
  const text = element(action + "-kind").value === "text";
  element(action + "-text-field").hidden = !text;
  element(action + "-file-field").hidden = text;
}

if (globalThis.crypto?.subtle) {
  for (const button of document.querySelectorAll("[data-panel]")) {
    button.addEventListener("click", () => {
      if (!busy) showPanel(button.dataset.panel);
    });
  }

  for (const action of ["encrypt", "decrypt"]) {
    element(action + "-kind").addEventListener("change", () => toggleMode(action));
    element(action).querySelector("button[type=submit]").disabled = false;
  }

  element("create-key").addEventListener("click", event => run(event.currentTarget, async () => {
    const recipient = await createRecipient();
    element("own-fingerprint").textContent = await fingerprint(recipient.cert);
    activeKey = recipient.privateKey;
    element("share-link").value = recipientLink(location.href, recipient.cert);
    element("key-info").hidden = false;
    element("key-file-field").hidden = true;
    element("create-key").hidden = true;
    report("受信用の鍵を作りました。");
  }, "鍵を作成できませんでした。"));

  element("save-key").addEventListener("click", event => run(event.currentTarget, async () => {
    const bytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", activeKey));
    try {
      download(pem("PRIVATE KEY", bytes), "m2send-private.pem", "application/x-pem-file");
      report("秘密鍵を保存します。受信者の端末だけで保管してください。");
    } finally {
      bytes.fill(0);
    }
  }, "秘密鍵を保存できませんでした。"));

  element("clear-key").addEventListener("click", () => {
    if (busy) return;
    activeKey = undefined;
    element("share-link").value = "";
    element("own-fingerprint").textContent = "";
    element("key-file").value = "";
    element("key-info").hidden = true;
    element("key-file-field").hidden = false;
    element("create-key").hidden = false;
    clearDecrypted();
    report("このタブの鍵を破棄しました。保存した秘密鍵は端末で削除してください。");
  });

  element("copy-link").addEventListener("click", () => copy("share-link", "リンク"));
  element("copy-ciphertext").addEventListener("click", () => copy("encrypted-text", "暗号文"));
  element("recipient").addEventListener("input", () => {
    recipientRevision++;
    element("recipient-details").hidden = true;
  });
  element("recipient").addEventListener("change", previewRecipient);
  window.addEventListener("hashchange", linkFromLocation);

  element("encrypt").addEventListener("submit", event => {
    event.preventDefault();
    const form = event.currentTarget;
    void run(form.querySelector("button[type=submit]"), async () => {
      element("encrypted").hidden = true;
      element("encrypted-text").value = "";
      ciphertext = undefined;
      let recipient;
      try {
        recipient = await readRecipient(certificate(element("recipient").value));
      } catch {
        report("送信用リンクまたは公開証明書を確認してください。", true);
        return;
      }

      const isText = element("encrypt-kind").value === "text";
      const bytes = isText ? new TextEncoder().encode(element("encrypt-text").value)
        : await fileBytes("encrypt-file", maxFile);
      try {
        if (isText && bytes.length > maxText) {
          report("テキストは最大 1 MiB です。大きい場合はファイルとして選択してください。", true);
          return;
        }
        ciphertext = await encrypt(bytes, recipient);
        element("encrypted-text").value = isText ? pem("CMS", ciphertext) : "";
        for (const id of ["encrypted-label", "encrypted-text", "copy-ciphertext"]) {
          element(id).hidden = !isText;
        }
        element("encrypted").hidden = false;
        report("暗号化しました。暗号文を受信者に返してください。");
      } finally {
        bytes.fill(0);
      }
    }, "暗号化できませんでした。ファイルの選択とサイズを確認してください。");
  });

  element("decrypt").addEventListener("submit", event => {
    event.preventDefault();
    const form = event.currentTarget;
    void run(form.querySelector("button[type=submit]"), async () => {
      clearDecrypted();
      let key = activeKey;
      if (!key) {
        let rawKey;
        try {
          const keyFile = await fileBytes("key-file", 8192);
          try {
            rawKey = readPem("PRIVATE KEY", new TextDecoder().decode(keyFile));
            key = await importPrivateKey(rawKey);
          } finally {
            keyFile.fill(0);
          }
        } catch {
          report("受信用の鍵を作ったタブを使うか、保存した秘密鍵を選択してください。", true);
          return;
        } finally {
          rawKey?.fill(0);
        }
      }

      const isText = element("decrypt-kind").value === "text";
      const input = element("decrypt-text").value;
      if (isText && input.length > 2 * maxText) {
        report("暗号文が長すぎます。暗号化ファイルとして選択してください。", true);
        return;
      }
      const data = isText ? readPem("CMS", input)
        : readCiphertext(await fileBytes("decrypt-file", 23 * 1024 * 1024));
      if (data.length > maxFile + 8192) throw new Error("Oversized ciphertext");
      plaintext = await decrypt(data, key);
      let message;
      if (isText) {
        try {
          message = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(plaintext);
        } catch {
          // Binary plaintext is still available as a download.
        }
      }
      element("decrypted-text").value = message ?? "";
      element("decrypted-text").hidden = message === undefined;
      element("decrypted-label").hidden = message === undefined;
      element("decrypted").hidden = false;
      report("復号しました。");
    }, "復号できませんでした。暗号文の形式・サイズと、宛先に対応する秘密鍵を確認してください。");
  });

  element("save-ciphertext").addEventListener("click", () => download(ciphertext, "m2send.cms"));
  element("save-plaintext").addEventListener("click", () => download(plaintext, "m2send-decrypted"));
  linkFromLocation();
} else {
  element("create-key").disabled = true;
  report("このツールは HTTPS または localhost で開いてください。", true);
}
