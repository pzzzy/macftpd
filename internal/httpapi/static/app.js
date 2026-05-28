(() => {
  if (location.username || location.password) {
    location.replace(location.protocol + "//" + location.host + location.pathname + location.search + location.hash);
    return;
  }

  const qs = (id) => document.getElementById(id);
  const escPath = (path) => encodeURIComponent(path || "/");

  async function parseJSONResponse(response) {
    let body = {};
    try {
      body = await response.json();
    } catch {
      const text = await response.text().catch(() => "");
      body = { error: text || response.statusText };
    }
    if (!response.ok) throw new Error(body.error || response.statusText);
    return body;
  }

  function uploadID() {
    const bytes = new Uint8Array(12);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function currentPath() {
    return qs("file-path")?.value || "/";
  }

  function selectedPaths() {
    return Array.from(document.querySelectorAll("[data-file-check]:checked")).map((el) => el.value);
  }

  function setNotice(message, kind = "info") {
    const box = qs("admin-notice");
    if (!box) return;
    box.textContent = message || "";
    box.className = message ? `alert alert-${kind} min-h-10 py-2 text-sm` : "hidden";
  }

  function partialURL(path, selected = "") {
    const url = new URL("/admin/partials/files", location.origin);
    url.searchParams.set("path", path || "/");
    if (selected) url.searchParams.set("selected", selected);
    return url.pathname + url.search;
  }

  function adminURL(path, selected = "") {
    const url = new URL("/admin/", location.origin);
    url.searchParams.set("path", path || "/");
    if (selected) url.searchParams.set("selected", selected);
    return url.pathname + url.search;
  }

  function reloadFiles(path = currentPath(), selected = "") {
    if (!window.htmx) return;
    window.htmx.ajax("GET", partialURL(path, selected), {
      target: "#file-workspace",
      swap: "innerHTML",
    });
    history.replaceState({ path, selected }, "", adminURL(path, selected));
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !(options.body instanceof FormData) && !headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }
    return parseJSONResponse(await fetch(path, { credentials: "same-origin", ...options, headers }));
  }

  async function uploadOneFile(file, index, total) {
    const chunkSize = 16 * 1024 * 1024;
    const id = uploadID();
    let offset = 0;
    if (file.size === 0) {
      const fd = new FormData();
      fd.append("path", currentPath());
      fd.append("filename", file.name);
      fd.append("upload_id", id);
      fd.append("offset", "0");
      fd.append("total_size", "0");
      fd.append("chunk", new Blob([]), file.name);
      return parseJSONResponse(await fetch("/api/upload/chunk", { method: "POST", body: fd, credentials: "same-origin" }));
    }
    while (offset < file.size) {
      const end = Math.min(offset + chunkSize, file.size);
      const fd = new FormData();
      fd.append("path", currentPath());
      fd.append("filename", file.name);
      fd.append("upload_id", id);
      fd.append("offset", String(offset));
      fd.append("total_size", String(file.size));
      fd.append("chunk", file.slice(offset, end), file.name);
      setNotice(`Uploading ${index}/${total}: ${file.name} ${Math.floor((end / file.size) * 100)}%`);
      await parseJSONResponse(await fetch("/api/upload/chunk", { method: "POST", body: fd, credentials: "same-origin" }));
      offset = end;
    }
  }

  async function uploadFiles(files) {
    files = Array.from(files || []);
    if (!files.length) return;
    try {
      for (let i = 0; i < files.length; i++) await uploadOneFile(files[i], i + 1, files.length);
      setNotice(`Uploaded ${files.length} file${files.length === 1 ? "" : "s"}`, "success");
      reloadFiles();
    } catch (error) {
      setNotice(error.message || String(error), "error");
    }
  }

  function bindFileWorkspace(root = document) {
    const workspace = root.id === "file-workspace" ? root : root.querySelector("#file-workspace");
    if (!workspace) return;

    workspace.querySelectorAll("[data-open-file]").forEach((row) => {
      row.addEventListener("dblclick", () => {
        const path = row.dataset.openFile;
        const isDir = row.dataset.dir === "true";
        if (isDir) {
          window.htmx.ajax("GET", partialURL(path), { target: "#file-workspace", swap: "innerHTML" });
          history.pushState({ path, selected: "" }, "", adminURL(path));
        }
      });
    });

    const search = qs("file-search");
    if (search) {
      search.addEventListener("input", () => {
        const needle = search.value.trim().toLowerCase();
        workspace.querySelectorAll("[data-open-file]").forEach((row) => {
          row.classList.toggle("hidden", needle && !row.dataset.search.toLowerCase().includes(needle));
        });
      });
    }

    const selectAll = qs("select-all-files");
    if (selectAll) {
      selectAll.addEventListener("change", () => {
        workspace.querySelectorAll("[data-file-check]").forEach((box) => {
          box.checked = selectAll.checked;
        });
      });
    }

    const uploadInput = qs("upload-files");
    if (uploadInput) {
      uploadInput.addEventListener("change", () => uploadFiles(uploadInput.files));
    }
    const dropzone = qs("upload-dropzone");
    if (dropzone) {
      ["dragenter", "dragover"].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.add("drop-active");
      }));
      ["dragleave", "drop"].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.remove("drop-active");
      }));
      dropzone.addEventListener("drop", (event) => uploadFiles(event.dataTransfer.files));
    }

    const selected = workspace.querySelector("[data-selected-path]")?.dataset.selectedPath || "";
    const linkPath = qs("link-path");
    if (selected && linkPath) linkPath.value = selected;
  }

  async function deletePath(path) {
    if (!path || !confirm(`Move ${path} to trash?`)) return;
    try {
      await api(`/api/files?path=${escPath(path)}`, { method: "DELETE" });
      setNotice(`Deleted ${path}`, "success");
      reloadFiles();
      window.htmx?.trigger("#activity-panel", "refresh");
    } catch (error) {
      setNotice(error.message || String(error), "error");
    }
  }

  async function renamePath(path) {
    const dest = prompt("Rename or move to", path);
    if (!dest || dest === path) return;
    try {
      const result = await api(`/api/files?path=${escPath(path)}`, {
        method: "PATCH",
        body: JSON.stringify({ dest_path: dest }),
      });
      setNotice(`Moved to ${result.entry.path}`, "success");
      reloadFiles(result.entry.path.split("/").slice(0, -1).join("/") || "/", result.entry.path);
    } catch (error) {
      setNotice(error.message || String(error), "error");
    }
  }

  async function makeFolder() {
    const name = prompt("Folder name");
    if (!name) return;
    const base = currentPath().replace(/\/+$/, "");
    const path = `${base || ""}/${name}` || "/";
    try {
      await api(`/api/files?path=${escPath(path)}`, { method: "POST", body: "{}" });
      setNotice(`Created ${path}`, "success");
      reloadFiles(currentPath(), path);
    } catch (error) {
      setNotice(error.message || String(error), "error");
    }
  }

  async function copyMove(operation, explicitPaths) {
    const paths = explicitPaths?.length ? explicitPaths : selectedPaths();
    if (!paths.length) {
      setNotice("Select one or more files first", "warning");
      return;
    }
    const dest = prompt(`${operation === "copy" ? "Copy" : "Move"} ${paths.length} item${paths.length === 1 ? "" : "s"} to`, operation === "copy" ? "/public" : currentPath());
    if (!dest) return;
    const overwrite = confirm("Overwrite an existing destination if needed?");
    try {
      const result = await api("/api/files/action", {
        method: "POST",
        body: JSON.stringify({ operation, paths, dest_path: dest, deduplicate: true, overwrite }),
      });
      const selected = result.items?.[0]?.dest_path || "";
      setNotice(`${operation === "copy" ? "Copied" : "Moved"} ${paths.length} item${paths.length === 1 ? "" : "s"}`, "success");
      reloadFiles(operation === "move" && selected ? (selected.split("/").slice(0, -1).join("/") || "/") : currentPath(), selected);
      window.htmx?.trigger("#activity-panel", "refresh");
    } catch (error) {
      setNotice(error.message || String(error), "error");
    }
  }

  function copyText(text) {
    navigator.clipboard.writeText(text).then(
      () => setNotice("Copied link", "success"),
      () => setNotice(text)
    );
  }

  window.macftpd = {
    reloadFiles,
    uploadFiles,
    deletePath,
    renamePath,
    makeFolder,
    copyMove,
    copyText,
    download(path) {
      location.href = `/api/download?path=${escPath(path)}`;
    },
  };

  document.addEventListener("htmx:afterSwap", (event) => bindFileWorkspace(event.target));
  document.addEventListener("DOMContentLoaded", () => bindFileWorkspace(document));
  window.addEventListener("popstate", () => {
    if (!window.htmx || !qs("file-workspace")) return;
    const params = new URLSearchParams(location.search);
    window.htmx.ajax("GET", partialURL(params.get("path") || "/", params.get("selected") || ""), {
      target: "#file-workspace",
      swap: "innerHTML",
    });
  });
})();
