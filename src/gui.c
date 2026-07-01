#include "eyas_crypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
typedef int send_len_t;
typedef int recv_len_t;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_t;
typedef size_t send_len_t;
typedef ssize_t recv_len_t;
#endif

#ifdef _WIN32
#define EYAS_RECV_CHUNK 32768
#else
#define EYAS_RECV_CHUNK 32768UL
#endif

static const char *page_head =
    "<!doctype html><html lang=en><head><meta charset=utf-8>"
    "<meta name=viewport content=\"width=device-width,initial-scale=1\"><title>eyas-crypt</title>"
    "<style>"
    ":root{--bg:#15121E;--bg2:#1E1B2E;--sep:#3D3860;--text:#EAE6FF;--text2:rgba(234,230,255,.65);--dim:#8A85A8;--purple:#B57BFF;--cyan:#72D9F5;--green:#56D98A;--yellow:#FFD166;--red:#FF7875;--radius:10px;--radius-lg:14px;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}"
    "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}"
    "body{background:var(--bg);color:var(--text);font-family:var(--font);display:flex;flex-direction:column;min-height:100vh;-webkit-font-smoothing:antialiased}"
    "::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:var(--sep);border-radius:4px}"
    ".label{font-size:.6rem;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}"
    ".prog{height:4px;border-radius:4px;background:rgba(114,217,245,.12);overflow:hidden;margin-top:14px;display:none;position:relative}"
    ".prog.on{display:block}"
    ".prog::after{content:'';position:absolute;top:0;left:-40%;height:100%;width:40%;border-radius:4px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:prog 1.1s ease-in-out infinite}"
    "@keyframes prog{0%{left:-40%}100%{left:100%}}"
    ".logo{background:linear-gradient(120deg,var(--purple),var(--cyan));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;font-weight:700;font-size:1.1rem;letter-spacing:-.03em}";

static const char *page_head2 =
    "header{border-bottom:1px solid var(--sep);padding:14px 0}.bar{max-width:760px;margin:0 auto;padding:0 24px;display:flex;align-items:center;justify-content:space-between;gap:12px}"
    "main{flex:1;width:100%;max-width:760px;margin:0 auto;padding:34px 24px 28px}"
    ".modes{display:flex;gap:8px;margin-bottom:16px}"
    ".mode-btn{flex:1;height:40px;font-size:.8rem;font-weight:600;border-radius:var(--radius);background:transparent;border:1px solid var(--sep);color:var(--dim);cursor:pointer;font-family:var(--font);transition:color .15s,border-color .15s,background .15s}"
    ".mode-btn:hover{color:var(--text2)}"
    ".mode-btn.active{color:var(--purple);border-color:rgba(181,123,255,.5);background:rgba(181,123,255,.12)}"
    ".card{background:var(--bg2);border:1px solid var(--sep);border-radius:var(--radius-lg);padding:20px}"
    ".file{display:flex;align-items:center;gap:12px;flex-wrap:wrap}"
    ".filebtn{display:inline-flex;align-items:center;gap:8px;height:42px;padding:0 18px;background:var(--bg);border:1px solid var(--sep);border-radius:var(--radius);color:var(--text2);font-size:.8rem;font-weight:500;cursor:pointer;white-space:nowrap;transition:border-color .15s,color .15s,box-shadow .15s}"
    ".filebtn:hover{border-color:var(--purple);color:var(--purple);box-shadow:0 0 16px rgba(181,123,255,.1)}"
    ".filebtn input{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}"
    ".fname{font-size:.72rem;color:var(--dim);word-break:break-all;min-width:0}"
    "h2{font-size:.95rem;font-weight:600;margin-bottom:14px}.field{margin:12px 0}"
    "label{display:block;font-size:.7rem;color:var(--text2);margin-bottom:6px}"
    "input{width:100%;height:44px;background:var(--bg);border:1px solid var(--sep);border-radius:var(--radius);padding:0 14px;color:var(--text);font-family:var(--font);font-size:.85rem;transition:border-color .2s,box-shadow .2s}"
    "input[type=file]{height:auto;padding:11px 12px}input::placeholder{color:var(--dim)}"
    "input:focus{outline:none;border-color:var(--purple);box-shadow:0 0 0 3px rgba(181,123,255,.15)}"
    "button{width:100%;height:44px;margin-top:4px;background:rgba(181,123,255,.12);border:1px solid rgba(181,123,255,.35);border-radius:var(--radius);color:var(--purple);font-family:var(--font);font-size:.85rem;font-weight:600;cursor:pointer;transition:background .2s,border-color .2s,box-shadow .2s}"
    "button:hover{background:rgba(181,123,255,.2);border-color:rgba(181,123,255,.6);box-shadow:0 0 18px rgba(181,123,255,.12)}"
    ".note{font-size:.68rem;color:var(--dim);line-height:1.5;margin-top:10px}"
    ".status{margin-top:16px;background:var(--bg2);border:1px solid var(--sep);border-radius:var(--radius);padding:13px 16px;font-size:.8rem;color:var(--text2);min-height:46px;display:flex;align-items:center;gap:9px}"
    ".status::before{content:'=^..^=';color:var(--dim);font-family:monospace;font-size:.7rem;flex-shrink:0;transition:color .2s}"
    ".status{transition:border-color .2s,color .2s,background .2s}"
    ".status.ok{border-color:rgba(86,217,138,.45);color:var(--green);background:rgba(86,217,138,.08)}.status.ok::before{color:var(--green)}"
    ".status.err{border-color:rgba(255,120,117,.5);color:var(--red);background:rgba(255,120,117,.08)}.status.err::before{color:var(--red)}"
    ".status.warn{border-color:rgba(255,209,102,.5);color:var(--yellow);background:rgba(255,209,102,.08)}.status.warn::before{color:var(--yellow)}"
    "footer{border-top:1px solid var(--sep);padding:14px 0;text-align:center}footer div{display:block}"
    "footer span{color:var(--sep);font-size:.62rem;letter-spacing:.06em}footer .by{color:var(--dim)}footer .by b{color:var(--purple);font-weight:600}"
    "@media(max-width:520px){.file{flex-direction:column;align-items:flex-start;gap:6px}}"
    "body::after{content:'';position:fixed;inset:0;pointer-events:none;background:repeating-linear-gradient(to bottom,transparent 0,transparent 3px,rgba(0,0,0,.025) 3px,rgba(0,0,0,.025) 4px);z-index:9999}"
    "</style></head><body>";

static const char *page_body =
    "<header><div class=bar><div style=\"display:flex;align-items:center;gap:9px\">"
    "<span style=\"font-size:1.15rem;line-height:1\">&#129413;</span><span class=logo>eyas-crypt</span>"
    "<span style=\"color:var(--sep);font-size:.8rem\">/</span>"
    "<span style=\"color:var(--dim);font-size:.68rem;letter-spacing:.02em\">sealed vault</span></div>"
    "<span class=label>chacha20 &middot; hmac-sha256</span></div></header>"
    "<main><div class=label style=\"margin-bottom:10px\">seal a file into a vault, or open one back</div>"
    "<div class=modes>"
    "<button type=button class=\"mode-btn active\" id=mb-seal onclick=\"mode('seal')\">&#128274; seal</button>"
    "<button type=button class=mode-btn id=mb-open onclick=\"mode('open')\">&#128275; open</button></div>"
    "<form id=seal-card class=card method=post action=/seal enctype=multipart/form-data onsubmit=\"return go(this,event)\"><h2>seal</h2>"
    "<div class=field><label>file</label><div class=file><label class=filebtn>&#128206; choose file&hellip;<input name=file type=file required onchange=\"pick(this)\"></label><span class=fname>no file selected</span></div></div>"
    "<div class=field><label>passphrase</label><input name=pass type=password autocomplete=off required></div>"
    "<button>seal &amp; download falcon.eyas</button>"
    "<p class=note>the vault always downloads as <b style=\"color:var(--text2)\">falcon.eyas</b> &mdash; the real filename is encrypted inside and only revealed on open.</p></form>"
    "<form id=open-card class=card method=post action=/open enctype=multipart/form-data style=\"display:none\" onsubmit=\"return go(this,event)\"><h2>open</h2>"
    "<div class=field><label>vault</label><div class=file><label class=filebtn>&#128206; choose .eyas&hellip;<input name=file type=file accept=.eyas required onchange=\"pick(this)\"></label><span class=fname>no file selected</span></div></div>"
    "<div class=field><label>passphrase</label><input name=pass type=password autocomplete=off required></div>"
    "<button>open &amp; download file</button><p class=note>wrong passphrases and modified vaults are rejected before any output.</p></form>"
    "<div class=prog id=prog></div>"
    "<div class=status id=st>";

static const char *page_tail =
    "</div></main>"
    "<footer><div><span>eyas-crypt &middot; sealed vault &middot; meow =^..^=</span></div>"
    "<div><span class=by>powered by <b>cocomelonc</b></span></div></footer>"
    "<script>"
    "function pick(i){i.closest('.file').querySelector('.fname').textContent=i.files.length?i.files[0].name:'no file selected'}"
    "function setst(k,m){var e=document.getElementById('st');e.className='status'+(k?' '+k:'');e.textContent=m}"
    "function reset(f){f.reset();f.querySelectorAll('.fname').forEach(function(x){x.textContent='no file selected'})}"
    "function mode(m){var s=m=='seal',a=document.getElementById('seal-card'),b=document.getElementById('open-card');a.style.display=s?'':'none';b.style.display=s?'none':'';document.getElementById('mb-seal').classList.toggle('active',s);document.getElementById('mb-open').classList.toggle('active',!s);reset(a);reset(b);setst('','ready.')}"
    "function go(f,e){e.preventDefault();var btn=f.querySelector('button[type=submit],button:not([type])')||f.querySelector('button');var seal=f.id=='seal-card';btn.disabled=true;document.getElementById('prog').classList.add('on');setst('warn',(seal?'sealing':'opening')+'\\u2026');"
    "fetch(f.action,{method:'POST',body:new FormData(f)}).then(function(r){var ct=r.headers.get('content-type')||'';"
    "if(r.ok&&ct.indexOf('octet-stream')>=0){var cd=r.headers.get('content-disposition')||'';var mm=/filename=\"?([^\";]+)\"?/.exec(cd);var nm=mm?mm[1]:'download';return r.blob().then(function(b){var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=nm;document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(a.href)},2000);setst('ok',(seal?'sealed \\u2192 ':'opened \\u2192 ')+nm)})}"
    "return r.text().then(function(t){setst('err',t||'failed.')})})"
    ".catch(function(){setst('err','request failed.')}).finally(function(){btn.disabled=false;document.getElementById('prog').classList.remove('on');reset(f)});return false}"
    "</script>"
    "</body></html>";

static void sock_close(sock_t s) {
#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
}

static void send_all(sock_t fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len > 0) {
    send_len_t chunk = (send_len_t)(len > 32768U ? 32768U : len);
    recv_len_t n = (recv_len_t)send(fd, p, chunk, 0);
    if (n <= 0) return;
    p += n;
    len -= (size_t)n;
  }
}

static void send_html(sock_t fd, const char *status) {
  char hdr[256];
  const char *st = status ? status : "ready.";
  size_t len = strlen(page_head) + strlen(page_head2) + strlen(page_body) + strlen(st) + strlen(page_tail);
  snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", len);
  send_all(fd, hdr, strlen(hdr));
  send_all(fd, page_head, strlen(page_head));
  send_all(fd, page_head2, strlen(page_head2));
  send_all(fd, page_body, strlen(page_body));
  send_all(fd, st, strlen(st));
  send_all(fd, page_tail, strlen(page_tail));
}

/* Short plain-text reply for the AJAX upload endpoints (read by the GUI's go()). */
static void send_msg(sock_t fd, int code, const char *msg) {
  char hdr[256];
  size_t len = strlen(msg);
  snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", code, code == 200 ? "OK" : "Bad Request", len);
  send_all(fd, hdr, strlen(hdr));
  send_all(fd, msg, len);
}

static void send_download(sock_t fd, const char *name, const uint8_t *data, size_t len) {
  char hdr[512];
  snprintf(hdr, sizeof(hdr),
           "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %zu\r\nContent-Disposition: attachment; filename=\"%s\"\r\nConnection: close\r\n\r\n",
           len, name);
  send_all(fd, hdr, strlen(hdr));
  send_all(fd, data, len);
}

static char *find_bytes(char *hay, size_t hay_len, const char *needle, size_t needle_len) {
  if (needle_len == 0 || hay_len < needle_len) return NULL;
  for (size_t i = 0; i + needle_len <= hay_len; i++) {
    if (memcmp(hay + i, needle, needle_len) == 0) return hay + i;
  }
  return NULL;
}

static void header_param(const char *headers, const char *key, char *out, size_t out_len) {
  const char *p = strstr(headers, key);
  out[0] = '\0';
  if (!p) return;
  p += strlen(key);
  if (*p != '"') return;
  p++;
  size_t i = 0;
  while (*p && *p != '"' && i + 1 < out_len) out[i++] = *p++;
  out[i] = '\0';
}

static int multipart_extract(char *body, size_t body_len, const char *boundary, char **file, size_t *file_len, char *filename, size_t filename_len, char *pass, size_t pass_len) {
  char marker[256];
  size_t marker_len;
  char *p = body;
  snprintf(marker, sizeof(marker), "--%s", boundary);
  marker_len = strlen(marker);
  pass[0] = '\0';
  filename[0] = '\0';
  *file = NULL;
  *file_len = 0;
  char *end_body = body + body_len;
  while (p < end_body && (p = find_bytes(p, (size_t)(end_body - p), marker, marker_len)) != NULL) {
    char *part_start, *data_start, *next;
    char saved;
    p += marker_len;
    if (p + 2 <= body + body_len && p[0] == '-' && p[1] == '-') break;
    if (p + 2 > body + body_len || p[0] != '\r' || p[1] != '\n') continue;
    part_start = p + 2;
    data_start = find_bytes(part_start, (size_t)(end_body - part_start), "\r\n\r\n", 4);
    if (!data_start) break;
    saved = *data_start;
    *data_start = '\0';
    data_start += 4;
    next = find_bytes(data_start, (size_t)(end_body - data_start), marker, marker_len);
    if (!next) break;
    if (next >= data_start + 2 && next[-2] == '\r' && next[-1] == '\n') next -= 2;
    if (strstr(part_start, "name=\"pass\"")) {
      size_t n = (size_t)(next - data_start);
      if (n >= pass_len) n = pass_len - 1;
      memcpy(pass, data_start, n);
      pass[n] = '\0';
    } else if (strstr(part_start, "name=\"file\"")) {
      header_param(part_start, "filename=", filename, filename_len);
      *file = data_start;
      *file_len = (size_t)(next - data_start);
    }
    data_start[-4] = saved;
    p = next;
  }
  return *file && *pass ? 0 : -1;
}

static void handle_upload(sock_t fd, const char *path, char *req, size_t req_len) {
  char *ctype = strstr(req, "Content-Type:");
  char *body = strstr(req, "\r\n\r\n");
  char *bpos;
  char boundary[160], filename[260], pass[512], *file;
  uint8_t *out = NULL;
  size_t file_len = 0, out_len = 0, body_len;
  int rc;
  if (!ctype || !body) {
    send_msg(fd, 400, "bad upload.");
    return;
  }
  body += 4;
  body_len = req_len - (size_t)(body - req);
  bpos = strstr(ctype, "boundary=");
  if (!bpos) {
    send_msg(fd, 400, "missing multipart boundary.");
    return;
  }
  bpos += 9;
  size_t i = 0;
  while (bpos[i] && bpos[i] != '\r' && bpos[i] != '\n' && i + 1 < sizeof(boundary)) {
    boundary[i] = bpos[i];
    i++;
  }
  boundary[i] = '\0';
  if (multipart_extract(body, body_len, boundary, &file, &file_len, filename, sizeof(filename), pass, sizeof(pass)) != 0) {
    send_msg(fd, 400, "upload parse failed.");
    return;
  }
  if (strcmp(path, "/seal") == 0) {
    /* The real filename is encrypted inside the payload; the download is always
       falcon.eyas so the vault name never leaks the original. */
    rc = eyas_vault_seal_memory((const uint8_t *)file, file_len, filename[0] ? filename : "file", pass, EYAS_DEFAULT_ITERS, &out, &out_len);
    if (rc == 0) send_download(fd, "falcon.eyas", out, out_len);
    else send_msg(fd, 400, "seal failed.");
  } else {
    char recovered[260];
    rc = eyas_vault_open_memory((const uint8_t *)file, file_len, pass, &out, &out_len, recovered, sizeof(recovered));
    if (rc == 0) send_download(fd, recovered[0] ? recovered : "recovered.bin", out, out_len);
    else send_msg(fd, 400, "open failed: bad passphrase or tampered vault.");
  }
  free(out);
}

static void handle(sock_t fd) {
  char *req = (char *)malloc(8 * 1024 * 1024);
  size_t cap = 8 * 1024 * 1024, used = 0;
  char method[16], path[128];
  if (!req) return;
  for (;;) {
    size_t room = cap - used - 1;
    recv_len_t n = recv(fd, req + used, (send_len_t)(room > EYAS_RECV_CHUNK ? EYAS_RECV_CHUNK : room), 0);
    if (n <= 0) break;
    used += (size_t)n;
    req[used] = '\0';
    if (used + 1 >= cap) break;
    if (strstr(req, "\r\n\r\n") && strstr(req, "Content-Length:") == NULL) break;
    char *cl = strstr(req, "Content-Length:");
    char *body = strstr(req, "\r\n\r\n");
    if (cl && body) {
      size_t want = (size_t)strtoull(cl + 15, NULL, 10);
      size_t have = used - (size_t)(body + 4 - req);
      if (have >= want) break;
    }
  }
  if (sscanf(req, "%15s %127s", method, path) != 2) {
    send_html(fd, "bad request.");
  } else if (strcmp(method, "POST") == 0 && (strcmp(path, "/seal") == 0 || strcmp(path, "/open") == 0)) {
    handle_upload(fd, path, req, used);
  } else {
    send_html(fd, "ready.");
  }
  free(req);
}

int eyas_gui_run(const char *bind_ip, int port) {
  sock_t sfd;
  struct sockaddr_in addr;
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
  sfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sfd == (sock_t)-1) return 1;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  addr.sin_addr.s_addr = inet_addr(bind_ip);
  if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(sfd, 16) != 0) {
    sock_close(sfd);
    return 1;
  }
  printf("eyas-crypt GUI: http://%s:%d/\n", bind_ip, port);
  for (;;) {
    struct sockaddr_in peer;
#ifdef _WIN32
    int plen = sizeof(peer);
#else
    socklen_t plen = sizeof(peer);
#endif
    sock_t cfd = accept(sfd, (struct sockaddr *)&peer, &plen);
    if (cfd == (sock_t)-1) continue;
    handle(cfd);
    sock_close(cfd);
  }
}
