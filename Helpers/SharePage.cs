using System;
using System.Security.Cryptography;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// The share hub's web page: ONE self-contained document — inline CSS and JavaScript, no CDN, no web fonts (the networks
/// it runs on may be offline or filtered) — for every common browser from a 320 px phone up: Chrome / Edge / Firefox /
/// Safari, iOS Safari 12+, Android Chrome / WebView / Samsung Internet. The script is ES5 (XMLHttpRequest with upload
/// progress, a WebSocket with an automatic long-poll fallback for networks and browsers where it can't connect — iOS
/// Safari refuses a WebSocket to a self-signed certificate even after the page was accepted). Light / dark follow the
/// device (prefers-color-scheme) in the Echoes palette, solid colors, no animations. All text from other devices is
/// set with textContent; links are made only from http(s) URLs. The Content-Security-Policy allows the inline blocks
/// only by their SHA-256 (no eval, no other script / style), and connections only to this very host.
/// </summary>
public static class SharePage
{
    /// <summary>The page bytes (UTF-8), built once.</summary>
    public static readonly byte[] Bytes;
    /// <summary>"'sha256-…'" of the inline script and style.</summary>
    public static readonly string ScriptHash, StyleHash;

    static SharePage()
    {
        ScriptHash = Hash(Js);
        StyleHash = Hash(Css);
        Bytes = Encoding.UTF8.GetBytes(Head + "<style>" + Css + "</style></head>" + Body + "<script>" + Js + "</script></body></html>");
    }

    private static string Hash(string s) => "'sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(s))) + "'";

    /// <summary>The page's policy. <paramref name="authority"/> is the request's (already validated) Host: the
    /// WebSocket is allowed to exactly this host and port (older Safari doesn't count ws: / wss: as 'self').</summary>
    public static string Csp(bool https, string authority)
    {
        string ws = authority.Length > 0 && IsSafeAuthority(authority) ? " " + (https ? "wss://" : "ws://") + authority : string.Empty;
        return "Content-Security-Policy: default-src 'none'; script-src " + ScriptHash + "; style-src " + StyleHash
               + "; img-src data:; connect-src 'self'" + ws + "; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n";
    }

    private static bool IsSafeAuthority(string a)
    {
        foreach (char c in a)
            if (!(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '-' or ':' or '[' or ']' or '%')) return false;
        return true;
    }

    // ------------------------------------------------------------------ markup

    private const string Head = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<meta name="format-detection" content="telephone=no">
<title>Echoes</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='12' fill='%230F766E'/%3E%3Cpath d='M68 28a32 32 0 0 1 0 44M32 72a32 32 0 0 1 0-44' fill='none' stroke='%230F766E' stroke-width='10' stroke-linecap='round'/%3E%3C/svg%3E">
""";

    private const string Logo = """<svg class="logo" viewBox="0 0 100 100" aria-hidden="true"><circle class="c" cx="50" cy="50" r="8"/><path class="a" d="M64 33a25 25 0 0 1 0 34M36 67a25 25 0 0 1 0-34"/><path class="b" d="M74 22a40 40 0 0 1 0 56M26 78a40 40 0 0 1 0-56"/></svg>""";

    private const string Body = """
<body>
<div class="app" id="app">
<header class="top">
""" + Logo + """
<div class="titles"><b>Echoes</b><span class="sub" id="hostLine">Share &amp; chat</span></div>
<div class="status" id="status"><span class="dot" id="dot"></span><span id="statusText">Connecting&#8230;</span></div>
<button type="button" class="me" id="meBtn" title="Your name in the chat (tap to change)"><span id="meName">&#8230;</span></button>
</header>
<nav class="tabs" id="tabs">
<button type="button" class="tab sel" id="tabChat">Chat<span class="badge hide" id="unread"></span></button>
<button type="button" class="tab" id="tabFiles">Files<span class="count" id="filesCount"></span></button>
</nav>
<main class="main">
<section class="pane chat on" id="chatPane">
<div class="msgs" id="msgs" role="log" aria-live="polite"><div class="empty" id="chatEmpty">No messages yet. Say hello, or send a file.</div></div>
<form class="composer" id="composer" autocomplete="off">
<label class="btn icon" for="fileInput" title="Send files" aria-label="Send files"><svg class="ico" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5V19M5 12H19"/></svg></label>
<textarea id="text" rows="1" maxlength="16384" placeholder="Message" aria-label="Message" dir="auto"></textarea>
<button type="submit" class="btn primary" id="sendBtn">Send</button>
</form>
</section>
<section class="pane files" id="filesPane">
<div class="card">
<h2>Send to <span class="hostName">this device</span></h2>
<div class="drop" id="drop">
<svg class="ico big" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 19V8M7 13L12 8L17 13M5 4H19"/></svg>
<b>Drop files here</b>
<label class="btn primary" for="fileInput">Choose files</label>
<small id="limitText">You can also paste a file or picture.</small>
</div>
<input type="file" id="fileInput" class="sr" multiple>
<div id="uploads"></div>
</div>
<div class="card">
<h2>Shared by <span class="hostName">this device</span></h2>
<div id="fileList" class="flist"></div>
<div class="muted" id="filesEmpty">Nothing shared yet.</div>
</div>
</section>
</main>
</div>
<div class="overlay hide" id="login">
<form class="dialog" id="loginForm" autocomplete="off">
""" + Logo + """
<h1>Enter the PIN</h1>
<p class="muted">Shown in Echoes on <b class="hostName">the other device</b>.</p>
<input id="pin" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="9" placeholder="00000000" aria-label="PIN">
<div class="err" id="loginErr"></div>
<button type="submit" class="btn primary wide" id="loginBtn">Open</button>
</form>
</div>
<div class="overlay hide" id="nameDlg">
<form class="dialog" id="nameForm" autocomplete="off">
<h1>Your name</h1>
<p class="muted">How this device shows up in the chat.</p>
<input id="nameInput" type="text" maxlength="40" aria-label="Your name">
<div class="row2"><button type="button" class="btn" id="nameCancel">Cancel</button><button type="submit" class="btn primary">Save</button></div>
</form>
</div>
<div class="overlay hide" id="gone">
<div class="dialog">
""" + Logo + """
<h1 id="goneTitle">Sharing stopped</h1>
<p class="muted" id="goneText">The other device stopped sharing. This page reconnects when it starts again.</p>
</div>
</div>
<div class="toast hide" id="toast" role="status"></div>
<noscript><p class="noscript">This page needs JavaScript.</p></noscript>
""";

    // ------------------------------------------------------------------ style (solid colors, no transitions)

    private const string Css = """
:root{--bg:#F4F6FA;--card:#FFFFFF;--inset:#F3F5F9;--raised:#FFFFFF;--hover:#E6EBF2;--line:#E2E7EE;--line2:#D0D7E2;--text:#141B26;--text2:#475467;--muted:#687387;--accent:#0F766E;--accentHover:#115E59;--accentText:#0F766E;--soft:#E0F4F1;--softLine:#9FD9D0;--on:#FFFFFF;--danger:#DC2626;--ok:#047857;--warn:#B45309;--input:#FFFFFF;--sel:#B5E3DC}
@media (prefers-color-scheme:dark){:root{--bg:#0B0E14;--card:#121720;--inset:#0D1118;--raised:#1A212C;--hover:#151B25;--line:#1C2331;--line2:#262F40;--text:#E6EAF2;--text2:#A9B2C4;--muted:#747F96;--accent:#2DD4BF;--accentHover:#5EEAD4;--accentText:#5EEAD4;--soft:#0E2B29;--softLine:#1B4E48;--on:#032420;--danger:#F87171;--ok:#34D399;--warn:#FBBF24;--input:#141A24;--sel:#1F5C55}}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--text);font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans","Helvetica Neue",Arial,sans-serif;-webkit-text-size-adjust:100%;text-size-adjust:100%}
::selection{background:var(--sel)}
button,input,textarea{font:inherit;color:inherit}
a{color:var(--accentText)}
.app{display:flex;flex-direction:column;height:100%;max-width:1180px;margin:0 auto;background:var(--bg)}
.top{display:flex;align-items:center;padding:9px 12px;background:var(--card);border-bottom:1px solid var(--line);flex:0 0 auto}
.logo{width:32px;height:32px;flex:0 0 auto;margin-right:10px;fill:none;stroke-width:6;stroke-linecap:round}
.logo .a{stroke:var(--accent)}.logo .b{stroke:var(--softLine)}.logo .c{fill:var(--accent);stroke:none}
.titles{min-width:0;flex:1 1 auto}
.titles b{display:block;font-size:16px;line-height:1.2}
.sub{display:block;font-size:12.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.status{display:flex;align-items:center;font-size:12.5px;color:var(--text2);margin-left:8px;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted);margin-right:6px;flex:0 0 auto}
.dot.on{background:var(--ok)}.dot.wait{background:var(--warn)}.dot.off{background:var(--danger)}
.me{margin-left:8px;border:1px solid var(--line2);background:var(--raised);border-radius:8px;padding:5px 10px;font-size:13px;max-width:170px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer;flex:0 1 auto;min-width:0}
.me:hover{border-color:var(--accent)}
.tabs{display:flex;background:var(--card);border-bottom:1px solid var(--line);flex:0 0 auto}
.tab{flex:1 1 0;border:0;border-bottom:2px solid var(--card);background:var(--card);padding:10px 8px 8px;font-weight:600;color:var(--text2);cursor:pointer}
.tab.sel{color:var(--accentText);border-bottom-color:var(--accent)}
.badge{display:inline-block;min-width:19px;padding:0 5px;margin-left:6px;border-radius:10px;background:var(--accent);color:var(--on);font-size:11.5px;line-height:19px;text-align:center}
.count{color:var(--muted);font-weight:400;margin-left:5px}
.hide{display:none!important}
.main{flex:1 1 auto;display:flex;min-height:0}
.pane{display:none;flex-direction:column;flex:1 1 auto;min-width:0;min-height:0}
.pane.on{display:flex}
.msgs{flex:1 1 auto;overflow-y:auto;-webkit-overflow-scrolling:touch;padding:14px 12px 6px;min-height:0}
.empty{text-align:center;color:var(--muted);padding:40px 16px}
.msg{max-width:86%;margin:0 0 10px}
.msg.mine{margin-left:auto}
.meta{display:flex;align-items:center;font-size:12px;color:var(--muted);margin:0 3px 3px;min-height:22px}
.who{font-weight:600;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.mine .who{color:var(--accentText)}
.tag{flex:0 0 auto;margin-left:6px;padding:0 6px;border:1px solid var(--softLine);border-radius:6px;background:var(--soft);color:var(--accentText);font-size:11px;font-weight:600;line-height:16px;white-space:nowrap}
.when{white-space:nowrap;margin-left:6px}
.sp{flex:1 1 auto;min-width:8px}
.mini{border:1px solid var(--bg);background:var(--bg);color:var(--muted);font-size:12px;padding:1px 7px;border-radius:6px;cursor:pointer;white-space:nowrap}
.mini:hover{color:var(--accentText);border-color:var(--line2)}
.bubble{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:8px 11px;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:break-word;word-break:break-word}
.mine .bubble{background:var(--soft);border-color:var(--softLine)}
.bubble a{word-break:break-all}
.note{color:var(--text2)}
.flink{display:flex;align-items:center;text-decoration:none;color:var(--text);min-width:0}
.flink .ico{color:var(--accentText);margin-right:8px;flex:0 0 auto}
.nm{font-weight:600;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:0 1 auto}
.sz{color:var(--muted);font-size:12.5px;margin-left:8px;white-space:nowrap;flex:0 0 auto}
.composer{display:flex;align-items:flex-end;padding:10px;background:var(--card);border-top:1px solid var(--line);flex:0 0 auto;margin:0}
.composer textarea{flex:1 1 auto;min-width:0;resize:none;height:42px;min-height:42px;max-height:150px;padding:9px 12px;font-size:16px;line-height:1.4;border:1px solid var(--line2);border-radius:10px;background:var(--input);margin:0 8px;outline:0}
.composer textarea:focus,.dialog input:focus{border-color:var(--accent)}
.btn{display:inline-flex;align-items:center;justify-content:center;height:42px;padding:0 16px;border-radius:10px;border:1px solid var(--line2);background:var(--raised);color:var(--text);font-weight:600;cursor:pointer;text-decoration:none;white-space:nowrap;flex:0 0 auto}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on)}
.btn.primary:hover{background:var(--accentHover);border-color:var(--accentHover)}
.btn:disabled{background:var(--hover);border-color:var(--line);color:var(--muted);cursor:default}
.btn.icon{width:42px;padding:0}
.btn.wide{width:100%}
button:focus,a:focus,label:focus{outline:2px solid var(--accent);outline-offset:1px}
.ico{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.ico.big{width:28px;height:28px;color:var(--accentText);display:block;margin:0 auto 6px}
.files{overflow-y:auto;-webkit-overflow-scrolling:touch;padding:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:12px}
.card h2{font-size:12px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);margin:0 0 10px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.drop{border:2px dashed var(--line2);border-radius:10px;padding:16px 12px;text-align:center;background:var(--inset)}
.drop.over{border-color:var(--accent);background:var(--soft)}
.drop b{display:block;margin-bottom:10px}
.drop small{display:block;color:var(--muted);margin-top:10px;font-size:12.5px}
.up{border:1px solid var(--line);border-radius:10px;padding:8px 8px 8px 11px;margin-top:8px;background:var(--inset)}
.up .row{display:flex;align-items:center;min-height:26px}
.up .nm{flex:1 1 auto;font-size:14px}
.bar{height:6px;border-radius:3px;background:var(--line);margin:6px 3px 0 0;overflow:hidden}
.fill{height:100%;width:0;background:var(--accent)}
.up.done .fill{background:var(--ok)}.up.err .fill{background:var(--danger)}
.st{font-size:12.5px;color:var(--muted);margin-top:4px}
.up.err .st{color:var(--danger)}.up.done .st{color:var(--ok)}
.x{border:1px solid var(--inset);background:var(--inset);color:var(--muted);border-radius:6px;width:28px;height:26px;margin-left:6px;cursor:pointer;flex:0 0 auto;padding:0;display:flex;align-items:center;justify-content:center}
.x:hover{color:var(--danger);border-color:var(--line2)}
.x .ico{width:14px;height:14px}
.flist a{display:flex;align-items:center;padding:10px;border:1px solid var(--line);border-radius:10px;margin-top:8px;text-decoration:none;color:var(--text);background:var(--inset);min-width:0}
.flist a:hover{border-color:var(--accent)}
.flist .ico{color:var(--accentText);margin-right:9px;flex:0 0 auto}
.flist .nm{flex:1 1 auto}
.flist .dl{margin-left:8px}
.muted{color:var(--muted);font-size:13.5px}
.overlay{position:fixed;left:0;top:0;right:0;bottom:0;background:var(--bg);display:flex;align-items:center;justify-content:center;padding:20px;z-index:10;overflow-y:auto}
.dialog{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;text-align:center;margin:auto}
.dialog .logo{width:44px;height:44px;margin:0 auto;display:block}
.dialog h1{font-size:19px;margin:10px 0 6px}
.dialog p{margin:0}
.dialog input{width:100%;height:48px;font-size:20px;text-align:center;border:1px solid var(--line2);border-radius:10px;background:var(--input);margin:16px 0 6px;outline:0;padding:0 10px}
#pin{font-size:24px;letter-spacing:.25em}
.err{color:var(--danger);font-size:13.5px;min-height:20px;margin-bottom:8px}
.row2{display:flex;margin-top:6px}.row2 .btn{flex:1 1 0}.row2 .btn+.btn{margin-left:8px}
.toast{position:fixed;left:12px;right:12px;bottom:76px;margin:0 auto;max-width:460px;background:var(--text);color:var(--bg);padding:10px 14px;border-radius:10px;font-size:14px;z-index:20;text-align:center}
.sr{position:absolute;width:1px;height:1px;margin:-1px;padding:0;border:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.noscript{padding:20px;text-align:center}
@media (max-width:420px){.status span+span{display:none}.status{margin-left:6px}.me{max-width:120px}.msgs{padding:12px 8px 4px}.msg{max-width:92%}.files{padding:8px}}
@media (min-width:760px){.tabs{display:none}.pane,.pane.on{display:flex}.files{flex:0 0 360px;border-left:1px solid var(--line)}.msgs{padding:16px 18px 8px}}
@media (min-width:1182px){.app{border-left:1px solid var(--line);border-right:1px solid var(--line)}}
""";

    // ------------------------------------------------------------------ script (ES5)

    private const string Js = """
(function () {
'use strict';
var D = document, W = window;
function $(id) { return D.getElementById(id); }
var NS = 'http://www.w3.org/2000/svg';
var P = {
  file: 'M14.5 3H6.5A1.5 1.5 0 0 0 5 4.5V19.5A1.5 1.5 0 0 0 6.5 21H17.5A1.5 1.5 0 0 0 19 19.5V7.5ZM14 3V8H19',
  down: 'M12 4V15M7 10L12 15L17 10M5 20H19',
  close: 'M7 7L17 17M17 7L7 17'
};
var S = { host: '', pin: true, me: null, seq: -1, files: [], https: location.protocol === 'https:',
  limits: { msg: 16384, upload: 0, chunk: 4194304 }, ws: null, wsFails: 0, polling: false, pollFails: 0, pollXhr: null,
  retry: null, unread: 0, tab: 'chat', seen: {}, loggedIn: false, gone: false };
var touch = ('ontouchstart' in W) || (navigator.maxTouchPoints > 0);
var linkPin = null;
var EMPTY = $('chatEmpty');

function get(k) { try { return W.localStorage.getItem(k); } catch (e) { return null; } }
function put(k, v) { try { if (v === null) W.localStorage.removeItem(k); else W.localStorage.setItem(k, v); } catch (e) { } }

function el(tag, cls, text) {
  var e = D.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}
function icon(name) {
  var s = D.createElementNS(NS, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('class', 'ico');
  s.setAttribute('aria-hidden', 'true');
  var p = D.createElementNS(NS, 'path');
  p.setAttribute('d', P[name]);
  s.appendChild(p);
  return s;
}
function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); }
function show(e, on) { if (on) e.classList.remove('hide'); else e.classList.add('hide'); }
function pad(n) { return n < 10 ? '0' + n : '' + n; }
function when(ms) {
  var d = new Date(ms), now = new Date();
  var t = pad(d.getHours()) + ':' + pad(d.getMinutes());
  if (d.toDateString() !== now.toDateString()) t = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + t;
  return t;
}
function size(b) {
  var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
  while (b >= 1024 && i < 4) { b = b / 1024; i++; }
  return i === 0 ? b + ' B' : (Math.round(b * 10) / 10) + ' ' + u[i];
}
function utf8(s) {
  var n = 0, i, c;
  for (i = 0; i < s.length; i++) {
    c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xD800 && c <= 0xDBFF) { n += 4; i++; }
    else n += 3;
  }
  return n;
}
function guessName() {
  var ua = navigator.userAgent || '';
  var dev = /iPad/.test(ua) ? 'iPad' : /iPhone|iPod/.test(ua) ? 'iPhone' : /Android/.test(ua) ? (/Mobile/.test(ua) ? 'Android phone' : 'Android tablet')
    : /Windows/.test(ua) ? 'Windows PC' : /Macintosh|Mac OS X/.test(ua) ? 'Mac' : /CrOS/.test(ua) ? 'Chromebook' : /Linux/.test(ua) ? 'Linux PC' : 'Browser';
  if (dev === 'Mac' && navigator.maxTouchPoints > 1) dev = 'iPad';
  var br = /SamsungBrowser/.test(ua) ? 'Samsung Internet' : /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox|FxiOS/.test(ua) ? 'Firefox'
    : /CriOS|Chrome/.test(ua) ? 'Chrome' : /Safari/.test(ua) ? 'Safari' : '';
  return br ? dev + ' (' + br + ')' : dev;
}
var myName = (get('echoes.name') || '').replace(/^\s+|\s+$/g, '').slice(0, 40) || guessName();

/* ---------------- requests ---------------- */
function api(method, path, body, cb, opt) {
  opt = opt || {};
  var x = new XMLHttpRequest();
  x.open(method, path, true);
  x.setRequestHeader('X-Echoes', '1');
  if (body !== null && !opt.raw) x.setRequestHeader('Content-Type', 'application/json');
  if (opt.timeout) x.timeout = opt.timeout;
  if (opt.progress && x.upload) x.upload.onprogress = opt.progress;
  var done = false;
  x.onreadystatechange = function () {
    if (x.readyState !== 4 || done) return;
    done = true;
    var data = null;
    try { data = x.responseText ? JSON.parse(x.responseText) : null; } catch (e) { data = null; }
    if (x.status === 401 && data && data.login && !opt.noLogin) needLogin('');
    cb(x.status, data);
  };
  try { x.send(body === null ? null : (opt.raw ? body : JSON.stringify(body))); }
  catch (e) { if (!done) { done = true; cb(0, null); } }
  return x;
}
function later(fn, ms) { if (S.retry) clearTimeout(S.retry); S.retry = setTimeout(function () { S.retry = null; fn(); }, ms); }

/* ---------------- status / host ---------------- */
function status(kind, text) {
  $('dot').className = 'dot ' + kind;
  $('statusText').textContent = text;
}
function showHost() {
  var n = S.host || 'the other device', i, list = D.querySelectorAll('.hostName');
  for (i = 0; i < list.length; i++) list[i].textContent = n;
  $('hostLine').textContent = S.host ? 'Shared by ' + S.host : 'Share & chat';
  title();
  if (S.limits.upload) $('limitText').textContent = 'Up to ' + size(S.limits.upload) + ' per file. You can also paste a file or picture.';
}
function title() { D.title = (S.unread ? '(' + S.unread + ') ' : '') + 'Echoes' + (S.host ? ' - ' + S.host : ''); }
function toast(text) {
  var t = $('toast');
  t.textContent = text;
  show(t, true);
  if (toast.timer) clearTimeout(toast.timer);
  toast.timer = setTimeout(function () { show(t, false); }, 4200);
}

/* ---------------- login ---------------- */
function readLinkPin() {
  var m = /[#&]k=([0-9]{4,9})/.exec(location.hash || '');
  if (!m) return;
  linkPin = m[1];
  try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { }
}
function start() {
  api('GET', '/api/hello', null, function (st, d) {
    if (st !== 200 || !d || !d.ok) { status('off', 'Can\'t reach the host'); later(start, 3000); return; }
    S.host = d.host || ''; S.pin = !!d.pin; showHost();
    if (d.authed) { S.me = d.me; ready(); return; }
    if (!S.pin) { login(''); return; }
    if (linkPin) { var p = linkPin; linkPin = null; login(p); return; }
    needLogin('');
  }, { noLogin: true });
}
function login(pin) {
  $('loginBtn').disabled = true;
  api('POST', '/api/login', { pin: pin, name: myName }, function (st, d) {
    $('loginBtn').disabled = false;
    if (st === 200 && d && d.ok) { S.me = d.me; show($('login'), false); ready(); return; }
    if (st === 429) { needLogin((d && d.error) || 'Too many wrong PINs - wait a little.'); return; }
    if (st === 401) { needLogin(pin ? 'Wrong PIN - check it in Echoes.' : ''); return; }
    needLogin('Can\'t reach ' + (S.host || 'the host') + ' - is it still sharing?');
  }, { noLogin: true });
}
function needLogin(msg) {
  stopLive();
  S.loggedIn = false;
  show($('gone'), false);
  $('loginErr').textContent = msg || '';
  show($('login'), true);
  status('wait', 'PIN needed');
  if (!touch) { try { $('pin').focus(); } catch (e) { } }
}
function ready() {
  stopLive();
  S.loggedIn = true;
  S.gone = false;
  show($('gone'), false);
  $('meName').textContent = myName;
  if (S.me && S.me.name !== myName) api('POST', '/api/name', { name: myName }, function () { });
  loadState(function () { connect(); });
}
function loadState(then) {
  api('GET', '/api/state', null, function (st, d) {
    if (st === 200 && d && d.ok) { applyState(d); if (then) then(); return; }
    if (st === 401) return;
    status('off', 'Can\'t reach ' + (S.host || 'the host'));
    later(function () { loadState(then); }, 3000);
  });
}
function applyState(d) {
  S.seq = d.seq; S.me = d.me; S.host = d.host || S.host;
  if (d.limits) S.limits = d.limits;
  showHost();
  var box = $('msgs'), i;
  clear(box);
  box.appendChild(EMPTY);
  S.seen = {};
  for (i = 0; i < d.messages.length; i++) addMessage(d.messages[i], false);
  emptyChat();
  files(d.files || []);
  toBottom(true);
}

/* ---------------- live updates: WebSocket, else long polls ---------------- */
function stopLive() {
  if (S.retry) { clearTimeout(S.retry); S.retry = null; }
  S.polling = false;
  if (S.pollXhr) { try { S.pollXhr.abort(); } catch (e) { } S.pollXhr = null; }
  if (S.ws) { var w = S.ws; S.ws = null; try { w.close(); } catch (e) { } }
}
function connect() {
  if (!S.loggedIn) return;
  if (S.wsFails >= 2 || !W.WebSocket) { startPolling(); return; }
  var ws, opened = false;
  try { ws = new WebSocket((S.https ? 'wss://' : 'ws://') + location.host + '/ws?since=' + S.seq); }
  catch (e) { wsFailed(); return; }
  S.ws = ws;
  var timer = setTimeout(function () { if (!opened) { try { ws.close(); } catch (e) { } } }, 7000);
  ws.onopen = function () { opened = true; clearTimeout(timer); S.wsFails = 0; status('on', 'Live'); };
  ws.onmessage = function (ev) { var e; try { e = JSON.parse(ev.data); } catch (x) { return; } onEvent(e); };
  ws.onerror = function () { };
  ws.onclose = function (ev) {
    clearTimeout(timer);
    if (S.ws !== ws) return;
    S.ws = null;
    if (ev.code === 4001) { needLogin('The PIN changed - enter the new one.'); return; }
    if (!opened) { wsFailed(); return; }
    if (ev.code === 1001) { stopped(true); return; }
    status('wait', 'Reconnecting' + '…');
    later(recover, 1500);
  };
}
function wsFailed() {
  S.wsFails++;
  if (S.wsFails >= 2) { startPolling(); return; }
  status('wait', 'Connecting' + '…');
  later(recover, 1200);
}
function recover() {
  api('GET', '/api/state', null, function (st, d) {
    if (st === 200 && d && d.ok) { applyState(d); connect(); return; }
    if (st === 401) return;
    stopped(false);
  }, { timeout: 15000 });
}
function stopped(byHost) {
  status('off', 'Not connected');
  S.gone = true;
  $('goneTitle').textContent = byHost ? 'Sharing stopped' : 'Can\'t reach ' + (S.host || 'the host');
  $('goneText').textContent = byHost
    ? (S.host || 'The other device') + ' stopped sharing. This page reconnects when it starts again.'
    : 'Check the Wi-Fi or network connection. This page reconnects by itself.';
  show($('gone'), true);
  later(function waitBack() {
    api('GET', '/api/hello', null, function (st, d) {
      if (st === 200 && d && d.ok) { show($('gone'), false); S.gone = false; if (d.authed) { S.me = d.me; ready(); } else if (!d.pin) login(''); else needLogin(''); return; }
      later(waitBack, 5000);
    }, { noLogin: true, timeout: 10000 });
  }, 3000);
}
function startPolling() {
  if (S.polling) return;
  S.polling = true;
  status('on', 'Live (polling)');
  poll();
}
function poll() {
  if (!S.polling) return;
  S.pollXhr = api('GET', '/api/poll?since=' + S.seq, null, function (st, d) {
    S.pollXhr = null;
    if (!S.polling) return;
    if (st === 200 && d && d.ok) {
      S.pollFails = 0;
      status('on', 'Live (polling)');
      if (d.reset) { loadState(poll); return; }
      for (var i = 0; i < d.events.length; i++) onEvent(d.events[i]);
      poll();
      return;
    }
    if (st === 401) return;
    if (st === 429) { setTimeout(poll, 5000); return; }
    S.pollFails++;
    S.polling = false;
    status('wait', 'Reconnecting' + '…');
    // still there? (a refused connection answers at once: the "stopped" screen shows without waiting)
    later(recover, S.pollFails > 1 ? Math.min(15000, 1000 * S.pollFails) : 200);
  }, { timeout: 40000 });
}
function onEvent(e) {
  if (!e || typeof e.seq !== 'number') return;
  if (e.t === 'reset') { loadState(null); return; }
  if (e.seq <= S.seq) return;
  S.seq = e.seq;
  if (e.t === 'msg') addMessage(e.m, true);
  else if (e.t === 'clear') { var box = $('msgs'); clear(box); box.appendChild(EMPTY); S.seen = {}; emptyChat(); }
  else if (e.t === 'files') files(e.files || []);
}

/* ---------------- chat ---------------- */
var URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi;
function linkify(parent, text) {
  var last = 0, m, url, trail, href, a;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(text)) !== null) {
    url = m[0];
    trail = /[.,;:!?)\]}'"]+$/.exec(url);
    if (trail) url = url.slice(0, url.length - trail[0].length);
    if (m.index > last) parent.appendChild(D.createTextNode(text.slice(last, m.index)));
    href = /^www\./i.test(url) ? 'http://' + url : url;
    if (/^https?:\/\/[^\/\s]/i.test(href)) {
      a = el('a', null, url);
      a.href = href;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      parent.appendChild(a);
    } else parent.appendChild(D.createTextNode(url));
    last = m.index + url.length;
    URL_RE.lastIndex = last;
  }
  if (last < text.length) parent.appendChild(D.createTextNode(text.slice(last)));
}
function fileLink(f, cls) {
  var a = el('a', cls);
  a.href = '/d/' + encodeURIComponent(f.id);
  a.setAttribute('download', f.name);
  a.appendChild(icon('file'));
  a.appendChild(el('span', 'nm', f.name));
  a.appendChild(el('span', 'sz', size(f.size)));
  return a;
}
function addMessage(m, live) {
  if (!m || S.seen[m.seq]) return;
  S.seen[m.seq] = true;
  var mine = !!(S.me && m.cid === S.me.cid);
  var row = el('div', 'msg' + (mine ? ' mine' : ''));
  var meta = el('div', 'meta');
  var who = el('span', 'who', mine ? 'You' : (m.from || '?'));
  who.setAttribute('dir', 'auto');
  meta.appendChild(who);
  if (m.host) { row.className += ' host'; meta.appendChild(el('span', 'tag', 'Host')); }   /* the server's flag, not the name */
  meta.appendChild(el('span', 'when', when(m.time)));
  meta.appendChild(el('span', 'sp'));
  var bubble = el('div', 'bubble');
  if (m.kind === 'file' && m.file && m.file.id) bubble.appendChild(fileLink(m.file, 'flink'));
  else if (m.kind === 'in' && m.file) {
    bubble.className = 'bubble note';
    bubble.textContent = (mine ? 'You sent ' : 'Sent ') + m.file.name + ' (' + size(m.file.size) + ') to ' + (S.host || 'the host') + '.';
  } else {
    bubble.setAttribute('dir', 'auto');   // Persian / Arabic messages read right to left
    linkify(bubble, m.text || '');
    var copy = el('button', 'mini', 'Copy');
    copy.type = 'button';
    copy.setAttribute('aria-label', 'Copy this message');
    copy.onclick = function () { copyText(m.text || '', copy); };
    meta.appendChild(copy);
  }
  row.appendChild(meta);
  row.appendChild(bubble);
  var box = $('msgs'), stick = atBottom();
  box.appendChild(row);
  while (box.childNodes.length > 601) box.removeChild(box.childNodes[1]);
  emptyChat();
  if (live) {
    if (stick || mine) toBottom(false);
    if (!mine && (D.hidden || S.tab !== 'chat' && W.innerWidth < 760)) { S.unread++; unreadBadge(); }
  }
}
function emptyChat() { show(EMPTY, $('msgs').childNodes.length <= 1); }
function atBottom() { var b = $('msgs'); return b.scrollHeight - b.scrollTop - b.clientHeight < 60; }
function toBottom() { var b = $('msgs'); b.scrollTop = b.scrollHeight; }
function unreadBadge() {
  var u = $('unread');
  u.textContent = S.unread > 99 ? '99+' : '' + S.unread;
  show(u, S.unread > 0);
  title();
}
function sendText() {
  var ta = $('text'), t = ta.value.replace(/\s+$/, '');
  if (!t.replace(/\s/g, '')) return;
  if (utf8(t) > S.limits.msg) { toast('Too long for one message (16 KB) - send it as a file.'); return; }
  var b = $('sendBtn');
  b.disabled = true;
  api('POST', '/api/send', { text: t }, function (st, d) {
    b.disabled = false;
    if (st === 200) { ta.value = ''; put('echoes.draft', null); grow(); if (!touch) ta.focus(); return; }
    if (st !== 401) toast((d && d.error) || 'Not sent - check the connection.');
  });
}
function grow() {
  var ta = $('text');
  ta.style.height = '42px';
  ta.style.height = Math.min(Math.max(ta.scrollHeight + 2, 42), 150) + 'px';
}
function copyText(text, btn) {
  function done(ok) {
    btn.textContent = ok ? 'Copied' : 'Copy failed';
    setTimeout(function () { btn.textContent = 'Copy'; }, 1400);
  }
  if (navigator.clipboard && W.isSecureContext) {
    navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(oldCopy(text)); });
    return;
  }
  done(oldCopy(text));
}
function oldCopy(text) {
  var ta = el('textarea', 'sr');
  ta.value = text;
  ta.setAttribute('readonly', '');
  D.body.appendChild(ta);
  ta.select();
  try { ta.setSelectionRange(0, text.length); } catch (e) { }
  var ok = false;
  try { ok = D.execCommand('copy'); } catch (e) { ok = false; }
  D.body.removeChild(ta);
  return ok;
}

/* ---------------- files from the host ---------------- */
function files(list) {
  S.files = list;
  var box = $('fileList'), i;
  clear(box);
  for (i = 0; i < list.length; i++) {
    var a = fileLink(list[i], '');
    var dl = icon('down');
    dl.setAttribute('class', 'ico dl');
    a.appendChild(dl);
    box.appendChild(a);
  }
  show($('filesEmpty'), list.length === 0);
  $('filesCount').textContent = list.length ? ' ' + list.length : '';
}

/* ---------------- uploads: chunks, resumed after a drop ---------------- */
var queue = [], running = 0;
function slice(f, a, b) { var s = f.slice || f.webkitSlice || f.mozSlice; return s.call(f, a, b); }
function addFiles(list) {
  if (!S.loggedIn) { toast('Enter the PIN first.'); return; }
  var i, f, n = 0;
  for (i = 0; i < list.length; i++) {
    f = list[i];
    if (!f) continue;
    if (S.limits.upload && f.size > S.limits.upload) { toast(f.name + ' is too large (up to ' + size(S.limits.upload) + ').'); continue; }
    var it = { file: f, name: f.name || 'pasted file', size: f.size, id: null, offset: 0, shown: 0, state: 'queued', fails: 0, xhr: null };
    row(it);
    queue.push(it);
    n++;
  }
  if (n && W.innerWidth < 760) tab('files');
  pump();
}
function row(it) {
  var r = el('div', 'up'), top = el('div', 'row');
  top.appendChild(el('span', 'nm', it.name));
  var x = el('button', 'x');
  x.type = 'button';
  x.setAttribute('aria-label', 'Cancel');
  x.appendChild(icon('close'));
  x.onclick = function () { cancel(it); };
  top.appendChild(x);
  r.appendChild(top);
  var bar = el('div', 'bar'), fill = el('div', 'fill');
  bar.appendChild(fill);
  r.appendChild(bar);
  var st = el('div', 'st', 'Waiting');
  r.appendChild(st);
  it.ui = { row: r, fill: fill, st: st, x: x };
  var box = $('uploads');
  box.insertBefore(r, box.firstChild);
}
function paint(it, text) {
  var pct = it.size ? Math.floor(Math.min(it.shown, it.size) * 100 / it.size) : 100;
  it.ui.fill.style.width = (it.state === 'done' ? 100 : pct) + '%';
  it.ui.st.textContent = text !== undefined ? text : pct + '%  ' + size(Math.min(it.shown, it.size)) + ' of ' + size(it.size);
  it.ui.row.className = 'up' + (it.state === 'done' ? ' done' : it.state === 'error' ? ' err' : '');
}
function pump() {
  for (var i = 0; i < queue.length && running < 2; i++)
    if (queue[i].state === 'queued') { running++; begin(queue[i]); }
}
function finish(it) {
  running--;
  var i = queue.indexOf(it);
  if (i >= 0) queue.splice(i, 1);
  pump();
}
function begin(it) {
  it.state = 'starting';
  paint(it, 'Starting');
  api('POST', '/api/up/start', { name: it.name, size: it.size }, function (st, d) {
    if (it.state === 'canceled') { if (d && d.id) api('POST', '/api/up/cancel?id=' + encodeURIComponent(d.id), null, function () { }); return; }
    if (st === 200 && d && d.ok) {
      it.id = d.id; it.offset = d.offset || 0; it.shown = it.offset; it.chunk = d.chunk || S.limits.chunk;
      if (d.done) { done(it, d.name); return; }
      chunk(it);
      return;
    }
    if (st === 0 || st === 429 || st === 503 || st === 502) { retryStart(it); return; }
    fail(it, (d && d.error) || ('Refused (' + st + ').'));
  });
}
function retryStart(it) {
  it.fails++;
  if (it.fails > 8) { fail(it, 'Can\'t reach ' + (S.host || 'the host') + '.'); return; }
  paint(it, 'Waiting to retry' + '…');
  setTimeout(function () { if (it.state !== 'canceled') begin(it); }, Math.min(20000, 1000 * Math.pow(2, it.fails)));
}
function chunk(it) {
  if (it.state === 'canceled') return;
  it.state = 'sending';
  var base = it.offset, end = Math.min(it.size, base + it.chunk);
  it.xhr = api('POST', '/api/up/chunk?id=' + encodeURIComponent(it.id) + '&offset=' + base, slice(it.file, base, end), function (st, d) {
    it.xhr = null;
    if (it.state === 'canceled') return;
    if (st === 200 && d && d.ok) {
      it.fails = 0;
      it.offset = d.offset; it.shown = d.offset;
      if (d.done) { done(it, d.name); return; }
      paint(it);
      chunk(it);
      return;
    }
    if (st === 409 && d && typeof d.offset === 'number') {
      it.offset = d.offset; it.shown = d.offset;
      if (d.offset === base) resume(it); else chunk(it);   // the same offset: an older request still holds it
      return;
    }
    if (st === 404 && d && d.restart) { it.id = null; it.offset = 0; it.shown = 0; it.state = 'queued'; running--; pump(); return; }
    if (st === 400 || st === 413 || st === 507 || st === 500) { fail(it, (d && d.error) || ('Refused (' + st + ').')); return; }
    if (st === 401) { fail(it, 'Logged out - send it again.'); return; }
    resume(it);
  }, { raw: true, timeout: 180000, progress: function (e) { if (e.lengthComputable) { it.shown = base + e.loaded; paint(it); } } });
}
function resume(it) {
  it.fails++;
  if (it.fails > 12) { fail(it, 'The connection keeps dropping.'); return; }
  it.state = 'waiting';
  paint(it, 'Connection lost - resuming' + '…');
  setTimeout(function () {
    if (it.state === 'canceled') return;
    api('GET', '/api/up/status?id=' + encodeURIComponent(it.id), null, function (st, d) {
      if (it.state === 'canceled') return;
      if (st === 200 && d && d.ok) {
        if (d.done) { done(it, d.name); return; }
        it.offset = d.offset; it.shown = d.offset;
        if (d.busy) { resume(it); return; }
        chunk(it);
        return;
      }
      if (st === 404 && d && d.restart) { it.id = null; it.offset = 0; it.shown = 0; it.state = 'queued'; running--; pump(); return; }
      resume(it);
    }, { timeout: 15000 });
  }, Math.min(30000, 1000 * Math.pow(2, Math.min(it.fails - 1, 5))));
}
function done(it, name) {
  it.state = 'done';
  it.shown = it.size;
  paint(it, 'Sent' + (name && name !== it.name ? ' as ' + name : ''));
  it.ui.x.onclick = function () { remove(it); };
  it.ui.x.setAttribute('aria-label', 'Remove');
  finish(it);
}
function fail(it, why) {
  it.state = 'error';
  paint(it, why);
  it.ui.x.onclick = function () { remove(it); };
  it.ui.x.setAttribute('aria-label', 'Remove');
  finish(it);
}
function cancel(it) {
  var was = it.state;
  it.state = 'canceled';
  if (it.xhr) { try { it.xhr.abort(); } catch (e) { } it.xhr = null; }
  if (it.id) api('POST', '/api/up/cancel?id=' + encodeURIComponent(it.id), null, function () { });
  remove(it);
  if (was === 'queued') { var i = queue.indexOf(it); if (i >= 0) queue.splice(i, 1); }
  else if (was !== 'done' && was !== 'error') finish(it);
}
function remove(it) { if (it.ui.row.parentNode) it.ui.row.parentNode.removeChild(it.ui.row); }

/* ---------------- tabs, name, wiring ---------------- */
function tab(t) {
  S.tab = t;
  $('chatPane').className = 'pane chat' + (t === 'chat' ? ' on' : '');
  $('filesPane').className = 'pane files' + (t === 'files' ? ' on' : '');
  $('tabChat').className = 'tab' + (t === 'chat' ? ' sel' : '');
  $('tabFiles').className = 'tab' + (t === 'files' ? ' sel' : '');
  if (t === 'chat') { S.unread = 0; unreadBadge(); toBottom(); }
}
function openName() {
  $('nameInput').value = myName;
  show($('nameDlg'), true);
  try { $('nameInput').focus(); $('nameInput').select(); } catch (e) { }
}
function wire() {
  $('tabChat').onclick = function () { tab('chat'); };
  $('tabFiles').onclick = function () { tab('files'); };
  $('meBtn').onclick = openName;
  $('nameCancel').onclick = function () { show($('nameDlg'), false); };
  $('nameForm').onsubmit = function (e) {
    e.preventDefault();
    var v = $('nameInput').value.replace(/^\s+|\s+$/g, '').slice(0, 40);
    if (!v) return;
    myName = v;
    put('echoes.name', v);
    $('meName').textContent = v;
    show($('nameDlg'), false);
    if (S.loggedIn) api('POST', '/api/name', { name: v }, function (st, d) { if (st === 200 && d && d.me) S.me = d.me; });
  };
  $('loginForm').onsubmit = function (e) {
    e.preventDefault();
    var v = $('pin').value.replace(/[^0-9]/g, '');
    if (v.length < 4) { $('loginErr').textContent = 'Type the 8-digit PIN shown in Echoes.'; return; }
    login(v);
  };
  $('composer').onsubmit = function (e) { e.preventDefault(); sendText(); };
  var ta = $('text');
  ta.value = get('echoes.draft') || '';
  ta.addEventListener('keydown', function (e) {
    var enter = e.key === 'Enter' || e.keyCode === 13;
    if (!enter || e.isComposing || e.keyCode === 229) return;
    if (e.ctrlKey || e.metaKey || (!touch && !e.shiftKey && !e.altKey)) { e.preventDefault(); sendText(); }
  });
  ta.addEventListener('input', function () { grow(); put('echoes.draft', ta.value ? ta.value.slice(0, 20000) : null); });
  grow();
  var input = $('fileInput');
  input.addEventListener('change', function () {
    var list = [], i;
    for (i = 0; i < input.files.length; i++) list.push(input.files[i]);
    try { input.value = ''; } catch (e) { }
    addFiles(list);
  });
  D.addEventListener('paste', function (e) {
    var cd = e.clipboardData, list = [], i, f;
    if (!cd) return;
    if (cd.files && cd.files.length) { for (i = 0; i < cd.files.length; i++) list.push(cd.files[i]); }
    else if (cd.items) { for (i = 0; i < cd.items.length; i++) if (cd.items[i].kind === 'file') { f = cd.items[i].getAsFile(); if (f) list.push(f); } }
    if (list.length) { e.preventDefault(); addFiles(list); }
  });
  var drop = $('drop'), depth = 0;
  function hasFiles(e) { var t = e.dataTransfer && e.dataTransfer.types; if (!t) return false; for (var i = 0; i < t.length; i++) if (t[i] === 'Files') return true; return false; }
  D.addEventListener('dragenter', function (e) { if (!hasFiles(e)) return; e.preventDefault(); depth++; drop.className = 'drop over'; });
  D.addEventListener('dragover', function (e) { if (!hasFiles(e)) return; e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'; });
  D.addEventListener('dragleave', function () { depth = Math.max(0, depth - 1); if (!depth) drop.className = 'drop'; });
  D.addEventListener('drop', function (e) {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    drop.className = 'drop';
    var list = [], i, fl = e.dataTransfer.files;
    for (i = 0; i < fl.length; i++) list.push(fl[i]);
    addFiles(list);
  });
  D.addEventListener('visibilitychange', function () {
    if (D.hidden) return;
    if (S.tab === 'chat' || W.innerWidth >= 760) { S.unread = 0; unreadBadge(); }
    if (S.loggedIn && !S.polling && !S.ws && !S.retry && !S.gone) recover();
  });
  W.addEventListener('resize', function () { if (W.innerWidth >= 760 && S.unread) { S.unread = 0; unreadBadge(); } });
}

$('meName').textContent = myName;
wire();
readLinkPin();
start();
})();
""";
}
