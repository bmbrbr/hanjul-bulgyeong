const V="hanjul-v47";
const FONTS="hanjul-fonts-1";
const FONT_CSS="https://fonts.googleapis.com/css2?family=Gowun+Batang:wght@400;700&family=Noto+Sans+KR:wght@400;500&display=swap";
const CORE=["./","./index.html","./manifest.webmanifest","./img/tree.webp","./img/monk.webp","./img/dbase.webp","./img/dtree.webp","./img/dmonk.webp","./img/lotus.webp","./icons/icon-192.png","./icons/icon-512.png","./icons/apple-touch-icon.png","./icons/favicon.png"];
const isFont=u=>/(^|\.)(gstatic|googleapis)\.com$/.test(u.hostname);
self.addEventListener("install",e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(CORE)).then(()=>self.skipWaiting()))});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==V&&k!==FONTS).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{const r=e.request;if(r.method!=="GET")return;const u=new URL(r.url);
  if(r.mode==="navigate"){e.respondWith(fetch(r).then(res=>{const cp=res.clone();caches.open(V).then(c=>c.put("./index.html",cp));return res}).catch(()=>caches.match("./index.html")));return}
  if(isFont(u)){
    /* 글꼴은 버전이 바뀌어도 지우지 않는 별도 보관함에 둔다 */
    if(u.hostname==="fonts.googleapis.com"){
      e.respondWith(caches.open(FONTS).then(c=>c.match(r).then(m=>{const net=fetch(r).then(res=>{if(res.ok||res.type==="opaque")c.put(r,res.clone());return res}).catch(()=>m);return m||net})));return}
    e.respondWith(caches.open(FONTS).then(c=>c.match(r).then(m=>m||fetch(r).then(res=>{if(res.ok||res.type==="opaque")c.put(r,res.clone());return res}))));return}
  if(u.origin===location.origin){
    e.respondWith(caches.match(r).then(m=>m||fetch(r).then(res=>{if(res.ok){const cp=res.clone();caches.open(V).then(c=>c.put(r,cp))}return res})))}});
/* 경전 글꼴(고운바탕 보통 굵기) 전체를 한 번 미리 받아 두어, 인터넷이 없어도 처음 보는 글자가 같은 글꼴로 나오게 한다 */
let warming=false;
async function warmFonts(){if(warming)return;warming=true;
  try{const c=await caches.open(FONTS);if(await c.match("warm-done"))return;
    const css=await (await fetch(FONT_CSS,{mode:"cors"})).text();
    const urls=[];css.split("@font-face").forEach(b=>{if(/Gowun Batang/.test(b)&&/font-weight:\s*400/.test(b)){const m=b.match(/url\((https:[^)]+)\)/);if(m)urls.push(m[1])}});
    for(const url of urls){if(await c.match(url))continue;try{const res=await fetch(url,{mode:"cors"});if(res.ok)await c.put(url,res)}catch(e){return}}
    if(urls.length)await c.put("warm-done",new Response("1"))}
  catch(e){}finally{warming=false}}
self.addEventListener("message",e=>{if(e.data==="warm-fonts")e.waitUntil?e.waitUntil(warmFonts()):warmFonts()});
