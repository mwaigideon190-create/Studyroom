const V="sr-v4",SHELL=["/","/index.html","/manifest.json","/icon-192.png","/icon-512.png","/admin.html","/admin-manifest.json","/admin-icon-192.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(V).then(c=>Promise.all(SHELL.map(u=>c.add(u).catch(()=>{})))));self.skipWaiting()});
self.addEventListener("activate",e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==V).map(x=>caches.delete(x)))).then(()=>self.clients.claim())));
// Open instantly from the saved copy (even offline or while the server wakes up), and refresh the copy in the background.
self.addEventListener("fetch",e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=="GET"||u.origin!==location.origin||u.pathname.startsWith("/api/"))return;
  const nav=e.request.mode==="navigate",key=nav?(u.pathname.includes("admin")?"/admin.html":"/index.html"):e.request;
  e.respondWith(caches.open(V).then(async c=>{
    const hit=await c.match(key,{ignoreSearch:true});
    const net=fetch(e.request).then(r=>{if(r.ok&&!r.redirected)c.put(key,r.clone());return r}).catch(()=>null);
    e.waitUntil(net);
    return hit||(await net)||Response.error();
  }));
});
