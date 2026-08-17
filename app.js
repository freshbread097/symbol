const $ = (s) => document.querySelector(s);
const input = $('#so'), go = $('#go'), stop = $('#stop'), status = $('#status'), nameEl = $('#name');
let file = null, stopped = false, enginePromise = null;

function log(text){ status.textContent = text; }
function versionFrom(bytes){
  const text = new TextDecoder('latin1').decode(bytes);
  // Only accept a full Unity build string, not arbitrary YYYY.x.x text.
  const patterns = [
    /Unity(?:Player)?[^\x20-\x7e]{0,32}(?:version|build)[^\x20-\x7e]{0,32}(20\d{2}|6000)\.([0-9]+)\.([0-9]+)[a-z](\d+)/i,
    /Unity(?:Player)?[^\x00-\x20]{0,80}((?:20\d{2}|6000)\.[0-9]+\.[0-9]+[a-z]\d+)/i,
    /((?:20\d{2}|6000)\.[0-9]+\.[0-9]+[abfp]\d+)/i
  ];
  for (const r of patterns){
    const m = text.match(r);
    if (m){
      const v = m[1] || m[0].match(/(?:20\d{2}|6000)\.[0-9]+\.[0-9]+[abfp]\d+/i)?.[0];
      if (v) return v;
    }
  }
  return null;
}
function elfArch(buf){
  const d = new Uint8Array(buf);
  if(d[0]!==0x7f||d[1]!==0x45||d[2]!==0x4c||d[3]!==0x46) throw Error('Not an ELF file.');
  if(d[5]!==1) throw Error('Only little-endian Android ELF files are supported.');
  const machine=d[18]|(d[19]<<8);
  if(machine===183) return 'arm64-v8a';
  if(machine===40) return 'armeabi-v7a';
  throw Error(`Unsupported Android architecture (e_machine=${machine}).`);
}
async function githubJson(url){
  const r=await fetch(url,{headers:{Accept:'application/vnd.github+json'}});
  if(!r.ok) throw Error(`GitHub API ${r.status} for ${url}`);
  return r.json();
}
async function findUnityAsset(version, arch){
  const base='https://api.github.com/repos/LavaGang/MelonLoader.UnityDependencies';
  const tags=[version];
  const bare=version.replace(/[abfp]\d+$/i,'');
  if(bare!==version) tags.push(bare);
  for(const tag of tags){
    try{
      const rel=await githubJson(`${base}/releases/tags/${encodeURIComponent(tag)}`);
      const a=rel.assets?.find(x=>x.name===`libunity.so.${arch}`);
      if(a) return {release:rel.tag_name,assetApi:`${base}/releases/assets/${a.id}`,name:a.name};
    }catch{}
  }
  for(let page=1;page<=12;page++){
    let list;
    try{list=await githubJson(`${base}/releases?per_page=100&page=${page}`)}catch(e){throw Error(`Could not query UnityDependencies releases: ${e.message}`)}
    if(!Array.isArray(list)||!list.length) break;
    for(const rel of list){
      const t=String(rel.tag_name||'');
      if(t!==version && t!==bare) continue;
      const a=rel.assets?.find(x=>x.name===`libunity.so.${arch}`);
      if(a) return {release:t,assetApi:`${base}/releases/assets/${a.id}`,name:a.name};
    }
  }
  throw Error(`No clean UnityDependencies release matched ${version} (${arch}). The detected version came from an explicit Unity build string.`);
}
async function downloadAsset(asset){
  // GitHub's release-asset API is CORS-friendly and redirects to the binary.
  const r=await fetch(asset.assetApi,{headers:{Accept:'application/octet-stream'}});
  if(!r.ok) throw Error(`Clean Unity ${asset.release} reference download failed: HTTP ${r.status}`);
  const b=await r.arrayBuffer();
  if(b.byteLength<1024*1024) throw Error(`Clean Unity ${asset.release} reference download returned only ${b.byteLength.toLocaleString()} bytes; the release asset was not received.`);
  return b;
}
function loadEngine(){
  if(enginePromise) return enginePromise;
  enginePromise=new Promise((resolve,reject)=>{
    if(window.Module?.__rzwasiReady){ resolve(window.Module); return; }
    window.Module = {locateFile:(name)=>`engine/${name}`,onRuntimeInitialized(){window.Module.__rzwasiReady=true;resolve(window.Module)},onAbort:(e)=>reject(new Error(`Rizin WASM aborted: ${e}`))};
    const s=document.createElement('script'); s.src='engine/rizin.js'; s.async=true; s.onerror=()=>reject(new Error(`Could not load engine/rizin.js. URL: ${new URL('engine/rizin.js',location.href).href}`)); document.head.appendChild(s);
  });
  return enginePromise;
}
function createSession(M){const create=M.cwrap('rzweb_create_session','number',[]),open=M.cwrap('rzweb_open_file','number',['number','string','number','number']),cmd=M.cwrap('rzweb_cmd','string',['number','string']),close=M.cwrap('rzweb_close_session',null,['number']);const id=create();if(!id)throw Error('Could not create a Rizin analysis session.');return{id,open,cmd,close}}
function jsonCmd(s,c){const out=s.cmd(s.id,c);try{return JSON.parse(out)}catch{return null}}
function normAsm(x){return String(x||'').toLowerCase().replace(/0x[0-9a-f]+/g,' IMM ').replace(/\b-?\d+\b/g,' IMM ').replace(/\s+/g,' ').replace(/\b(sym\.imp|fcn\.|sub\.)[^\s,]+/g,' FUNC ').trim()}
function opsFromPdfj(obj){const out=[];const walk=v=>{if(!v||typeof v!=='object')return;if(Array.isArray(v)){for(const x of v)walk(x);return}if(typeof v.opcode==='string')out.push(v.opcode);else if(typeof v.disasm==='string')out.push(v.disasm);for(const k of Object.keys(v))if(k!=='opcode'&&k!=='disasm')walk(v[k])};walk(obj);return out}
async function functionSignatures(s,funcs,label){const map=[];let i=0;for(const f of funcs){if(stopped)throw Error('Stopped.');if(!f?.offset||!f?.size)continue;const raw=s.cmd(s.id,`pdfj @ ${f.offset}`);let obj;try{obj=JSON.parse(raw)}catch{obj=null}const sig=opsFromPdfj(obj).map(normAsm).join('|');map.push({...f,sig});i++;if(i%20===0)log(`${label}: ${i.toLocaleString()} functions analyzed…`)}return map}
async function decompile(s,addr){try{return String(s.cmd(s.id,`pdd @ ${addr}`)||'')}catch{return ''}}
function normPseudo(code,names){let x=String(code||'').replace(/\/\*.*?\*\//gs,' ').replace(/\/\/.*$/gm,' ');x=x.replace(/0x[0-9a-f]+/gi,' ADDR ').replace(/\b\d+(?:\.\d+)?\b/g,' NUM ');for(const n of names)if(n)x=x.replace(new RegExp(`(?<![A-Za-z0-9_$])${n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}(?![A-Za-z0-9_$])`,'g'),' FUNC ');return x.replace(/\s+/g,' ').trim()}
async function mapFunctions(targetSession,cleanSession,targetFuncs,cleanFuncs){const cleanBySig=new Map;for(const f of cleanFuncs){if(!f.sig)continue;const a=cleanBySig.get(f.sig)||[];a.push(f);cleanBySig.set(f.sig,a)}const result={},used=new Set;for(const f of targetFuncs){const c=cleanBySig.get(f.sig)||[];if(c.length===1&&c[0].name!==f.name&&!used.has(c[0].name)){result[f.name]=c[0].name;used.add(c[0].name)}}const unresolved=targetFuncs.filter(f=>!result[f.name]&&f.name&&!f.name.startsWith('sym.imp.')),candidates=cleanFuncs.filter(f=>f.name&&!f.name.startsWith('sym.imp.')&&!used.has(f.name)),groups=new Map;for(const f of candidates){const k=`${f.size}:${f.sig.split('|').length}`,a=groups.get(k)||[];a.push(f);groups.set(k,a)}let count=0;for(const f of unresolved){if(stopped)throw Error('Stopped.');const pool=groups.get(`${f.size}:${f.sig.split('|').length}`)||[];if(!pool.length||pool.length>12)continue;const tc=normPseudo(await decompile(targetSession,f.offset),targetFuncs.map(x=>x.name));if(!tc)continue;let best=null,score=0;for(const c of pool){if(used.has(c.name))continue;const cc=normPseudo(await decompile(cleanSession,c.offset),cleanFuncs.map(x=>x.name));if(!cc)continue;const n=Math.min(tc.length,cc.length);let s=0;for(let i=0;i<n;i+=16)if(tc.slice(i,i+16)===cc.slice(i,i+16))s++;const ratio=s/Math.max(1,Math.ceil(Math.max(tc.length,cc.length)/16));if(ratio>score){score=ratio;best=c}}if(best&&score>=.78&&best.name!==f.name){result[f.name]=best.name;used.add(best.name)}if(++count%5===0)log(`Decompiler fallback: ${count} ambiguous functions checked…`)}return result}
async function main(){stopped=false;stop.disabled=false;go.disabled=true;try{log('Reading libunity.so locally…');const buf=await file.arrayBuffer(),arch=elfArch(buf),version=versionFrom(new Uint8Array(buf));if(!version)throw Error('Could not find a valid Unity build string (for example 2021.3.45f1) in libunity.so. I will not guess the version from unrelated numbers.');log(`Detected Unity ${version} / ${arch}. Finding matching clean Unity library…`);const ref=await findUnityAsset(version,arch);log(`Found clean Unity ${ref.release}: ${ref.name}. Downloading through GitHub release API…`);const rb=await downloadAsset(ref);if(stopped)throw Error('Stopped.');log('Loading Rizin + JSDec WebAssembly…');const M=await loadEngine(),t=createSession(M),c=createSession(M);try{M.FS.writeFile('/target.so',new Uint8Array(buf));M.FS.writeFile('/clean.so',new Uint8Array(rb));if(!t.open(t.id,'/target.so',0,1)||!c.open(c.id,'/clean.so',0,1))throw Error('Rizin could not open one of the ELF libraries.');log('Analyzing target library…');t.cmd(t.id,'aaa');log('Analyzing clean Unity reference…');c.cmd(c.id,'aaa');const tf=jsonCmd(t,'aflj')||[],cf=jsonCmd(c,'aflj')||[];log(`Functions discovered: target ${tf.length.toLocaleString()} / clean ${cf.length.toLocaleString()}.`);const ts=await functionSignatures(t,tf,'Target'),cs=await functionSignatures(c,cf,'Reference');log('Matching functions…');const map=await mapFunctions(t,c,ts,cs);const blob=new Blob([JSON.stringify(map,null,2)+'\n'],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='SymbolMap.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);log(`Done.\nUnity: ${version}\nArchitecture: ${arch}\nTarget functions: ${ts.length.toLocaleString()}\nReference functions: ${cs.length.toLocaleString()}\nMappings: ${Object.keys(map).length.toLocaleString()}\n\nSymbolMap.json downloaded.`)}finally{try{t.close(t.id)}catch{}try{c.close(c.id)}catch{}}}catch(e){log(`Error: ${e.message||e}`)}finally{stop.disabled=true;go.disabled=!file}}
input.onchange=()=>{file=input.files[0]||null;nameEl.textContent=file?`${file.name} — ${file.size.toLocaleString()} bytes`:'No file selected.';go.disabled=!file};go.onclick=main;stop.onclick=()=>{stopped=true;log('Stopping after the current browser analysis call…')};loadEngine().then(()=>{log('Browser analysis engine ready. Select libunity.so.');go.disabled=!file}).catch(e=>log(e.message));
