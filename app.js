const $ = (id) => document.getElementById(id);
const logBox = $('activityLog');
function addLog(message, type='SYSTEM') {
  const p = document.createElement('p');
  const i = document.createElement('i'); i.textContent = `[${type}] `;
  p.append(i, document.createTextNode(message)); logBox.appendChild(p); logBox.scrollTop = logBox.scrollHeight;
  while (logBox.children.length > 18) logBox.removeChild(logBox.firstChild);
}
function toast(message) { const el=$('toast'); el.textContent=message; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'),2800); }
async function readResponse(r) {
  const raw = await r.text();
  let data;
  try { data = raw ? JSON.parse(raw) : {}; }
  catch (_) { throw new Error(`Server returned an invalid response (HTTP ${r.status}). Restart Flask and try again.`); }
  if (!r.ok) throw new Error(data.error || `Request failed (HTTP ${r.status})`);
  return data;
}
async function postJSON(url, body) {
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  return readResponse(r);
}
function showResults(data) {
  const list=$('resultsList'); list.replaceChildren();
  data.results.forEach(item=>{
    const card=document.createElement('div'); card.className='result-item';
    const title=document.createElement('b'); title.textContent=(item.passed?'✓ ':'⚠ ')+item.name; title.className=item.passed?'pass':'fail';
    const detail=document.createElement('small'); detail.textContent=item.detail;
    card.append(title,detail); list.appendChild(card);
  });
  const warnings=data.results.filter(x=>!x.passed).length;
  $('resultSummary').textContent=warnings===0?'All checks passed':`${warnings} warning(s) detected`;
  $('decisionRow').hidden=warnings===0;
  $('decisionText').textContent=warnings?`${warnings} warning(s) need your review. This demo lets you decide whether to proceed.`:'No warnings detected.';
  $('networkStatus').textContent=warnings?'Warnings detected':'Checks passed';
  $('hostAddress').textContent=data.host_ip?`Host IP: ${data.host_ip}`:$('hostAddress').textContent;
  addLog(`${data.mode==='simulation'?'Simulation':'LAN'} assessment complete: ${warnings} warning(s).`,warnings?'WARNING':'READY');
}
$('simulateBtn').addEventListener('click',async()=>{
  $('simulateBtn').disabled=true; $('simulateBtn').textContent='Checking...'; addLog('Running virtual device assessment...');
  try{const data=await postJSON('/api/simulate',{ip_a:$('simIpA').value,ip_b:$('simIpB').value});showResults(data);toast('Simulation assessment completed');}
  catch(e){toast(e.message);addLog(e.message,'ERROR');}finally{$('simulateBtn').disabled=false;$('simulateBtn').textContent='Run Simulation Check →';}
});
async function detectBrowserComputer(){
  const info=$('clientConnectionInfo');
  try{
    const response=await fetch('/api/client-info');
    const data=await readResponse(response);
    const ipField=$('targetIp');
    // Prefill from the browser connection once, but never overwrite a user's manual IP.
    if(!ipField.dataset.userEdited && data.is_lan_client && !ipField.value){ipField.value=data.client_ip;}
    info.textContent=data.is_lan_client
      ? `Browser connection detected from ${data.client_ip}. You may keep it or enter another laptop's IPv4 address.`
      : "You are viewing CyberShield on the host. Enter the other laptop's Wi-Fi IPv4 address below.";
    info.classList.toggle('pass', Boolean(data.is_lan_client));
    $('lanCheckBtn').disabled=false;
  }catch(e){info.textContent='Automatic detection unavailable. You can still enter the other laptop IPv4 address manually.';$('lanCheckBtn').disabled=false;}
}
$('targetIp').addEventListener('input',()=>{$('targetIp').dataset.userEdited='true';});
$('lanCheckBtn').addEventListener('click',async()=>{
  const targetIp=$('targetIp').value.trim();
  if(!targetIp){toast('Enter the other laptop IPv4 address first.');$('targetIp').focus();return;}
  $('lanCheckBtn').disabled=true;$('lanCheckBtn').textContent='Checking...';addLog('Starting LAN assessment for '+targetIp+'...');
  try{const data=await postJSON('/api/lan-check',{target_ip:targetIp,target_port:$('targetPort').value});showResults(data);toast('LAN assessment completed');}
  catch(e){toast(e.message);addLog(e.message,'ERROR');$('clientConnectionInfo').textContent=e.message;}
  finally{$('lanCheckBtn').textContent='Run LAN Security Check →';$('lanCheckBtn').disabled=false;}
});
$('continueBtn').addEventListener('click',()=>{toast('Decision recorded: you chose to continue despite warnings.');addLog('User acknowledged warnings and chose to continue.','USER');});
$('sendMessageBtn').addEventListener('click',async()=>{
  const msg=$('messageInput').value.trim(); if(!msg){toast('Enter a message first');return;}
  const mode=$('transferMode').value;
  try{
    const data = mode==='simulation'
      ? await postJSON('/api/simulate/message',{message:msg,sender:$('simSender').value})
      : await postJSON('/api/message',{message:msg});
    $('messageFeedback').textContent = mode==='simulation'
      ? `${data.sender} sent a simulated message to ${data.recipient} at ${data.time}.`
      : `Message received by host at ${data.time}.`;
    $('messageInput').value='';
    await refreshMessages();
    addLog(mode==='simulation' ? `Virtual message: ${data.sender} → ${data.recipient}.` : 'Text message received by host.','TRANSFER');
    toast(mode==='simulation'?'Simulated message delivered':'Message sent');
  } catch(e){$('messageFeedback').textContent=e.message;addLog(e.message,'ERROR');}
});
$('uploadBtn').addEventListener('click',async()=>{
  const file=$('fileInput').files[0];if(!file){toast('Choose a file first');return;}if(file.size>5*1024*1024){$('fileFeedback').textContent='File exceeds the 5 MB limit.';return;}
  const mode=$('transferMode').value;
  const form=new FormData();form.append('file',file);
  try{
    const r=await fetch(mode==='simulation'?'/api/simulate/upload':'/api/upload',{method:'POST',body:form});
    const data=await readResponse(r);
    $('fileFeedback').textContent=mode==='simulation'
      ? `Simulated transfer complete: ${data.name} (${(data.size/1024).toFixed(1)} KB), Device A → Device B. No file was saved.`
      : `Received ${data.name} (${(data.size/1024).toFixed(1)} KB) on the host.`;
    addLog(`${mode==='simulation'?'Simulated file transfer':'File received'}: ${data.name}`,'TRANSFER');
    await refreshFiles();
    toast(mode==='simulation'?'Virtual file transfer complete':'File transferred to host');
  } catch(e){$('fileFeedback').textContent=e.message;addLog(e.message,'ERROR');}
});
$('menuToggle').addEventListener('click',()=>$('mainNav').classList.toggle('open'));
document.querySelectorAll('#mainNav a').forEach(a=>a.addEventListener('click',()=>$('mainNav').classList.remove('open')));
async function refreshStatus(){try{const r=await fetch('/api/status');const d=await r.json();$('hostAddress').textContent=`Host IP: ${d.host_ip}`;}catch(_){$('networkStatus').textContent='Offline';}}
async function refreshMessages(){try{const mode=$('transferMode')?.value||'simulation';const r=await fetch(mode==='simulation'?'/api/simulate/messages':'/api/messages');const items=await readResponse(r);const box=$('messageHistory');box.replaceChildren();if(!items.length){box.textContent='No messages in this mode yet.';return;}items.slice(-8).forEach(x=>{const p=document.createElement('p');const b=document.createElement('b');b.textContent=`${x.time} · ${x.sender}${x.recipient?' → '+x.recipient:''}: `;p.append(b,document.createTextNode(x.message));box.appendChild(p);});}catch(e){$('messageHistory').textContent=e.message;}}
async function refreshFiles(){try{const mode=$('transferMode')?.value||'simulation';const r=await fetch(mode==='simulation'?'/api/simulate/files':'/api/files');const items=await readResponse(r);const box=$('sharedFiles');box.replaceChildren();if(!items.length){box.textContent=mode==='simulation'?'No simulated files transferred yet.':'No files received yet.';return;}items.slice(0,8).forEach(x=>{const p=document.createElement('p');if(mode==='simulation'){p.textContent=`✓ ${x.name} (${(x.size/1024).toFixed(1)} KB) · ${x.sender} → ${x.recipient} · virtual transfer`;}else{const a=document.createElement('a');a.href='/api/files/'+encodeURIComponent(x.stored_name);a.textContent=`↓ ${x.name} (${(x.size/1024).toFixed(1)} KB)`;a.setAttribute('download','');p.appendChild(a);}box.appendChild(p);});}catch(e){$('sharedFiles').textContent=e.message;}}
async function refreshLogs(){try{const r=await fetch('/api/logs');const entries=await r.json();if(entries.length){logBox.replaceChildren();entries.slice(0,7).reverse().forEach(x=>{const p=document.createElement('p');const i=document.createElement('i');i.textContent=`[${x.time}] `;p.append(i,document.createTextNode(x.event+': '+x.detail));logBox.appendChild(p);});}}catch(_){}}
// Decorative falling-code background.
const canvas=$('matrix'),ctx=canvas.getContext('2d');let drops=[];function resize(){canvas.width=innerWidth;canvas.height=innerHeight;drops=Array(Math.ceil(canvas.width/18)).fill(1);}window.addEventListener('resize',resize);resize();function drawMatrix(){ctx.fillStyle='rgba(0,5,2,0.09)';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle='#16d94e';ctx.font='13px monospace';drops.forEach((y,i)=>{ctx.fillText(Math.random()>.5?'1':'0',i*18,y*17);if(y*17>canvas.height&&Math.random()>.975)drops[i]=0;drops[i]++;});requestAnimationFrame(drawMatrix);}drawMatrix();
$('transferMode').addEventListener('change',()=>{const sim=$('transferMode').value==='simulation';$('simSender').disabled=!sim;refreshMessages();refreshFiles();});$('simSender').disabled=false;refreshStatus();detectBrowserComputer();refreshLogs();refreshMessages();refreshFiles();setInterval(()=>{refreshMessages();refreshFiles();refreshLogs();},3000);
