'use strict';
/* Paqet Tunnel Plus Web 0.1.1: local read-only dashboard.
 * Sample values are illustrative; tests never run from this screen.
 */
const byId = id => document.getElementById(id);
const sections = {
  overview:['نمای کلی تانل‌ها','وضعیت محلی سرویس‌ها'],
  tunnels:['تانل‌ها و سرویس‌ها','تنظیمات غیرمحرمانه و وضعیت سرویس'],
  tests:['آزمایش کیفیت مسیر','پیش‌نمایش ابزارهای آینده؛ تست سرعت در این نسخه فعال نیست'],
  flags:['آزمایش پرچم‌های TCP','پیش‌نمایش شش پروفایل؛ اجرا فقط در منوی SSH'],
  logs:['لاگ‌ها و عیب‌یابی','مشاهده آخرین لاگ‌های سرویس انتخاب‌شده'],
  settings:['تنظیمات و امنیت','پنل فقط‌خواندنی با اتصال SSH محلی']
};
const examples = [
  {name:'tunnel',role:'client',service:'paqet-plus-client-tunnel',state:'demo',local_flag:'S',remote_flag:'PA',kcp_mode:'fast2',conn:'1',mtu:'1200'},
  {name:'tunnel',role:'server',service:'paqet-plus-server-tunnel',state:'demo',local_flag:'PA',remote_flag:'PA',kcp_mode:'fast2',conn:'1',mtu:'1200'}
];
const profiles = [
  {name:'historic-s-sa',client:'S / SA',server:'SA / PA',result:'8/8 در تست اولیه'},
  {name:'current-s-pa',client:'S / PA',server:'PA / PA',result:'40/40 در تست پایداری'},
  {name:'standard-pa-pa',client:'PA / PA',server:'PA / PA',result:'0/8 در تست اولیه'},
  {name:'pa-sa',client:'PA / SA',server:'SA / PA',result:'0/8 در تست اولیه'},
  {name:'s-a',client:'S / A',server:'A / PA',result:'40/40 در تست پایداری'},
  {name:'pa-a',client:'PA / A',server:'A / PA',result:'0/8 در تست اولیه'}
];
let token='', live=false, services=examples, selected=1, onConfirm=null;

function showDialog(title, text, needsToken=false, next=null) {
  byId('modalHeading').textContent=title;
  byId('modalText').textContent=text;
  byId('tokenWrap').style.display=needsToken?'block':'none';
  byId('confirmModal').style.display=next?'inline-flex':'none';
  byId('tokenInput').value='';
  onConfirm=next;
  byId('dialog').classList.add('show');
  if(needsToken) byId('tokenInput').focus();
}
function hideDialog(){byId('dialog').classList.remove('show');onConfirm=null;}
byId('cancelModal').addEventListener('click',hideDialog);
byId('confirmModal').addEventListener('click',()=>{if(onConfirm)onConfirm(byId('tokenInput').value);});

document.querySelectorAll('[data-section]').forEach(btn=>{
  btn.addEventListener('click',()=>{
    const k=btn.dataset.section;
    document.querySelectorAll('[data-section]').forEach(x=>x.classList.toggle('active',x===btn));
    document.querySelectorAll('.panel-view').forEach(x=>x.classList.toggle('current',x.id==='view-'+k));
    byId('heading').textContent=sections[k][0];
    byId('subtitle').textContent=sections[k][1];
  });
});
function paintTable(id, rows) {
  const tbody=byId(id);
  tbody.replaceChildren();
  rows.forEach(cols=>{
    const tr=document.createElement('tr');
    cols.forEach(cell=>{
      const td=document.createElement('td');
      td.textContent=String(cell===undefined?'—':cell);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}
function paint() {
  byId('count').textContent=live?String(services.length):'۲ نمونه';
  byId('active').textContent=live?String(services.filter(x=>x.state==='active').length):'—';
  paintTable('homeRows',services.map(x=>[x.service,x.role==='client'?'ایران / Client':'خارج / Server',x.state==='demo'?'نمایشی':x.state,x.local_flag,x.remote_flag]));
  paintTable('serviceRows',services.map(x=>[x.service,x.role,x.state,x.kcp_mode,x.mtu,x.conn,String(x.local_flag)+' / '+String(x.remote_flag)]));
  const sel=byId('logService'), old=sel.value;
  sel.replaceChildren();
  services.forEach(x=>{
    const o=document.createElement('option');
    o.value=x.service;
    o.textContent=x.service;
    sel.appendChild(o);
  });
  if(services.some(x=>x.service===old))sel.value=old;
}
function paintFlags(){
  const list=byId('profiles');
  list.replaceChildren();
  profiles.forEach((p,i)=>{
    const btn=document.createElement('button');
    btn.type='button';
    btn.className='profile'+(i===selected?' selected':'');
    const title=document.createElement('strong');
    title.textContent='پروفایل '+(i+1)+' — '+p.name;
    const details=document.createElement('small');
    details.textContent='ایران: '+p.client+' | آلمان: '+p.server+' | '+p.result;
    btn.append(title,details);
    btn.addEventListener('click',()=>{selected=i;paintFlags();});
    list.appendChild(btn);
  });
  byId('selectedProfile').textContent=(selected+1)+' — '+profiles[selected].name;
  byId('selectedFlags').textContent='Iran: '+profiles[selected].client+' | Germany: '+profiles[selected].server;
}
async function api(path){
  const r=await fetch(path,{headers:{Authorization:'Bearer '+token},cache:'no-store'});
  if(!r.ok)throw new Error('HTTP '+r.status);
  return await r.json();
}
async function refresh(){
  if(!live){
    showDialog('حالت نمایشی','برای دریافت اطلاعات واقعی، سرویس محلی پنل را اجرا و با توکن وارد شوید.');
    return;
  }
  try {
    const data=await api('/api/status');
    services=data.services||[];
    byId('coreVersion').textContent=data.core_version||'unknown';
    paint();
  } catch(e) {showDialog('خطای ارتباط','بروزرسانی انجام نشد: '+e.message);}
}
async function login(value){
  token=String(value).trim();
  try {
    if(!(await api('/api/check')).ok)throw new Error('invalid');
    live=true;
    byId('loginBtn').textContent='قطع اتصال';
    byId('livePill').className='pill good';
    byId('livePill').textContent='● متصل — فقط‌خواندنی';
    byId('sideState').textContent='پایش زنده محلی';
    hideDialog();
    await refresh();
  } catch(e) {
    token='';
    showDialog('ورود ناموفق','توکن اشتباه است یا پنل سرور از طریق SSH در دسترس نیست.');
  }
}
byId('loginBtn').addEventListener('click',()=>{
  if(live){
    token='';live=false;services=examples;
    byId('coreVersion').textContent='alpha.21*';
    byId('loginBtn').textContent='اتصال به پنل';
    byId('livePill').className='pill warn';
    byId('livePill').textContent='● نمونه اولیه — اتصال واقعی انجام نشده';
    byId('sideState').textContent='حالت نمایشی آفلاین';
    paint();
  } else {
    showDialog('اتصال به پنل','توکن فایل /opt/paqet-tunnel-plus/web-panel.token را در این پنجره وارد کنید. آن را برای دیگران نفرستید.',true,login);
  }
});
byId('refreshStatus').addEventListener('click',refresh);
byId('loadLogs').addEventListener('click',async()=>{
  if(!live){showDialog('حالت نمایشی','برای خواندن لاگ ابتدا متصل شوید.');return;}
  try{
    const q='/api/logs?service='+encodeURIComponent(byId('logService').value)+'&lines=80';
    byId('logOutput').textContent=(await api(q)).logs||'لاگی وجود ندارد';
  }catch(e){byId('logOutput').textContent='خطا: '+e.message;}
});
byId('plannedManagement').addEventListener('click',()=>showDialog('امکانات آینده','مدیریت سرویس بعد از افزودن مجوزهای تفکیک‌شده، بکاپ و بازگشت امن فعال می‌شود.'));
byId('plannedTest').addEventListener('click',()=>showDialog('تست سرعت واقعی','این نسخه تست سرعت اجرا نمی‌کند. اجرای تست نیازمند عامل آزمون در هر دو سرور و محدودیت حجم/زمان است.'));
byId('plannedFlags').addEventListener('click',()=>showDialog('تست پرچم‌ها','برای پروفایل '+(selected+1)+' فعلاً از مدیریت SSH گزینه ۸ استفاده کنید؛ این رابط YAML را تغییر نمی‌دهد.'));
byId('copyCmd').addEventListener('click',()=>{
  const cmd='ssh -L 8792:127.0.0.1:8792 root@SERVER_IP';
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(cmd).then(()=>showDialog('کپی شد',cmd)).catch(()=>showDialog('دستور اتصال',cmd));
  }else showDialog('دستور اتصال',cmd);
});
paint();paintFlags();
