const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
(async () => {
  const browser = await chromium.launch({headless:true});
  const page = await browser.newPage({viewport:{width:1280,height:1000}});
  const errors = []; page.on('pageerror',e=>errors.push(e.message));
  try {
    for (let i=0;;i++) {
      try { await page.goto('http://127.0.0.1:5055/pages/settings.html'); break; }
      catch(e) {if(i===30) throw e;await new Promise(r=>setTimeout(r,300));}
    }
    await page.locator('.vm-row').first().waitFor();
    const count = await page.locator('.vm-row').count();
    assert(count>=23);
    assert.equal(await page.getByRole('button',{name:'Rediger',exact:true}).count(),count);
    assert.equal(await page.getByRole('button',{name:'Fjern',exact:true}).count(),count);
    await page.getByRole('button',{name:'Tilføj forbindelse',exact:true}).click();
    assert.deepEqual(await page.locator('[name=protocol] option').allTextContents(),['RDP','SSH','VNC']);
    await page.getByRole('button',{name:'Annuller',exact:true}).click();
    // Empty portal state must still permit creation; leave fixture DB rows intact.
    const removeAll = await page.evaluate(async () => {
      const {connections} = await (await fetch('/api/vm-connections')).json();
      for(const r of connections) {
        const response = await fetch('/api/vm-connections/'+r.key,{method:'DELETE',headers:{'Content-Type':'application/json','Idempotency-Key':crypto.randomUUID()},body:JSON.stringify({version:r.version})});
        if(!response.ok) return await response.text();
      }
      return '';
    });
    assert.equal(removeAll,'');
    await page.getByRole('button',{name:'Opdater liste',exact:true}).click();
    await page.getByText('Ingen forbindelser. Tilføj den første ovenfor.').waitFor();
    await page.getByRole('button',{name:'Tilføj forbindelse',exact:true}).click();
    await page.locator('[name=name]').fill('MrNobody Slave');
    await page.locator('[name=label]').fill('Slave SSH');
    await page.locator('[name=protocol]').selectOption('ssh');
    assert.equal(await page.locator('[name=port]').inputValue(),'22');
    await page.locator('[name=host]').fill('192.168.1.50');
    await page.locator('[name=username]').fill('ubuntu');
    await page.locator('[name=password]').fill('browser-fixture-secret');
    await page.getByRole('button',{name:'Gem forbindelse',exact:true}).click();
    await page.locator('#editConnection').waitFor({state:'hidden'});
    await page.locator('.vm-row').filter({hasText:'Slave SSH'}).waitFor();
    const data = await page.evaluate(async()=>await (await fetch('/api/vm-connections')).json());
    assert(!JSON.stringify(data).includes('browser-fixture-secret'));
    assert(data.connections[0].connectionId>0);
    await page.getByRole('button',{name:'Rediger',exact:true}).click();
    assert.equal(await page.locator('[name=password]').inputValue(),'');
    await page.locator('[name=label]').fill('Slave SSH renamed');
    await page.getByRole('button',{name:'Gem forbindelse',exact:true}).click();
    await page.locator('#editConnection').waitFor({state:'hidden'});
    await page.getByText('MrNobody Slave · Slave SSH renamed',{exact:true}).waitFor();
    fs.mkdirSync('guacvm-evidence',{recursive:true});
    await page.screenshot({path:'guacvm-evidence/settings-desktop.png',fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:'guacvm-evidence/settings-mobile.png',fullPage:true});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await page.goto('http://127.0.0.1:5055/');
    await page.getByRole('heading',{name:'MrNobody Slave',exact:true}).waitFor();
    await page.locator('.card-button').click();
    assert.match(await page.getByRole('link',{name:/Slave SSH renamed/}).getAttribute('href'),/^\/guacamole\/#\/client\//);
    await page.goto('http://127.0.0.1:5055/pages/settings.html');
    page.on('dialog',d=>d.accept());
    await page.getByRole('button',{name:'Fjern',exact:true}).click();
    await page.getByText('Ingen forbindelser. Tilføj den første ovenfor.').waitFor();
    assert.deepEqual(errors,[]);
    console.log('Browser: existing rows, empty state, create, edit/password preservation, portal link, mobile and removal passed.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
