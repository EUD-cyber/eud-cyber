const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../../TESTFILES/ATTACKER-V2/web/static/app.js'),'utf8');
const snippet=source.slice(source.indexOf('function campaignP10Summary'),source.indexOf('async function startCampaign'));
const elements={campaignPowershell:{value:''},campaignBash:{value:''},campaignP10Review:{textContent:''}};
const context=vm.createContext({document:{getElementById:id=>elements[id]}});vm.runInContext(snippet,context);
for(const [ps,bash,a,b] of [['Get-Date','','configured','not configured'],['','printf lab','not configured','configured'],['Get-Date','printf lab','configured','configured'],['  ','\n ','not configured','not configured']]){
  elements.campaignPowershell.value=ps;elements.campaignBash.value=bash;context.updateCampaignP10Review();
  const text=elements.campaignP10Review.textContent;
  assert.ok(text.includes(`PowerShell ${a} / Bash ${b}`));assert.ok(!text.includes('Get-Date'));assert.ok(!text.includes('printf lab'));
  assert.equal(text.includes('NOT_CONFIGURED'),!ps.trim()&&!bash.trim());
}
const html=fs.readFileSync(path.join(__dirname,'../../TESTFILES/ATTACKER-V2/web/templates/index.html'),'utf8');
assert.match(html,/PowerShell command \(Windows, optional\)/);assert.match(html,/Bash command \(Linux, optional\)/);
assert.ok(!html.includes('id="campaignPowershellFields" hidden'));
console.log('Full Campaign independent command fields and redacted Review rendering passed.');
