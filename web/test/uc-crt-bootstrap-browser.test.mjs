import {test} from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs/promises';import path from 'node:path';import os from 'node:os';import {fileURLToPath} from 'node:url';
import {startUcLanServer} from '../tools/uc-lan-server.mjs';
const web=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
test('Edge opt-in compatibility CRT uses local module, original cookie writes and live browser services',{skip:!process.env.UC_CRT_COOKIE_MODULE||!process.env.UC_AUTHENTIC_ASSET_ROOT,timeout:60000},async()=>{
 const temp=await fs.mkdtemp(path.join(os.tmpdir(),'uc-crt-edge-'));let server,browser;
 try{
  server=await startUcLanServer({bind:'127.0.0.1',port:0,dist:path.join(web,'dist'),assetRoot:process.env.UC_AUTHENTIC_ASSET_ROOT,manifest:path.join(process.env.UC_AUTHENTIC_ASSET_ROOT,'phase52-manifest.json'),certDir:temp});
  const {chromium}=await import('playwright');browser=await chromium.launch({channel:'msedge',headless:true});const context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();await page.goto(server.urls[0]);
  await page.locator('#play-preview').click();await page.getByText('Execution inspector',{exact:true}).click();
  await page.locator('#crt-run').click();assert.match(await page.locator('#crt-result').textContent(),/Select the reviewed/);
  await page.locator('#crt-module').setInputFiles(process.env.UC_CRT_COOKIE_MODULE);
  await page.locator('#crt-run').click();await page.waitForFunction(()=>document.querySelector('#crt-result').textContent.includes('originalPeEntryExecuted'));
  const original=JSON.parse(await page.locator('#crt-result').textContent());assert.equal(original.cookieReturned,false);assert.equal(original.lastInstruction,0x87c299);assert.equal(original.hostServices.length,0);
  await page.locator('#crt-mode').selectOption('compatibility-crt');await page.locator('#crt-run').click();await page.waitForFunction(()=>{try{return JSON.parse(document.querySelector('#crt-result').textContent).mode==='compatibility-crt'}catch{return false}});
  const result=JSON.parse(await page.locator('#crt-result').textContent());assert.equal(result.cookieReturned,true);assert.equal(result.hostServices.length,5);assert.equal(result.registers.eip,0xdec0de);assert.equal(result.registers.esp,0x300f000);
  const [ft,pid,tid,tick,qpc]=result.hostServices;let cookie=(ft.outputWords[0]^ft.outputWords[1]^pid.eax^tid.eax^tick.eax^qpc.outputWords[0]^qpc.outputWords[1])>>>0;if(cookie===0xbb40e64e)cookie=0xbb40e64f;
  assert.notEqual(cookie&0xffff0000,0);assert.equal(result.after.cookie,cookie);assert.equal(result.after.complement,(~cookie)>>>0);
  assert.deepEqual(result.originalMemoryWrites.filter(w=>w.address===0x1285688||w.address===0x128568c).map(w=>w.instruction),[0x87c2e5,0x87c2ed]);
  assert.equal(result.virtualProcess.provenance,'BROWSER_COMPATIBILITY_ENVIRONMENT');assert.equal(result.originalPeEntryExecuted,false);assert.equal(result.originalLoaderBindingObserved,false);assert.equal(result.importValuesUnchanged,true);assert.equal(result.cleanupProvider,0x8aac6a);
  assert.equal(result.syntheticThreadDependencies.compatibilityContext.ownerToken,0x3010000);assert.equal(result.startupState,0);assert.equal(result.startupOwner,0);assert.deepEqual(result.cleanupGlobals,[0,0]);assert.equal(result.milestones.cInitializers,false);
  assert.equal(await page.locator('#play').isDisabled(),true);
  if(process.env.UC_CRT_EVIDENCE)await fs.writeFile(process.env.UC_CRT_EVIDENCE,JSON.stringify({browser:'msedge',browserVersion:browser.version(),secureContext:await page.evaluate(()=>isSecureContext),originalOnly:original,compatibility:result},null,2)+'\n');
 }finally{await browser?.close();await server?.close();await fs.rm(temp,{recursive:true,force:true});}
});
