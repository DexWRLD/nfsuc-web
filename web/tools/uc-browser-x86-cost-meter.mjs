// Nested inclusive/exclusive profiler. Timings are diagnostic, not adoption samples.
export function createCostMeter(enabled=true) {
 const rows={},counters={},stack=[];const start=performance.now();
 function enter(name){if(!enabled)return()=>{};const frame={name,start:performance.now(),children:0};stack.push(frame);return()=>{const ms=performance.now()-frame.start;if(stack.pop()!==frame)throw new Error('Profiler nesting mismatch');const row=rows[name]??={calls:0,inclusiveMs:0,exclusiveMs:0};row.calls++;row.inclusiveMs+=ms;row.exclusiveMs+=Math.max(0,ms-frame.children);if(stack.length)stack.at(-1).children+=ms;};}
 function measure(name,fn){const end=enter(name);try{return fn();}finally{end();}}
 function result(){if(stack.length)throw new Error('Unclosed profiler scope');return{wallMs:performance.now()-start,categories:rows,counters,exclusiveSumMs:Object.values(rows).reduce((s,r)=>s+r.exclusiveMs,0),note:'Inclusive times overlap. Sum only exclusive times; uninstrumented work and profiler overhead remain outside named scopes.'};}
 return{enter,measure,result,count(name,amount=1){if(enabled)counters[name]=(counters[name]??0)+amount;}};
}
