
// const BASE = 0x3ff7ea1000n;
const BASE = 0x2aaaaaa000n;
const LIBC_BASE = 0x2000048f50n;

const bfInstructions = {};

class Gadget {
    frameLocation = null;
    nextRa = null;
    synthesize() {
        throw "not defined";
    }
    getSize() { //size of gadget stack frame
        throw "not defined";
    }
    setFrameLocation(location) {
        this.frameLocation = location;
    }
    getFrameLocation() {
        if (!this.frameLocation) {
            throw "location not defined";
        }
        return this.frameLocation;
    }
    setNextRa(ra) {
        this.nextRa = ra;
    }
    getEntryPoint() {
        throw "not defined";
    }
}

class Sequence extends Gadget {
    constructor(seq){ //array of gadgets
        super();
        for(let i = 0; i < seq.length; i++) {
            // Account for the variables the previous gadget placed on the stack as only Ret increments stack pointer
            if (seq[i] instanceof Ret) {
                if (i > 0 && !((seq[i-1] instanceof Ret) || (seq[i-1] instanceof Sequence))) {
                    seq[i] = new Ret(seq[i-1]);
                }
            }
        }
        this.seq = seq;
    }
    getSize() { //sum of gadget sizes
        return this.seq
            .map(gadget => gadget.getSize())
            .reduce((p, n) => p+n, 0);
    }
    synthesize() {
        let result = [];
        for (let i = 0; i < this.seq.length; i++) {
            let gadget = this.seq[i];
            if(i !== this.seq.length - 1){
                gadget.setNextRa(this.seq[i+1].getEntryPoint());
            }else{
                gadget.setNextRa(this.nextRa);
            }
            result = result.concat(gadget.synthesize());
        }
        return result;
    }
    setFrameLocation(location) {
        super.setFrameLocation(location);
        let nextLocation = location;
        for(let gadget of this.seq){
            gadget.setFrameLocation(nextLocation);
            nextLocation += gadget.getSize();
        }
    }
    getEntryPoint(){
        return this.seq[0].getEntryPoint();
    }
}

class Ret extends Gadget{
    constructor(prevGadget) {
        super()
        if (prevGadget == null) {
            this.prevGadgetStackSize = 0
        } else if (prevGadget instanceof Sequence) {
            this.prevGadgetStackSize = prevGadget.seq[prevGadget.seq.length - 1].synthesize().length
        } else {
            this.prevGadgetStackSize = prevGadget.synthesize().length
        }
    }
    getSize(){
        return 0x70;
    }
    // ra is loaded from 0x68(sp)
    synthesize() {
        let stackVars = [];
        for (let i = this.prevGadgetStackSize; i < 13; i++) {
            stackVars.push(0);
        }
        stackVars.push(this.nextRa);
        return stackVars;
                // 0  8  10 18 20 28 30 38 40 48 50 58 60 68
        // return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, this.nextRa];
    }
    getEntryPoint(){
        return 0x0000000000000b32n + BASE;
    }
}

class PopA0 extends Gadget {
    constructor(a0) {
        super();
        this.a0 = a0;
    }
    getSize() {
        return 0;
    }
    synthesize() {
        return [
            // Load a0 from 0x8(sp)
            // Load a6 from 0x18(sp)
            0n, this.a0, 0n, this.nextRa
        ];
    }
    getEntryPoint() {
        return 0x0000000000000a3an + BASE;
    }
    getPoppedA0Location(){
        return this.getFrameLocation() + 8;
    }
}

class PopS0 extends Gadget {
    constructor(s0) {
        super();

        this.s0 = s0;
    }
    getSize() {
        return 0;
    }
    synthesize() {
        // Load s0 from 0(sp)
        // Load a6 from 8(sp)
        return [this.s0, this.nextRa];
    }
    getEntryPoint() {
        return 0x0000000000000a40n + BASE;
    }
    getPoppedS0Location() {
        return this.getFrameLocation();
    }
}

class Add1A0 extends Gadget {
    //SIDE EFFECT: also pops s0
    constructor(s0) {
        super();
        this.s0 = s0;
    }
    getSize(){
        return 0;
    }
    synthesize() {
        // Load s0 from 0(sp)
        // Load a6 from 8(sp)
        return [
            this.s0,
            this.nextRa
        ]
    }
    getEntryPoint(){
        return 0x0000000000000a46n + BASE;
    }
}

class Dec2A0 extends Gadget {
    getSize(){
        return 0;
    }
    // Load a6 from 8(sp)
    synthesize() {
        return [ 0, this.nextRa ];
    }
    getEntryPoint(){
        return 0x0000000000000a4en + BASE;
    }
}

class _LdA5_S0 extends Gadget {
    /*
    0x00000000000a4ac8 : 
        c.ldsp a4, 0x48(sp)
        c.ld a5, 0(s0)
        bne a4, a5, 0x10
        c.ldsp a6, 0x58(sp)
        c.ldsp s0, 0x50(sp)
        c.jalr a6
    */
    constructor(a4, s0){
        //warning: popped a4 must equal [prev_s0]
        super();
        this.a4 = a4;
        this.s0 = s0;
    }
    getSize() {
        return 0;
    }
    synthesize() {
             // 0  8  10 18 20 28 30 38 40 48       50       58
        return [0, 0, 0, 0, 0, 0, 0, 0, 0, this.a4, this.s0, this.nextRa ];
    }
    getEntryPoint() {
        return 0x0000000000000a54n + BASE;
    }
}

class PrepareLdA0_A0 extends Sequence {
    constructor() {
        super([
            new PopS0(0x30000000), //scratch space
            new Ret(),
            new _LdA5_S0(0, 0x30000000),
            new Ret(),
        ])
    }
}

class _LdA0_8A0 extends Gadget {
    /*
    0x00000000000d3230 : 
        c.ld a0, 8(a0)
        c.add a0, a5
        c.ldsp a4, 0x28(sp)
        c.ld a5, 0(s0)
        bne a4, a5, 0x1e
        c.ldsp a6, 0x38(sp)
        c.ldsp s0, 0x30(sp)
        c.jalr a6
    */
    constructor(a4, s0){
        super();
        this.a4 = a4;
        this.s0 = s0;
    }
    getSize() {
        return 0;
    }
    synthesize() {
             // 0  8  10 18 20 28       30       38
        return [0, 0, 0, 0, 0, this.a4, this.s0, this.nextRa ]
    }
    getEntryPoint() {
        return 0x0000000000000a66n + BASE;
    }
}

class LdA0_8A0 extends Sequence {
    //reads the value of 8(a0) into a0
    //SIDE EFFECTS: will cobble a4, a5, and s0
    constructor() {
        super([
            new PrepareLdA0_A0(), 
            new Ret(),
            new _LdA0_8A0(0, 0x30000000),
            new Ret()
        ])
    }
}

class SdA0_0x10S0 extends Gadget {
    /*
    0x00000000000d30de : 
        c.ldsp a6, 8(sp)
        c.sd a0, 0x10(s0)
        c.ldsp s0, 0(sp)
        c.jalr a6
    */
   constructor(nextS0){
       super();
       this.nextS0 = nextS0;
   }
   getSize(){
       return 0;
   }
   synthesize() {
       return [this.nextS0, this.nextRa];
   }
   getEntryPoint() {
       return 0x0000000000000a7cn + BASE;
   }
}

class WriteA0 extends Sequence {
    constructor(dest, nextS0) {
        super([
            new PopS0(dest-0x10),
            new Ret(),
            new SdA0_0x10S0(nextS0),
            new Ret(),
        ])
    }
}

class Spacer extends Gadget {
    constructor(size){
        super();
        this.size = size;
    }
    getSize() {
        return this.size * 8;
    }
    synthesize(){
        return new Array(this.size).fill(0);
    }
    getEntryPoint(){
        return 0;
    }
}

class _PopA5 extends Gadget {
    //SIDE EFFECT: cobbles a0
    /*
    0x000000000002d9d6 : 
        c.ldsp a5, 8(sp)
        c.ldsp a6, 0x18(sp)
        c.mv a0, a5
        c.jalr a6
    */
   constructor(a5) {
       super();
       this.a5 = a5;
   }
   getSize(){
       return 0;
   }
   synthesize() {
       return [0, this.a5, 0, this.nextRa]
   }
   getEntryPoint() {
       return 0x0000000000000a84n + BASE;
   }
}


class _CallA5 extends Gadget {
    //PRECONDITION: s0+50 is valid scratch space
    //SIDE EFFECT: pops s0, a0 is set to the retval
    /*
    0x00000000000b95d4 : 
        c.jalr a5
        c.ldsp a6, 8(sp)
        sd zero, 0x50(s0)
        c.ldsp s0, 0(sp)
        c.jalr a6
    */
    constructor(s0) {
        super();
        this.s0 = s0;
    }
    getSize(){
        return 0;
    }
    synthesize() {
        return [this.s0, this.nextRa];
    }
    getEntryPoint(){
        return 0x0000000000000a8cn + BASE;
    }
}

class _Longjmp extends Gadget {
    getSize() {
        return 0;
    }
    synthesize() {
        return [];
    }
    getEntryPoint() {
        // return 0x0000002000058494n;
        return 0x0000000000000a98n + BASE;
    }
}

class StackPivot extends Sequence {
    constructor(destRa, destSp) {
        super([
            // TODO
            new PopA0(null),
            new Ret(),
            new _Longjmp(),
        ])
        if(destRa && destSp){
            this.setDest(destRa, destSp);
        }
    }
    setDest(ra, sp) {
        // TODO: longjmp needs to jump to ret then popa0 instead of popa0 directly
        this.seq[0] = new PopA0(jmpBuf.makeTarget(ra, sp))
    }
}

class SeqzA0 extends Gadget {
    getSize() {
        return 0;
    }
    synthesize() {
        return [0, this.nextRa];
    }
    getEntryPoint(){
        return 0x0000000000000b00n + BASE;
    }
}

class PopS0S1S2 extends Gadget {
    constructor(s0, s1, s2){
        super();
        this.s0 = s0;
        this.s1 = s1;
        this.s2 = s2;
    }
    getSize() {
        return 0;
    }
    synthesize() {
        return [
            this.s2, this.s1, this.s0, this.nextRa
        ]
    }
    getEntryPoint() {
        return 0x0000000000000b08n + BASE;
    }
}

class _AddA5A0 extends Gadget {
    constructor(s0, s1, s2, s3){
        super();
        this.s0 = s0;
        this.s1 = s1;
        this.s2 = s2;
        this.s3 = s3;
    }
    getSize(){
        return 0;
    }
    synthesize() {
        return [0, this.s3, this.s2, this.s1, this.s0, this.nextRa];
    }
    getEntryPoint(){
        return 0x0000000000000b12n + BASE;
    }
}

class _AddA0A5 extends Gadget {
    getSize(){
        return 0;
    }
    synthesize() {
        return [0, 0, 0, 0, 0, 0, 0, 0, 0, this.nextRa];
    }
    getEntryPoint(){
        return 0x0000000000000b24n + BASE;
    }
}

//based on the truthiness of a0
class ConditionalStackPivot extends Sequence {
    //cobbles a0
    constructor(){
        super([
            // TODO
            new WriteA0(null, 0), //make a copy of a0 before the next gadget cobbles it
            new Ret(),
            new _PopA5(0), //want a5 = 8*Seqz(A0), cobbles a0
            new Ret(),
            new PopA0(0), //restored value from before
            new Ret(),
            new SeqzA0(),
            new Ret(),
            new PopS0S1S2(0, 0, 0x30000000),
            new Ret(),
            new _AddA5A0(0, 0, 0x30000000, 0), //add a5 to a0 8 times
            new Ret(),
            new _AddA5A0(0, 0, 0x30000000, 0),
            new Ret(),
            new _AddA5A0(0, 0, 0x30000000, 0),
            new Ret(),
            new _AddA5A0(0, 0, 0x30000000, 0),
            new Ret(),
            new _AddA5A0(0, 0, 0x30000000, 0),
            new Ret(),
            new _AddA5A0(0, 0, 0x30000000, 0),
            new Ret(),
            new _AddA5A0(0, 0, 0x30000000, 0),
            new Ret(),
            new _AddA5A0(0, 0, 0x30000000, 0),
            new Ret(),
            new PopA0(null), //the jump buffer
            new Ret(),
            new _AddA0A5(),
            new Ret(),
            new _Longjmp(),
        ])
    }
    setFrameLocation(location){
        super.setFrameLocation(location);
        
        // TODO: longjmp needs to jump to ret then popa0 instead of popa0 directly
        this.seq[0] = new WriteA0(this.seq[4].getPoppedA0Location(), 0);

        super.setFrameLocation(location);
    }
    setDests(trueRa, trueSp, falseRa, falseSp){
        if(jmpBuf.nextSpot % 26 === 25) { //we cannot allocate two more jump buffers or else they will be split
            jmpBuf.makeTarget(0, 0); //allocate a dummy so we move on to the next set
        }
        const trueJmp = jmpBuf.makeTarget(trueRa, trueSp);
        const falseJmp = jmpBuf.makeTarget(falseRa, falseSp);
        if(falseJmp !== trueJmp + 8) {
            throw "jmpbuf didn't allocate contiguously";
        }
        
        if(!this.seq[26].getPoppedA0Location){
            throw "expected pop a0 gadget";
        }
        this.seq[26] = new PopA0(trueJmp);
    }
}

class WriteVal extends Sequence {
    //preserves A0
    constructor(val, dest) {
        super([
            // TODO
            new WriteA0(null, 0),
            new Ret(),
            new PopA0(val),
            new Ret(),
            new WriteA0(dest, 0),
            new Ret(),
            new PopA0(0),
            new Ret(),
        ])
    }
    setFrameLocation(location) {
        super.setFrameLocation(location);

        this.seq[0] = new WriteA0(this.seq[6].getPoppedA0Location(), 0);

        super.setFrameLocation(location);
    }
}

class WriteVals extends Sequence {
    constructor(vals, dest) {
        super(vals.map((val, i) => new WriteVal(val, dest + 8*i)));
    }
}

class CallFunc extends Sequence {
    //may cobble all coller-saved regs
    //retval stored in a0
    constructor(func) {
        super([
            new WriteVals([0, 0, 0, 0, 0, 0], 0),
            new Ret(),
            new WriteA0(null, 0),
            new Ret(),
            new _PopA5(func), //putchar
            new Ret(),
            new StackPivot(null, null),
            new Ret(),
            new Spacer(512),
            new Ret(),
            new PopA0(0), //this will get overwritten
            new Ret(),
            new PopS0(0x30000000), //this too
            new Ret(),
            new _CallA5(0),
            new Ret(),
        ]);
    }

    setFrameLocation(location) {
        super.setFrameLocation(location);
        
        this.seq[0] = new WriteVals([0, 0, 0, this.seq[12].getEntryPoint(), 0x30000000, this.seq[14].getEntryPoint()], this.seq[10].getFrameLocation());
        this.seq[2] = new WriteA0(this.seq[10].getPoppedA0Location(), 0);
        this.seq[6] = new StackPivot(this.seq[10].getEntryPoint(), this.seq[10].getFrameLocation()); //TODO UPDATE

        super.setFrameLocation(location);
    }
}

class OutputCharAtA0 extends Sequence {
    constructor() {
        super([
            new WriteA0(null, 0),
            new Ret(),
            new Sub8FromA0(),
            new Ret(),
            new LdA0_8A0(),
            new Ret(),
            new CallFunc(0x0000002000080bccn), //putchar
            new Ret(),
            // new CallFunc(0x000000000005b70an + BASE), //putchar
            new PopA0(0),
            new Ret(),
        ])
    }
    setFrameLocation(location){
        super.setFrameLocation(location);

        this.seq[0] = new WriteA0(this.seq[8].getPoppedA0Location(), 0);

        super.setFrameLocation(location);
    }
}

class InputCharAtA0 extends Sequence {
    constructor() {
        super([
            new WriteA0(null, 0), //write to the pop A0
            new Ret(),
            new Sub8FromA0(),
            new Ret(),
            new Sub8FromA0(),
            new Ret(),
            new WriteA0(null, 0), //write to the pop S0
            new Ret(),
            new CallFunc(0x0000002000083f76n), //getchar
            new Ret(),
            // new CallFunc(0x000000000005eaa6n + BASE), //getchar
            new PopS0(0),
            new Ret(),
            new SdA0_0x10S0(0),
            new Ret(),
            new PopA0(0),
            new Ret(),
        ])
    }
    setFrameLocation(location){
        super.setFrameLocation(location);

        this.seq[0] = new WriteA0(this.seq[14].getPoppedA0Location(), 0);
        this.seq[6] = new WriteA0(this.seq[10].getPoppedS0Location(), 0);

        super.setFrameLocation(location);
    }
}

class BeginLoop extends Sequence {
    constructor() {
        super([
            new WriteA0(null, 0), //should write to the below gadget
            new Ret(),
            new PopA0(0), //this is where EndLoop will jump back
            new Ret(),
            new WriteA0(null, 0), //write to our conditional branch target
            new Ret(),
            new WriteA0(null, 0), //write to their conditional branch target
            new Ret(),
            new Sub8FromA0(),
            new Ret(),
            new LdA0_8A0(), //read the value into a0
            new Ret(),
            new ConditionalStackPivot(),
            new Ret(),
            new PopA0(0),
            new Ret(),
        ])
    }
    setFrameLocation(location){
        super.setFrameLocation(location);

        this.seq[0] = new WriteA0(this.seq[2].getPoppedA0Location(), 0);
        this.seq[4] = new WriteA0(this.seq[14].getPoppedA0Location(), 0);

        super.setFrameLocation(location);
    }
    setEnd(endLoop){ //called after setFrameLocation
        const endPop = endLoop.seq[4];
        const beginPop = this.seq[14];
        this.seq[6] = new WriteA0(endPop.getPoppedA0Location(), 0);

        this.seq[12].setDests(beginPop.getEntryPoint(), beginPop.getFrameLocation(), endPop.getEntryPoint(), endPop.getFrameLocation());
    }
}

class EndLoop extends Sequence {
    constructor() {
        super([
            new WriteA0(null, 0), 
            new Ret(),
            new StackPivot(null, null),
            new Ret(),
            new PopA0(0),
            new Ret(),
        ])
    }
    setBeginning(beginLoop) { //should be called after setFrameLocation
        const popA0 = beginLoop.seq[2]
        this.seq[0] = new WriteA0(popA0.getPoppedA0Location(), 0);
        this.seq[2] = new StackPivot(popA0.getEntryPoint(), popA0.getFrameLocation());
    }
}

class Add8ToA0 extends Sequence {
    //SIDE EFFECT: sets s0 to 0
    constructor() {
        super([
            new Add1A0(0),
            new Ret(),
            new Add1A0(0),
            new Ret(),
            new Add1A0(0),
            new Ret(),
            new Add1A0(0),
            new Ret(),
            new Add1A0(0),
            new Ret(),
            new Add1A0(0),
            new Ret(),
            new Add1A0(0),
            new Ret(),
            new Add1A0(0), //s0 = 0
            new Ret(),
        ])
    }
}

class Sub8FromA0 extends Sequence {
    constructor() {
        super([
            new Dec2A0(),
            new Ret(),
            new Dec2A0(),
            new Ret(),
            new Dec2A0(),
            new Ret(),
            new Dec2A0(),
            new Ret(),
        ])
    }
}

class IncrementAtA0 extends Sequence {
    constructor() {
        super([
            new WriteA0(null, 0),
            new Ret(),
            new Sub8FromA0(),
            new Ret(),
            new Sub8FromA0(),
            new Ret(),
            new WriteA0(null, 0),
            new Ret(),
            new Add8ToA0(),
            new Ret(),
            new LdA0_8A0(),
            new Ret(),
            new Add1A0(0), 
            new Ret(),
            new PopS0(0),
            new Ret(),
            new SdA0_0x10S0(0),
            new Ret(),
            new PopA0(0),
            new Ret(),
        ])
    }
    setFrameLocation(location){
        super.setFrameLocation(location);
        
        //fill in the self-modifying ROP chain destinations
        this.seq[0] = new WriteA0(this.seq[18].getPoppedA0Location(), 0);
        this.seq[6] = new WriteA0(this.seq[14].getPoppedS0Location(), 0);

        super.setFrameLocation(location);
    }
}

class DecrementAtA0 extends Sequence {
    constructor() {
        super([
            new WriteA0(null, 0),
            new Ret(),
            new Sub8FromA0(),
            new Ret(),
            new Sub8FromA0(),
            new Ret(),
            new WriteA0(null, 0),
            new Ret(),
            new Add8ToA0(),
            new Ret(),
            new LdA0_8A0(),
            new Ret(),
            new Add1A0(0), 
            new Ret(),
            new Dec2A0(), 
            new Ret(),
            new PopS0(0),
            new Ret(),
            new SdA0_0x10S0(0),
            new Ret(),
            new PopA0(0),
            new Ret(),
        ])
    }
    setFrameLocation(location){
        super.setFrameLocation(location);
        
        //fill in the self-modifying ROP chain destinations
        this.seq[0] = new WriteA0(this.seq[20].getPoppedA0Location(), 0);
        this.seq[6] = new WriteA0(this.seq[16].getPoppedS0Location(), 0);

        super.setFrameLocation(location);
    }
}

bfInstructions['>'] = Add8ToA0;
bfInstructions['<'] = Sub8FromA0;
bfInstructions['+'] = IncrementAtA0;
bfInstructions['-'] = DecrementAtA0;
bfInstructions['.'] = OutputCharAtA0;
bfInstructions[','] = InputCharAtA0;
bfInstructions['['] = BeginLoop;
bfInstructions[']'] = EndLoop;

function createProgram(gadgets) {
    const result = new Sequence([new Ret(), ...gadgets]);

    result.setNextRa(new Ret().getEntryPoint());
    result.setFrameLocation(0x10000000);

    return result;
}

//beginningIndex -- index of a [
//return value -- index of the corresponding ]
function getLoopEnd(bf, beginningIndex) {
    if(bf.charAt(beginningIndex) !== '['){
        throw "beginningIndex is not a beginning";
    }
    let levels = 0;
    for(let i = beginningIndex; i < bf.length; i++){
        if(bf.charAt(i) === '['){
            levels++;
        }else if(bf.charAt(i) === ']'){
            levels--;
        }
        if(levels === 0) return i;
    }
    
    throw "no end found";
}

function sanitizeBrainfuck(bf) {
    return bf.split('').filter(ch => bfInstructions[ch]).join('');
}

function brainfuckToRop(bf) {
    let initSeq = [new Ret(), new PopA0(0x38000000), new Ret()];
    let endSeq = [new PopA0(0), new Ret(), new CallFunc(0x000000200005a220n)] //exit(0)
    // let endSeq = [new PopA0(0), new CallFunc(0x00000000000342e4n + BASE)] //exit(0)

    let seq = initSeq.concat(
        bf.split('')
            .map(instr => 
                bfInstructions[instr]
                    ? new bfInstructions[instr]()
                    : new Ret())
    ).concat(endSeq);

    const result = new Sequence(seq);
    console.log('synthesized seq[0]: ', result.seq[0].synthesize().length, result.seq[0].prevGadgetStackSize)
    console.log('synthesized seq[2]: ', result.seq[2].synthesize().length, result.seq[2].prevGadgetStackSize)
    
    result.setNextRa(new Ret().getEntryPoint());
    result.setFrameLocation(0x10000000);

    //initialize the loops
    for(let i = 0; i < bf.length; i++){
        if(bf.charAt(i) == '['){
            const beginIndex = i;
            const endIndex = getLoopEnd(bf, i);
            const beginLoop = result.seq[initSeq.length + beginIndex];
            const endLoop = result.seq[initSeq.length + endIndex];
            beginLoop.setEnd(endLoop);
            endLoop.setBeginning(beginLoop);
        }
    }

    return result;
}

function showRopChain(gadget){
    document.getElementById('stackbuf').innerHTML = (gadget.synthesize().map(num => num.toString(16)).join("\n"));
    document.getElementById('jmpbuf').innerHTML = (jmpBuf.synthesize().map(num => num.toString(16)).join("\n"));
}

function generateCode() {
    showRopChain(brainfuckToRop(sanitizeBrainfuck(document.getElementById("source").value)));

    return false;
}
