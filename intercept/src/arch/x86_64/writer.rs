#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl Reg {
    /// Low 3 bits of the register encoding.
    #[inline]
    fn lo3(self) -> u8 {
        (self as u8) & 7
    }

    /// Whether this register requires the REX.B or REX.R extension bit.
    #[inline]
    fn is_extended(self) -> bool {
        (self as u8) >= 8
    }
}

#[derive(Debug)]
pub struct X86_64Writer {
    base: *mut u8,
    code: *mut u8,
    pc: u64,
    size: usize,
}

impl X86_64Writer {
    pub unsafe fn new(buffer: *mut u8, size: usize, pc: u64) -> Self {
        Self {
            base: buffer,
            code: buffer,
            pc,
            size,
        }
    }

    pub fn pc(&self) -> u64 {
        self.pc
    }

    pub fn offset(&self) -> usize {
        (self.code as usize).saturating_sub(self.base as usize)
    }

    pub fn code_ptr(&self) -> *mut u8 {
        self.code
    }

    fn can_write(&self, bytes: usize) -> bool {
        self.offset() + bytes <= self.size
    }

    unsafe fn emit(&mut self, byte: u8) {
        debug_assert!(self.can_write(1));
        self.code.write(byte);
        self.code = self.code.add(1);
        self.pc = self.pc.wrapping_add(1);
    }

    unsafe fn emit_u32_le(&mut self, val: u32) {
        debug_assert!(self.can_write(4));
        (self.code as *mut u32).write_unaligned(val);
        self.code = self.code.add(4);
        self.pc = self.pc.wrapping_add(4);
    }

    unsafe fn emit_u64_le(&mut self, val: u64) {
        debug_assert!(self.can_write(8));
        (self.code as *mut u64).write_unaligned(val);
        self.code = self.code.add(8);
        self.pc = self.pc.wrapping_add(8);
    }

    /// REX prefix: 0100 W R X B
    #[inline]
    fn rex(w: bool, r: bool, x: bool, b: bool) -> u8 {
        0x40 | ((w as u8) << 3) | ((r as u8) << 2) | ((x as u8) << 1) | (b as u8)
    }

    /// ModRM byte: mod(2) | reg(3) | rm(3)
    #[inline]
    fn modrm(mod_: u8, reg: u8, rm: u8) -> u8 {
        ((mod_ & 3) << 6) | ((reg & 7) << 3) | (rm & 7)
    }

    // ── Push / Pop ───────────────────────────────────────────────────

    /// `push reg` — [REX.B?] 50+rd
    pub unsafe fn put_push_reg(&mut self, reg: Reg) {
        if reg.is_extended() {
            self.emit(Self::rex(false, false, false, true));
        }
        self.emit(0x50 + reg.lo3());
    }

    /// `pop reg` — [REX.B?] 58+rd
    pub unsafe fn put_pop_reg(&mut self, reg: Reg) {
        if reg.is_extended() {
            self.emit(Self::rex(false, false, false, true));
        }
        self.emit(0x58 + reg.lo3());
    }

    // ── MOV ──────────────────────────────────────────────────────────

    /// `mov reg, imm64` — REX.W B8+rd io (10 bytes)
    pub unsafe fn put_mov_reg_imm64(&mut self, reg: Reg, imm: u64) {
        self.emit(Self::rex(true, false, false, reg.is_extended()));
        self.emit(0xB8 + reg.lo3());
        self.emit_u64_le(imm);
    }

    /// `mov dst, src` (64-bit) — REX.W 89 ModRM (mod=11)
    pub unsafe fn put_mov_reg_reg(&mut self, dst: Reg, src: Reg) {
        self.emit(Self::rex(true, src.is_extended(), false, dst.is_extended()));
        self.emit(0x89);
        self.emit(Self::modrm(0b11, src.lo3(), dst.lo3()));
    }

    /// Emit the ModRM + optional SIB + disp32 for `[base + disp32]`.
    ///
    /// Uses mod=10 (disp32) always to avoid ambiguity with RIP-relative (mod=0,rm=5).
    /// When base is RSP(4) or R12(12), a SIB byte 0x24 is required.
    unsafe fn emit_modrm_base_disp32(&mut self, reg_field: u8, base: Reg, offset: i32) {
        let base_lo = base.lo3();
        if base_lo == 4 {
            // RSP/R12 require SIB byte
            self.emit(Self::modrm(0b10, reg_field, 0b100)); // rm=100 means SIB follows
            self.emit(0x24); // SIB: scale=0, index=100(none), base=100(RSP/R12)
        } else {
            self.emit(Self::modrm(0b10, reg_field, base_lo)); // mod=10 disp32
        }
        self.emit_u32_le(offset as u32);
    }

    /// `mov dst, [base + offset]` (64-bit load)
    pub unsafe fn put_mov_reg_mem(&mut self, dst: Reg, base: Reg, offset: i32) {
        self.emit(Self::rex(true, dst.is_extended(), false, base.is_extended()));
        self.emit(0x8B);
        self.emit_modrm_base_disp32(dst.lo3(), base, offset);
    }

    /// `mov [base + offset], src` (64-bit store)
    pub unsafe fn put_mov_mem_reg(&mut self, base: Reg, offset: i32, src: Reg) {
        self.emit(Self::rex(true, src.is_extended(), false, base.is_extended()));
        self.emit(0x89);
        self.emit_modrm_base_disp32(src.lo3(), base, offset);
    }

    // ── LEA ──────────────────────────────────────────────────────────

    /// `lea dst, [base + offset]` (64-bit)
    pub unsafe fn put_lea_reg_mem(&mut self, dst: Reg, base: Reg, offset: i32) {
        self.emit(Self::rex(true, dst.is_extended(), false, base.is_extended()));
        self.emit(0x8D);
        self.emit_modrm_base_disp32(dst.lo3(), base, offset);
    }

    // ── Arithmetic ───────────────────────────────────────────────────

    /// `sub reg, imm32` — REX.W 81 /5 id
    pub unsafe fn put_sub_reg_imm32(&mut self, reg: Reg, imm: u32) {
        self.emit(Self::rex(true, false, false, reg.is_extended()));
        self.emit(0x81);
        self.emit(Self::modrm(0b11, 5, reg.lo3()));
        self.emit_u32_le(imm);
    }

    /// `add reg, imm32` — REX.W 81 /0 id
    pub unsafe fn put_add_reg_imm32(&mut self, reg: Reg, imm: u32) {
        self.emit(Self::rex(true, false, false, reg.is_extended()));
        self.emit(0x81);
        self.emit(Self::modrm(0b11, 0, reg.lo3()));
        self.emit_u32_le(imm);
    }

    /// `and reg, imm32` — REX.W 81 /4 id
    pub unsafe fn put_and_reg_imm32(&mut self, reg: Reg, imm: u32) {
        self.emit(Self::rex(true, false, false, reg.is_extended()));
        self.emit(0x81);
        self.emit(Self::modrm(0b11, 4, reg.lo3()));
        self.emit_u32_le(imm);
    }

    /// `test r1, r2` — REX.W 85 ModRM (mod=11)
    pub unsafe fn put_test_reg_reg(&mut self, r1: Reg, r2: Reg) {
        self.emit(Self::rex(true, r2.is_extended(), false, r1.is_extended()));
        self.emit(0x85);
        self.emit(Self::modrm(0b11, r2.lo3(), r1.lo3()));
    }

    // ── Branches / Calls ─────────────────────────────────────────────

    /// `jmp rel32` — E9 cd (5 bytes). `target` is an absolute address.
    pub unsafe fn put_jmp_near(&mut self, target: u64) {
        self.emit(0xE9);
        let rel = (target as i64) - (self.pc as i64 + 4);
        self.emit_u32_le(rel as u32);
    }

    /// Far absolute jump via `jmp [rip+2]; ud2; .quad addr` (16 bytes).
    ///
    /// Encoding: FF 25 02 00 00 00  0F 0B  <8-byte address>
    pub unsafe fn put_jmp_far(&mut self, target: u64) {
        // FF /4 = JMP r/m64; ModRM = mod=00, reg=4, rm=5 (RIP+disp32)
        self.emit(0xFF);
        self.emit(0x25);
        self.emit_u32_le(0x02); // disp32 = 2 (skip over UD2)
        self.emit(0x0F);
        self.emit(0x0B); // UD2 (trap if somehow fallen through)
        self.emit_u64_le(target);
    }

    /// Auto-select near (5B) vs far (16B) jump to absolute address.
    pub unsafe fn put_jmp_address(&mut self, target: u64) {
        // Near JMP: 5 bytes total. Check if rel32 fits.
        let rel = (target as i64) - (self.pc as i64 + 5);
        if rel >= i32::MIN as i64 && rel <= i32::MAX as i64 {
            self.put_jmp_near(target);
        } else {
            self.put_jmp_far(target);
        }
    }

    /// `call rel32` — E8 cd (5 bytes). `target` is an absolute address.
    pub unsafe fn put_call_near(&mut self, target: u64) {
        self.emit(0xE8);
        let rel = (target as i64) - (self.pc as i64 + 4);
        self.emit_u32_le(rel as u32);
    }

    /// `call reg` — [REX.B?] FF /2
    pub unsafe fn put_call_reg(&mut self, reg: Reg) {
        if reg.is_extended() {
            self.emit(Self::rex(false, false, false, true));
        }
        self.emit(0xFF);
        self.emit(Self::modrm(0b11, 2, reg.lo3()));
    }

    /// `jnz rel32` — 0F 85 cd (6 bytes). `target` is an absolute address.
    pub unsafe fn put_jnz_rel32(&mut self, target: u64) {
        self.emit(0x0F);
        self.emit(0x85);
        let rel = (target as i64) - (self.pc as i64 + 4);
        self.emit_u32_le(rel as u32);
    }

    // ── Misc ─────────────────────────────────────────────────────────

    /// `ret` — C3
    pub unsafe fn put_ret(&mut self) {
        self.emit(0xC3);
    }

    /// `pushfq` — 9C
    pub unsafe fn put_pushfq(&mut self) {
        self.emit(0x9C);
    }

    /// `popfq` — 9D
    pub unsafe fn put_popfq(&mut self) {
        self.emit(0x9D);
    }

    /// `cld` — FC
    pub unsafe fn put_cld(&mut self) {
        self.emit(0xFC);
    }

    /// `fxsave [reg]` — [REX.B?] 0F AE /0
    ///
    /// The target address must be 16-byte aligned.
    pub unsafe fn put_fxsave_reg_indirect(&mut self, reg: Reg) {
        if reg.is_extended() {
            self.emit(Self::rex(false, false, false, true));
        }
        self.emit(0x0F);
        self.emit(0xAE);
        if reg.lo3() == 4 {
            // RSP/R12 require SIB byte
            self.emit(Self::modrm(0b00, 0, 0b100));
            self.emit(0x24);
        } else if reg.lo3() == 5 {
            // RBP/R13 in mod=00 means [rip+disp32], use mod=01 disp8=0
            self.emit(Self::modrm(0b01, 0, reg.lo3()));
            self.emit(0x00);
        } else {
            self.emit(Self::modrm(0b00, 0, reg.lo3()));
        }
    }

    /// `fxrstor [reg]` — [REX.B?] 0F AE /1
    ///
    /// The source address must be 16-byte aligned.
    pub unsafe fn put_fxrstor_reg_indirect(&mut self, reg: Reg) {
        if reg.is_extended() {
            self.emit(Self::rex(false, false, false, true));
        }
        self.emit(0x0F);
        self.emit(0xAE);
        if reg.lo3() == 4 {
            // RSP/R12 require SIB byte
            self.emit(Self::modrm(0b00, 1, 0b100));
            self.emit(0x24);
        } else if reg.lo3() == 5 {
            // RBP/R13 in mod=00 means [rip+disp32], use mod=01 disp8=0
            self.emit(Self::modrm(0b01, 1, reg.lo3()));
            self.emit(0x00);
        } else {
            self.emit(Self::modrm(0b00, 1, reg.lo3()));
        }
    }

    /// `nop` — 90
    pub unsafe fn put_nop(&mut self) {
        self.emit(0x90);
    }

    /// Multi-byte NOP padding using recommended NOP forms.
    pub unsafe fn put_nop_n(&mut self, n: usize) {
        // Intel recommended multi-byte NOP forms.
        let mut remaining = n;
        while remaining > 0 {
            match remaining {
                1 => { self.emit(0x90); remaining -= 1; }
                2 => { self.emit(0x66); self.emit(0x90); remaining -= 2; }
                3 => { self.emit(0x0F); self.emit(0x1F); self.emit(0x00); remaining -= 3; }
                4 => { self.emit(0x0F); self.emit(0x1F); self.emit(0x40); self.emit(0x00); remaining -= 4; }
                5 => { self.emit(0x0F); self.emit(0x1F); self.emit(0x44); self.emit(0x00); self.emit(0x00); remaining -= 5; }
                6 => { self.emit(0x66); self.emit(0x0F); self.emit(0x1F); self.emit(0x44); self.emit(0x00); self.emit(0x00); remaining -= 6; }
                7 => { self.emit(0x0F); self.emit(0x1F); self.emit(0x80); self.emit(0x00); self.emit(0x00); self.emit(0x00); self.emit(0x00); remaining -= 7; }
                8 => { self.emit(0x0F); self.emit(0x1F); self.emit(0x84); self.emit(0x00); self.emit(0x00); self.emit(0x00); self.emit(0x00); self.emit(0x00); remaining -= 8; }
                _ => {
                    // 9-byte NOP: 66 0F 1F 84 00 00 00 00 00
                    self.emit(0x66); self.emit(0x0F); self.emit(0x1F); self.emit(0x84);
                    self.emit(0x00); self.emit(0x00); self.emit(0x00); self.emit(0x00); self.emit(0x00);
                    remaining -= 9;
                }
            }
        }
    }

    /// Emit raw bytes.
    pub unsafe fn put_bytes(&mut self, bytes: &[u8]) {
        debug_assert!(self.can_write(bytes.len()));
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.code, bytes.len());
        self.code = self.code.add(bytes.len());
        self.pc = self.pc.wrapping_add(bytes.len() as u64);
    }

    /// `push qword [base + offset]` — FF /6 with mod/rm
    pub unsafe fn put_push_mem(&mut self, base: Reg, offset: i32) {
        if base.is_extended() {
            self.emit(Self::rex(false, false, false, true));
        }
        self.emit(0xFF);
        self.emit_modrm_base_disp32(6, base, offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(f: impl FnOnce(&mut X86_64Writer)) -> Vec<u8> {
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            f(&mut w);
            buf[..w.offset()].to_vec()
        }
    }

    #[test]
    fn push_pop_rax() {
        assert_eq!(encode(|w| unsafe { w.put_push_reg(Reg::RAX) }), &[0x50]);
        assert_eq!(encode(|w| unsafe { w.put_pop_reg(Reg::RAX) }), &[0x58]);
    }

    #[test]
    fn push_pop_r12() {
        assert_eq!(encode(|w| unsafe { w.put_push_reg(Reg::R12) }), &[0x41, 0x54]);
        assert_eq!(encode(|w| unsafe { w.put_pop_reg(Reg::R12) }), &[0x41, 0x5C]);
    }

    #[test]
    fn mov_reg_imm64() {
        let bytes = encode(|w| unsafe { w.put_mov_reg_imm64(Reg::RAX, 0xDEADBEEFCAFEBABE) });
        // REX.W=48, B8+0=B8, then 8-byte LE
        assert_eq!(bytes.len(), 10);
        assert_eq!(bytes[0], 0x48);
        assert_eq!(bytes[1], 0xB8);
        assert_eq!(u64::from_le_bytes(bytes[2..10].try_into().unwrap()), 0xDEADBEEFCAFEBABE);
    }

    #[test]
    fn mov_r11_imm64() {
        let bytes = encode(|w| unsafe { w.put_mov_reg_imm64(Reg::R11, 0x1234) });
        assert_eq!(bytes.len(), 10);
        // REX.W + REX.B = 0x49, B8+3=BB
        assert_eq!(bytes[0], 0x49);
        assert_eq!(bytes[1], 0xBB);
    }

    #[test]
    fn mov_reg_reg() {
        let bytes = encode(|w| unsafe { w.put_mov_reg_reg(Reg::RAX, Reg::RBX) });
        // REX.W=48 89 D8(mod=11, reg=rbx(3), rm=rax(0))
        assert_eq!(bytes, &[0x48, 0x89, 0xD8]);
    }

    #[test]
    fn mov_mem_reg_rsp_base() {
        // mov [rsp+0x10], rax
        let bytes = encode(|w| unsafe { w.put_mov_mem_reg(Reg::RSP, 0x10, Reg::RAX) });
        // REX.W=48, 89, ModRM(mod=10,reg=rax(0),rm=100(SIB)), SIB=24, disp32=10000000
        assert_eq!(bytes, &[0x48, 0x89, 0x84, 0x24, 0x10, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn lea_reg_mem() {
        // lea rax, [rbp+0x20]
        let bytes = encode(|w| unsafe { w.put_lea_reg_mem(Reg::RAX, Reg::RBP, 0x20) });
        assert_eq!(bytes, &[0x48, 0x8D, 0x85, 0x20, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn sub_add_reg_imm32() {
        let bytes = encode(|w| unsafe { w.put_sub_reg_imm32(Reg::RSP, 0x100) });
        assert_eq!(bytes, &[0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00]);
        let bytes = encode(|w| unsafe { w.put_add_reg_imm32(Reg::RSP, 0x100) });
        assert_eq!(bytes, &[0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_reg_reg() {
        let bytes = encode(|w| unsafe { w.put_test_reg_reg(Reg::RAX, Reg::RAX) });
        assert_eq!(bytes, &[0x48, 0x85, 0xC0]);
    }

    #[test]
    fn jmp_near_forward() {
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_jmp_near(0x1100); // target = 0x1100, from 0x1000, insn=5 bytes, rel = 0x1100 - 0x1005 = 0xFB
        }
        assert_eq!(buf[0], 0xE9);
        assert_eq!(i32::from_le_bytes(buf[1..5].try_into().unwrap()), 0xFB);
    }

    #[test]
    fn jmp_far() {
        let bytes = encode(|w| unsafe { w.put_jmp_far(0xDEADBEEFCAFEBABE) });
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[0..6], &[0xFF, 0x25, 0x02, 0x00, 0x00, 0x00]);
        assert_eq!(&bytes[6..8], &[0x0F, 0x0B]); // UD2
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0xDEADBEEFCAFEBABE);
    }

    #[test]
    fn call_near() {
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_call_near(0x2000); // rel = 0x2000 - 0x1005 = 0xFFB
        }
        assert_eq!(buf[0], 0xE8);
        assert_eq!(i32::from_le_bytes(buf[1..5].try_into().unwrap()), 0xFFB);
    }

    #[test]
    fn call_reg_r11() {
        let bytes = encode(|w| unsafe { w.put_call_reg(Reg::R11) });
        // REX.B=41, FF, ModRM(mod=11, reg=2, rm=3(r11.lo3))
        assert_eq!(bytes, &[0x41, 0xFF, 0xD3]);
    }

    #[test]
    fn jnz_rel32() {
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_jnz_rel32(0x1100); // rel = 0x1100 - 0x1006 = 0xFA
        }
        assert_eq!(buf[0], 0x0F);
        assert_eq!(buf[1], 0x85);
        assert_eq!(i32::from_le_bytes(buf[2..6].try_into().unwrap()), 0xFA);
    }

    #[test]
    fn ret_pushfq_popfq_cld_nop() {
        assert_eq!(encode(|w| unsafe { w.put_ret() }), &[0xC3]);
        assert_eq!(encode(|w| unsafe { w.put_pushfq() }), &[0x9C]);
        assert_eq!(encode(|w| unsafe { w.put_popfq() }), &[0x9D]);
        assert_eq!(encode(|w| unsafe { w.put_cld() }), &[0xFC]);
        assert_eq!(encode(|w| unsafe { w.put_nop() }), &[0x90]);
    }

    #[test]
    fn nop_n_various() {
        let bytes = encode(|w| unsafe { w.put_nop_n(9) });
        assert_eq!(bytes.len(), 9);
        assert_eq!(&bytes[..4], &[0x66, 0x0F, 0x1F, 0x84]);

        let bytes = encode(|w| unsafe { w.put_nop_n(14) });
        assert_eq!(bytes.len(), 14); // 9 + 5
    }

    #[test]
    fn put_bytes_raw() {
        let bytes = encode(|w| unsafe { w.put_bytes(&[0x90, 0xCC, 0xC3]) });
        assert_eq!(bytes, &[0x90, 0xCC, 0xC3]);
    }

    #[test]
    fn mov_reg_mem_and_mov_mem_reg() {
        // mov rax, [rbx+0x8]
        let bytes = encode(|w| unsafe { w.put_mov_reg_mem(Reg::RAX, Reg::RBX, 0x8) });
        assert_eq!(bytes, &[0x48, 0x8B, 0x83, 0x08, 0x00, 0x00, 0x00]);

        // mov [rbx+0x8], rax
        let bytes = encode(|w| unsafe { w.put_mov_mem_reg(Reg::RBX, 0x8, Reg::RAX) });
        assert_eq!(bytes, &[0x48, 0x89, 0x83, 0x08, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn extended_registers() {
        // mov r11, [r12+0x10] — both extended
        let bytes = encode(|w| unsafe { w.put_mov_reg_mem(Reg::R11, Reg::R12, 0x10) });
        // REX = 0x4D (W+R+B), 8B, ModRM(10,011,100=SIB), SIB=24, disp32
        assert_eq!(bytes, &[0x4D, 0x8B, 0x9C, 0x24, 0x10, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn push_mem() {
        // push qword [rsp+0x50]
        let bytes = encode(|w| unsafe { w.put_push_mem(Reg::RSP, 0x50) });
        // FF, ModRM(10,110,100=SIB), SIB=24, disp32
        assert_eq!(bytes, &[0xFF, 0xB4, 0x24, 0x50, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn fxsave_reg_indirect_r11() {
        // fxsave [r11] — REX.B 0F AE /0
        let bytes = encode(|w| unsafe { w.put_fxsave_reg_indirect(Reg::R11) });
        assert_eq!(bytes, &[0x41, 0x0F, 0xAE, 0x03]);
    }

    #[test]
    fn fxrstor_reg_indirect_r11() {
        // fxrstor [r11] — REX.B 0F AE /1
        let bytes = encode(|w| unsafe { w.put_fxrstor_reg_indirect(Reg::R11) });
        assert_eq!(bytes, &[0x41, 0x0F, 0xAE, 0x0B]);
    }

    #[test]
    fn fxsave_reg_indirect_rax() {
        // fxsave [rax] — 0F AE /0 (no REX needed)
        let bytes = encode(|w| unsafe { w.put_fxsave_reg_indirect(Reg::RAX) });
        assert_eq!(bytes, &[0x0F, 0xAE, 0x00]);
    }

    #[test]
    fn fxsave_reg_indirect_rsp() {
        // fxsave [rsp] — 0F AE /0 with SIB byte
        let bytes = encode(|w| unsafe { w.put_fxsave_reg_indirect(Reg::RSP) });
        assert_eq!(bytes, &[0x0F, 0xAE, 0x04, 0x24]);
    }

    #[test]
    fn fxrstor_reg_indirect_rsp() {
        // fxrstor [rsp] — 0F AE /1 with SIB byte
        let bytes = encode(|w| unsafe { w.put_fxrstor_reg_indirect(Reg::RSP) });
        assert_eq!(bytes, &[0x0F, 0xAE, 0x0C, 0x24]);
    }

    /// Helper that encodes with a specific starting PC (unlike `encode` which uses 0x1000).
    fn encode_at(pc: u64, f: impl FnOnce(&mut X86_64Writer)) -> Vec<u8> {
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), pc);
            f(&mut w);
            buf[..w.offset()].to_vec()
        }
    }

    #[test]
    fn and_reg_imm32() {
        // and r11, 0xFFFFFFF0 — REX.W+REX.B=49 81 E3(modrm: mod=11, /4, r11.lo3=3) F0 FF FF FF
        let bytes = encode(|w| unsafe { w.put_and_reg_imm32(Reg::R11, 0xFFFFFFF0) });
        assert_eq!(bytes, &[0x49, 0x81, 0xE3, 0xF0, 0xFF, 0xFF, 0xFF]);

        // and rax, 0x0F — REX.W=48 81 E0(modrm: mod=11, /4, rax.lo3=0) 0F 00 00 00
        let bytes = encode(|w| unsafe { w.put_and_reg_imm32(Reg::RAX, 0x0F) });
        assert_eq!(bytes, &[0x48, 0x81, 0xE0, 0x0F, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn jmp_address_selects_near_or_far() {
        // Near case: PC=0x1000, target=0x2000 → within ±2GB → 5 bytes, starts with E9
        let bytes = encode_at(0x1000, |w| unsafe { w.put_jmp_address(0x2000) });
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], 0xE9);

        // Far case: PC=0x1000, target=0x1_0000_0000 → beyond ±2GB → 16 bytes, starts with FF 25
        let bytes = encode_at(0x1000, |w| unsafe { w.put_jmp_address(0x1_0000_0000) });
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0xFF);
        assert_eq!(bytes[1], 0x25);
        // Verify the embedded target address
        let target = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(target, 0x1_0000_0000);
    }
}
