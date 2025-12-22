#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    SP = 31,
}

#[derive(Debug)]
pub struct Arm64Writer {
    base: *mut u32,
    code: *mut u32,
    pc: u64,
    size: usize,
}

impl Arm64Writer {
    pub unsafe fn new(buffer: *mut u8, size: usize, pc: u64) -> Self {
        Self {
            base: buffer as *mut u32,
            code: buffer as *mut u32,
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

    /// Returns the current write pointer. Used for label fixups.
    pub fn code_ptr(&self) -> *mut u32 {
        self.code
    }

    fn can_write(&self, bytes: usize) -> bool {
        self.offset() + bytes <= self.size
    }

    unsafe fn put_u32(&mut self, insn: u32) {
        debug_assert!(self.can_write(4));
        self.code.write(insn);
        self.code = self.code.add(1);
        self.pc = self.pc.wrapping_add(4);
    }

    pub unsafe fn put_u32_raw(&mut self, insn: u32) {
        self.put_u32(insn);
    }

    pub unsafe fn put_ret(&mut self) {
        self.put_u32(0xD65F03C0);
    }

    pub unsafe fn put_br_reg(&mut self, reg: Reg) {
        let n = reg as u32;
        self.put_u32(0xD61F0000 | (n << 5));
    }

    pub unsafe fn put_blr_reg(&mut self, reg: Reg) {
        let n = reg as u32;
        self.put_u32(0xD63F0000 | (n << 5));
    }

    pub unsafe fn put_push_reg_reg(&mut self, a: Reg, b: Reg) {
        // STP Xa, Xb, [SP, #-16]!
        let rt = a as u32;
        let rt2 = b as u32;
        let rn = Reg::SP as u32;
        let imm7 = (-2i32 as u32) & 0x7f; // -16 bytes, scaled by 8
        self.put_u32(0xA980_0000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt);
    }

    pub unsafe fn put_pop_reg_reg(&mut self, a: Reg, b: Reg) {
        // LDP Xa, Xb, [SP], #16
        let rt = a as u32;
        let rt2 = b as u32;
        let rn = Reg::SP as u32;
        let imm7 = 2u32; // +16 bytes, scaled by 8
        self.put_u32(0xA8C0_0000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt);
    }

    pub unsafe fn put_add_reg_reg_imm(&mut self, d: Reg, n: Reg, imm: u32) {
        // ADD Xd, Xn, #imm12 (shift=0)
        let rd = d as u32;
        let rn = n as u32;
        let imm12 = imm & 0x0fff;
        self.put_u32(0x9100_0000 | (imm12 << 10) | (rn << 5) | rd);
    }

    pub unsafe fn put_sub_reg_reg_imm(&mut self, d: Reg, n: Reg, imm: u32) {
        // SUB Xd, Xn, #imm12 (shift=0)
        let rd = d as u32;
        let rn = n as u32;
        let imm12 = imm & 0x0fff;
        self.put_u32(0xD100_0000 | (imm12 << 10) | (rn << 5) | rd);
    }

    pub unsafe fn put_mov_reg_reg(&mut self, dst: Reg, src: Reg) {
        // MOV Xd, Xs.
        //
        // Note: SP is not a general register for logical instructions; the usual ORR-alias form
        // would treat `SP` as `XZR`. Handle SP explicitly using `ADD ...,#0`.
        if src == Reg::SP || dst == Reg::SP {
            self.put_add_reg_reg_imm(dst, src, 0);
            return;
        }

        // Alias of ORR Xd, XZR, Xs
        let rd = dst as u32;
        let rm = src as u32;
        self.put_u32(0xAA00_03E0 | (rm << 16) | rd);
    }

    pub unsafe fn put_mov_reg_u64(&mut self, dst: Reg, value: u64) {
        // Materialize an absolute 64-bit constant using MOVZ/MOVK.
        // This avoids literal pools and PC-relative semantics in generated code.
        let rd = dst as u32;
        let mut first = true;
        for (hw, shift) in [(0u32, 0u32), (1, 16), (2, 32), (3, 48)] {
            let imm16 = ((value >> shift) & 0xffff) as u32;
            if first {
                // MOVZ Xd, #imm16, LSL #shift
                self.put_u32(0xD280_0000 | (hw << 21) | (imm16 << 5) | rd);
                first = false;
            } else {
                // MOVK Xd, #imm16, LSL #shift
                self.put_u32(0xF280_0000 | (hw << 21) | (imm16 << 5) | rd);
            }
        }
    }

    pub unsafe fn put_b_imm(&mut self, target: u64) {
        let imm = (target as i64 - self.pc as i64) >> 2;
        let imm26 = (imm as u32) & 0x03FF_FFFF;
        self.put_u32(0x1400_0000 | imm26);
    }

    pub unsafe fn put_bl_imm(&mut self, target: u64) {
        let imm = (target as i64 - self.pc as i64) >> 2;
        let imm26 = (imm as u32) & 0x03FF_FFFF;
        self.put_u32(0x9400_0000 | imm26);
    }

    /// Emit ADRP+ADD+BR sequence (12 bytes, ±4GB range).
    ///
    /// This is shorter than the 16-byte LDR+BR+literal sequence and useful
    /// for patching short functions where overwriting 16 bytes would corrupt
    /// adjacent code.
    pub unsafe fn put_adrp_add_br(&mut self, reg: Reg, target: u64) {
        let rt = reg as u32;

        // ADRP: load page-aligned PC-relative address.
        // immhi (19 bits) | immlo (2 bits) encode a 21-bit page offset.
        let target_page = target & !0xFFF;
        let pc_page = self.pc & !0xFFF;
        let page_off = ((target_page as i64) - (pc_page as i64)) >> 12;
        let immlo = (page_off as u32) & 0x3;
        let immhi = ((page_off as u32) >> 2) & 0x7FFFF;
        self.put_u32(0x9000_0000 | (immlo << 29) | (immhi << 5) | rt);

        // ADD Xt, Xt, #pageoff (low 12 bits of target).
        let pageoff12 = (target & 0xFFF) as u32;
        self.put_u32(0x9100_0000 | (pageoff12 << 10) | (rt << 5) | rt);

        // BR Xt
        self.put_br_reg(reg);
    }

    pub unsafe fn put_ldr_br_address(&mut self, reg: Reg, addr: u64) {
        // Sequence:
        //   LDR Xt, [PC, #8]
        //   BR  Xt
        //   .quad addr
        //
        // LDR (literal, 64-bit): op=01, imm19<<5, Rt.
        let rt = reg as u32;
        let imm19 = 2u32; // 2 * 4 = 8 bytes
        self.put_u32(0x5800_0000 | (imm19 << 5) | rt);
        self.put_br_reg(reg);

        // Inline literal (8 bytes), little-endian.
        debug_assert!(self.can_write(8));
        let p = self.code as *mut u8;
        (p as *mut u64).write(addr);
        self.code = (p.add(8)) as *mut u32;
        self.pc = self.pc.wrapping_add(8);
    }

    pub unsafe fn put_ldr_reg_address(&mut self, reg: Reg, addr: u64) {
        // Sequence:
        //   LDR Xt, [PC, #8]
        //   B   +12
        //   .quad addr
        //
        // This loads an absolute pointer value into Xt and continues execution after the literal.
        let rt = reg as u32;
        let imm19 = 2u32; // 8 bytes
        self.put_u32(0x5800_0000 | (imm19 << 5) | rt);

        // Skip over literal.
        self.put_b_imm(self.pc + 12);

        debug_assert!(self.can_write(8));
        let p = self.code as *mut u8;
        (p as *mut u64).write(addr);
        self.code = (p.add(8)) as *mut u32;
        self.pc = self.pc.wrapping_add(8);
    }

    pub unsafe fn put_ldr_reg_reg_offset(&mut self, rt: Reg, rn: Reg, offset: i64) {
        // LDR Xt, [Xn, #imm] (unsigned immediate, scaled by 8 for 64-bit)
        // Encoding supports only non-negative, 8-byte aligned offsets here.
        if offset < 0 || (offset & 0x7) != 0 {
            panic!("unsupported LDR offset: {offset}");
        }
        let imm12 = ((offset as u64) >> 3) as u32;
        let rt = rt as u32;
        let rn = rn as u32;
        self.put_u32(0xF940_0000 | (imm12 << 10) | (rn << 5) | rt);
    }

    pub unsafe fn put_str_reg_reg_offset(&mut self, rt: Reg, rn: Reg, offset: i64) {
        // STR Xt, [Xn, #imm] (unsigned immediate, scaled by 8 for 64-bit)
        if offset < 0 || (offset & 0x7) != 0 {
            panic!("unsupported STR offset: {offset}");
        }
        let imm12 = ((offset as u64) >> 3) as u32;
        let rt = rt as u32;
        let rn = rn as u32;
        self.put_u32(0xF900_0000 | (imm12 << 10) | (rn << 5) | rt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_b_forward() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_b_imm(0x1100);
        }
        let insn = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // PC-relative offset = (0x1100 - 0x1000) / 4 = 0x40
        assert_eq!(insn, 0x1400_0040);
    }

    #[test]
    fn encode_br_x16() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_br_reg(Reg::X16);
        }
        let insn = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(insn, 0xD61F0000 | (16 << 5));
    }

    #[test]
    fn encode_stp_sp_pre_index_x29_x30() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_push_reg_reg(Reg::X29, Reg::X30);
        }
        let insn = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(insn, 0xA9BF_7BFD);
    }

    #[test]
    fn encode_ldp_sp_post_index_x29_x30() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_pop_reg_reg(Reg::X29, Reg::X30);
        }
        let insn = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(insn, 0xA8C1_7BFD);
    }

    #[test]
    fn encode_add_sub_imm() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_sub_reg_reg_imm(Reg::SP, Reg::SP, 0x100);
            w.put_add_reg_reg_imm(Reg::SP, Reg::SP, 0x100);
        }
        let sub = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let add = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(sub, 0xD100_0000 | (0x100 << 10) | (31 << 5) | 31);
        assert_eq!(add, 0x9100_0000 | (0x100 << 10) | (31 << 5) | 31);
    }

    #[test]
    fn encode_mov_x0_x1() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_mov_reg_reg(Reg::X0, Reg::X1);
        }
        let insn = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(insn, 0xAA01_03E0);
    }

    #[test]
    fn encode_mov_x16_sp_uses_add() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_mov_reg_reg(Reg::X16, Reg::SP);
        }
        let insn = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // ADD X16, SP, #0
        assert_eq!(insn, 0x9100_0000 | (0 << 10) | (31 << 5) | 16);
    }

    #[test]
    fn encode_mov_reg_u64() {
        let mut buf = [0u8; 32];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_mov_reg_u64(Reg::X16, 0x0123_4567_89AB_CDEFu64);
        }
        let i0 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let i1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let i2 = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let i3 = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        // movz x16, #0xcdef
        assert_eq!(i0, 0xD280_0000 | (0 << 21) | (0xCDEF << 5) | 16);
        // movk x16, #0x89ab, lsl #16
        assert_eq!(i1, 0xF280_0000 | (1 << 21) | (0x89AB << 5) | 16);
        // movk x16, #0x4567, lsl #32
        assert_eq!(i2, 0xF280_0000 | (2 << 21) | (0x4567 << 5) | 16);
        // movk x16, #0x0123, lsl #48
        assert_eq!(i3, 0xF280_0000 | (3 << 21) | (0x0123 << 5) | 16);
    }

    #[test]
    fn encode_ldr_br_literal() {
        let mut buf = [0u8; 32];
        let addr = 0xDEAD_BEEF_CAFE_BABEu64;
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_ldr_br_address(Reg::X16, addr);
        }
        let ldr = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let br = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let lit = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(ldr, 0x5800_0000 | (2 << 5) | 16);
        assert_eq!(br, 0xD61F_0000 | (16 << 5));
        assert_eq!(lit, addr);
    }

    #[test]
    fn encode_ldr_reg_address_literal() {
        let mut buf = [0u8; 32];
        let addr = 0x0123_4567_89AB_CDEFu64;
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_ldr_reg_address(Reg::X17, addr);
        }
        let ldr = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let b = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let lit = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(ldr, 0x5800_0000 | (2 << 5) | 17);
        // B from 0x1004 to 0x1010 => imm26 = 3
        assert_eq!(b, 0x1400_0003);
        assert_eq!(lit, addr);
    }

    #[test]
    fn encode_ldr_str_reg_reg_offset() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_ldr_reg_reg_offset(Reg::X0, Reg::X1, 0x18);
            w.put_str_reg_reg_offset(Reg::X2, Reg::X3, 0x18);
        }
        let ldr = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let str_ = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        // imm12 = 0x18 / 8 = 3
        assert_eq!(ldr, 0xF940_0000 | (3 << 10) | (1 << 5) | 0);
        assert_eq!(str_, 0xF900_0000 | (3 << 10) | (3 << 5) | 2);
    }

    #[test]
    fn encode_blr_x16() {
        let mut buf = [0u8; 16];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x1000);
            w.put_blr_reg(Reg::X16);
        }
        let insn = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(insn, 0xD63F_0000 | (16 << 5));
    }
}
