#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdint.h>

/* CS_OP_REG = 1. Both AARCH64_OP_REG (1) and AARCH64_OP_MEM_REG (0x81) have bit 0 set. */
#define IS_REG_OPERAND(type) ((type) & CS_OP_REG)

void capstone_check_x16_x17(const uint8_t *code, size_t insn_count,
                             bool *uses_x16, bool *uses_x17) {
    *uses_x16 = false;
    *uses_x17 = false;

    csh handle;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        /* Conservative fallback: assume both are used. */
        *uses_x16 = true;
        *uses_x17 = true;
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn;
    size_t count = cs_disasm(handle, code, insn_count * 4, 0, insn_count, &insn);

    for (size_t i = 0; i < count; i++) {
        cs_aarch64 *arm64 = &insn[i].detail->aarch64;
        for (uint8_t j = 0; j < arm64->op_count; j++) {
            cs_aarch64_op *op = &arm64->operands[j];
            if (IS_REG_OPERAND(op->type)) {
                aarch64_reg reg = op->reg;
                /* Check both Xn and Wn forms: W16/W17 alias X16/X17. */
                if (reg == AARCH64_REG_X16 || reg == AARCH64_REG_W16)
                    *uses_x16 = true;
                if (reg == AARCH64_REG_X17 || reg == AARCH64_REG_W17)
                    *uses_x17 = true;
            }
            /* Also check base/index registers inside memory operands. */
            if (op->type == AARCH64_OP_MEM) {
                aarch64_reg base = op->mem.base;
                aarch64_reg idx  = op->mem.index;
                if (base == AARCH64_REG_X16 || base == AARCH64_REG_W16 ||
                    idx  == AARCH64_REG_X16 || idx  == AARCH64_REG_W16)
                    *uses_x16 = true;
                if (base == AARCH64_REG_X17 || base == AARCH64_REG_W17 ||
                    idx  == AARCH64_REG_X17 || idx  == AARCH64_REG_W17)
                    *uses_x17 = true;
            }
        }
    }

    cs_free(insn, count);
    cs_close(&handle);
}
