/*
 * CA01 / PROC_TMD UU.11.34, function 0x00019520 (428-byte ARM function).
 * Manual, instruction-derived C reconstruction - NOT Ghidra-decompiled original.
 *
 * Input ELF SHA256:
 * 28e8b7d000b0d764c3bdadb1f2ff0e28d16dbd6d64946967e527597d3ddd51c8
 *
 * Source evidence: ARM disassembly 0x19520..0x196c8 saved beside this file.
 * All addresses below correspond to firmware virtual addresses, not actual
 * host pointers. 'read_*' / 'write_*' are abstractions. Do NOT execute on vehicle.
 * External call names are invented labels for unknown firmware function symbols.
 */
#include <stdint.h>
#include <stddef.h>

struct ca01_mem_ops {
    uint32_t (*read32)(uint32_t address);
    uint16_t (*read16)(uint32_t address);
    uint8_t  (*read8)(uint32_t address);
    void (*write32)(uint32_t address, uint32_t value);
    void (*release_slot)(uint32_t slot);               /* BL 0x00009a0c */
    uint32_t (*allocate)(uint32_t slot, uint32_t len); /* BL 0x00009970 */
    void (*configure_slot)(uint32_t ptr, uint32_t mode,
                           uint32_t len);             /* BL 0x00009acc */
    void (*apply_config)(const void *packed);          /* BL 0x0001cfa4 */
};

#pragma pack(push,1)
struct ca01_tmd_apply {
    uint16_t long_dimension;  /* sp + 0x04 */
    uint16_t short_dimension; /* sp + 0x06 */
    uint8_t config4f;        /* sp + 0x08 */
    uint8_t config50;        /* sp + 0x09 */
    uint8_t enabled;         /* sp + 0x0a = 1 */
    uint8_t config4e;        /* sp + 0x0b */
    uint16_t config52;       /* sp + 0x0c */
    uint16_t config56;       /* sp + 0x0e */
    uint16_t config54;       /* sp + 0x10 */
    uint8_t config58;        /* sp + 0x12 */
    uint8_t config5a;        /* sp + 0x13 */
    uint8_t config59;        /* sp + 0x14 */
};
#pragma pack(pop)

_Static_assert(sizeof(struct ca01_tmd_apply)==17, "unexpected ARM ABI struct layout");

/*
 * r0=width, r1=height at entry. Call contracts inferred from register usage,
 * not from missing external implementations. Matches ARM register/data flow,
 * subject to conventional caller/callee ABI preservation at call sites.
 */
void ca01_tmd_00019520_reconstructed(uint32_t width, uint32_t height,
                                     const struct ca01_mem_ops *ops)
{
    /* 0x19528: ORRS; 0x19534: BMI early return if either sign bit set. */
    if ((int32_t)(width | height) < 0) return;

    uint32_t prev_width = ops->read32(0x0006322c); /* [r6+0xa4] */
    uint32_t prev_height = ops->read32(0x00063230);/* [r6+0xa8] */
    if (width != prev_width || height != prev_height) {
        if (ops->read32(0x00063184) != 0) {        /* 0x19554 */
            ops->release_slot(2);                  /* 0x19560 */
        }

        uint32_t bytes = width * UINT32_C(4) * height; /* MUL, 32-bit wrap */
        uint32_t allocation_len;
        if (width != 0 && height != 0) {
            allocation_len = bytes;                /* 0x1957c..0x1959c */
        } else {
            allocation_len = 0x000e1000;          /* 0x19678..0x1969c */
        }

        uint32_t ptr = ops->allocate(2, allocation_len); /* 0x9970 */
        ops->write32(0x00063184, ptr);
        ops->configure_slot(ptr, 0, allocation_len);    /* 0x9acc */
        ops->write32(0x000632c8, bytes);                /* [0x632b4+0x14] */
        ops->write32(0x0006322c, width);
        ops->write32(0x00063230, height);
    }

    uint32_t clipped_width = width;
    uint32_t clipped_height = height;
    if (ops->read32(0x0006321c) == 0) {
        /* ARM CMP/COPYLT and CMP/COPYLE, 0x195d4..0x195ec.
         * Note signed MIN for widths, <= comparison for heights.
         */
        uint32_t previous_w = ops->read32(0x000633e0);
        uint32_t previous_h = ops->read32(0x000633e4);
        clipped_width =
            (int32_t)width < (int32_t)previous_w ? width : previous_w;
        clipped_height =
            (int32_t)height <= (int32_t)previous_h ? height : previous_h;
    }
    ops->write32(0x000633d8, clipped_width);   /* r2+0xb8 */
    ops->write32(0x000633dc, clipped_height);  /* r2+0xbc */

    /* 0x195f0..0x1966c, orientation and packed hardware configuration. */
    const int landscape = width > height;
    struct ca01_tmd_apply cfg = {
        .long_dimension  = landscape ? 0x0280 : 0x0168,
        .short_dimension = landscape ? 0x0168 : 0x0280,
        .config4f = ops->read8(0x00063303),
        .config50 = ops->read8(0x00063304),
        .enabled = 1,
        .config4e = ops->read8(0x00063302),
        .config52 = ops->read16(0x00063306),
        .config56 = ops->read16(0x0006330a),
        .config54 = ops->read16(0x00063308),
        .config58 = ops->read8(0x0006330c),
        .config5a = ops->read8(0x0006330e),
        .config59 = ops->read8(0x0006330d)
    };
    ops->apply_config(&cfg);  /* 0x1966c -> 0x0001cfa4 */
}
