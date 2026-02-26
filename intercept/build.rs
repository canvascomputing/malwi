fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if arch != "aarch64" && arch != "x86_64" {
        return;
    }

    let mut build = cc::Build::new();
    build
        .define("CAPSTONE_USE_SYS_DYN_MEM", None)
        .include("capstone/include")
        .include("capstone")
        .files([
            "capstone/cs.c",
            "capstone/Mapping.c",
            "capstone/MCInst.c",
            "capstone/MCInstPrinter.c",
            "capstone/MCInstrDesc.c",
            "capstone/MCRegisterInfo.c",
            "capstone/SStream.c",
            "capstone/utils.c",
        ])
        .warnings(false);

    if arch == "aarch64" {
        build
            .define("CAPSTONE_HAS_AARCH64", None)
            .files([
                "capstone/arch/AArch64/AArch64BaseInfo.c",
                "capstone/arch/AArch64/AArch64Disassembler.c",
                "capstone/arch/AArch64/AArch64DisassemblerExtension.c",
                "capstone/arch/AArch64/AArch64InstPrinter.c",
                "capstone/arch/AArch64/AArch64Mapping.c",
                "capstone/arch/AArch64/AArch64Module.c",
            ])
            .file("capstone_helper.c");
    }

    if arch == "x86_64" {
        build.define("CAPSTONE_HAS_X86", None).files([
            "capstone/arch/X86/X86ATTInstPrinter.c",
            "capstone/arch/X86/X86Disassembler.c",
            "capstone/arch/X86/X86DisassemblerDecoder.c",
            "capstone/arch/X86/X86InstPrinterCommon.c",
            "capstone/arch/X86/X86IntelInstPrinter.c",
            "capstone/arch/X86/X86Mapping.c",
            "capstone/arch/X86/X86Module.c",
        ]);
    }

    build.compile("capstone");
}
