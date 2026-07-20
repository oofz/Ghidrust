//! Print register names as numeric ids .

pub fn strip_reg_names(operands: &str) -> String {
    let mut out = operands.to_string();
    for (i, name) in [
 "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rbx", "rsp",
 "rbp", "rsi", "rdi", "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "ax", "cx",
 "dx", "bx", "sp", "bp", "si", "di", "al", "cl", "dl", "bl",
    ]
    .iter()
    .enumerate()
    {
 out = out.replace(name, &format!("r{i}"));
    }
    out
}
