use icicle_vm::{
    cpu::{lifter::BlockState, Arch, Cpu, ValueSource},
    Vm,
};
use pcode::Op;

pub(crate) const EXCP_SWI: u32 = 2;

use crate::fuzzware::uc_arm_reg::{self, *};

pub(crate) struct XpsrHandler {
    pub ng: pcode::VarNode,
    pub zr: pcode::VarNode,
    pub cy: pcode::VarNode,
    pub ov: pcode::VarNode,
    pub xpsr: pcode::VarNode,
}

impl XpsrHandler {
    pub fn new(cpu: &mut Cpu) -> Self {
        Self {
            ng: cpu.arch.sleigh.get_varnode("NG").unwrap(),
            zr: cpu.arch.sleigh.get_varnode("ZR").unwrap(),
            cy: cpu.arch.sleigh.get_varnode("CY").unwrap(),
            ov: cpu.arch.sleigh.get_varnode("OV").unwrap(),
            xpsr: cpu.arch.sleigh.get_varnode("xpsr").unwrap(),
        }
    }
}

const XPSR_NZCV_MASK: u32 = 0xf000_0000;

impl icicle_vm::cpu::RegHandler for XpsrHandler {
    fn read(&mut self, cpu: &mut Cpu) {
        let mut xpsr = cpu.read_var::<u32>(self.xpsr) & !crate::arm::XPSR_NZCV_MASK;
        xpsr |= (cpu.read_var::<u8>(self.ng) as u32) << 31;
        xpsr |= (cpu.read_var::<u8>(self.zr) as u32) << 30;
        xpsr |= (cpu.read_var::<u8>(self.cy) as u32) << 29;
        xpsr |= (cpu.read_var::<u8>(self.ov) as u32) << 28;
        cpu.write_var(self.xpsr, xpsr);
    }

    fn write(&mut self, cpu: &mut Cpu) {
        let xpsr = cpu.read_var::<u32>(self.xpsr) & crate::arm::XPSR_NZCV_MASK;
        cpu.write_var::<u8>(self.ng, ((xpsr >> 31) & 0b1) as u8);
        cpu.write_var::<u8>(self.zr, ((xpsr >> 30) & 0b1) as u8);
        cpu.write_var::<u8>(self.cy, ((xpsr >> 29) & 0b1) as u8);
        cpu.write_var::<u8>(self.ov, ((xpsr >> 28) & 0b1) as u8);
    }
}

/// Most of this should probably be implemented as part of the SLEIGH specification instead.
pub(crate) fn add_arm_extras(vm: &mut Vm, nvic_changed_hook: pcode::HookId) {
    const CPSR_IRQ_MASK_BIT: u32 = 1 << 7;
    const CPSR_FIQ_MASK_BIT: u32 = 1 << 6;

    let xpsr_reg = vm.cpu.arch.sleigh.add_custom_reg("xpsr", 4).unwrap();
    let xpsr_handler = XpsrHandler::new(&mut vm.cpu);
    vm.cpu.add_reg_handler(xpsr_reg.id, Box::new(xpsr_handler));

    let basepri_reg = vm.cpu.arch.sleigh.add_custom_reg("basepri", 4).unwrap();
    let primask_reg = vm.cpu.arch.sleigh.add_custom_reg("primask", 4).unwrap();

    vm.add_op_injector(
        "getCurrentExceptionNumber",
        move |_: &Arch, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntAnd, (xpsr_reg, 0x1ff_u32)));
            false
        },
    );

    vm.add_op_injector("enableIRQinterrupts", move |_: &Arch, _, _, _, b: &mut BlockState| {
        b.pcode.push((primask_reg, Op::IntAnd, (primask_reg, !CPSR_IRQ_MASK_BIT)));
        b.pcode.push(pcode::Op::Hook(nvic_changed_hook));
        // Changing this variable could cause an interrupt to be triggered, so terminate the
        // block here.
        true
    });

    vm.add_op_injector("disableIRQinterrupts", move |_: &Arch, _, _, _, b: &mut BlockState| {
        b.pcode.push((primask_reg, Op::IntOr, (primask_reg, CPSR_IRQ_MASK_BIT)));
        b.pcode.push(pcode::Op::Hook(nvic_changed_hook));
        false
    });

    vm.add_op_injector("enableFIQinterrupts", move |_: &Arch, _, _, _, b: &mut BlockState| {
        b.pcode.push((primask_reg, Op::IntAnd, (primask_reg, !CPSR_FIQ_MASK_BIT)));
        b.pcode.push(pcode::Op::Hook(nvic_changed_hook));
        // Changing this variable could cause an interrupt to be triggered, so terminate the
        // block here.
        true
    });

    vm.add_op_injector("disableFIQinterrupts", move |_: &Arch, _, _, _, b: &mut BlockState| {
        b.pcode.push((primask_reg, Op::IntOr, (primask_reg, CPSR_FIQ_MASK_BIT)));
        b.pcode.push(pcode::Op::Hook(nvic_changed_hook));
        false
    });

    vm.add_op_injector(
        "isIRQinterruptsEnabled",
        move |_: &Arch, _, _, output, b: &mut BlockState| {
            let shift = 31 - CPSR_IRQ_MASK_BIT.leading_zeros();
            b.pcode.push((output, Op::IntRight, (primask_reg, shift)));
            // Even though the p-code operation is called "isIRQinterruptsEnabled" it is intended to
            // returns the value of `PRIMASK` directly (which is 0 when interrupts are enabled, and
            // 1 when they are enabled).
            // b.pcode.push((output, Op::IntNot, output));
            b.pcode.push((output, Op::IntAnd, (output, 1)));
            false
        },
    );

    vm.add_op_injector(
        "getBasePriority",
        move |_: &Arch, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntAnd, (basepri_reg, 0xff_u32)));
            false
        },
    );

    vm.add_op_injector(
        "setBasePriority",
        move |_: &Arch, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let val = inputs.first();
            b.pcode.push((basepri_reg, Op::IntAnd, (val, 0xff_u32)));
            b.pcode.push(pcode::Op::Hook(nvic_changed_hook));
            // Changing this variable could cause an interrupt to be triggered, so terminate the
            // block here.
            true
        },
    );

    // Control registers. controls current mode of the stack and whether thread mode should be
    // privileged.
    //
    // Bit 0: Execution privilege in thread mode:
    //  - 0: thread mode is unprivilege
    //  - 1: thread mode is privilege
    //
    // Bit 1:
    //  - 0: thread mode
    //  - 1: main-stack mode
    let control = vm.cpu.arch.sleigh.add_custom_reg("spsel", 4).unwrap();
    // Cached copy of spsel bit 1
    let current_sp_mode_is_psp =
        vm.cpu.arch.sleigh.add_custom_reg("curr_sp_mode_is_psp", 4).unwrap();

    vm.add_op_injector(
        "isCurrentModePrivileged",
        move |_: &Arch, _, _, output: pcode::VarNode, b: &mut BlockState| {
            // Assume always true to match unicorn behavior.
            // Note: should be equal to `!(control & 1)` in thread mode and `1` in main stack mode.
            b.pcode.push((output, Op::Copy, pcode::Value::Const(1, output.size)));
            false
        },
    );

    vm.add_op_injector(
        "isThreadModePrivileged",
        move |_: &Arch, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntAnd, (control.truncate(1), 0b1_u8)));
            b.pcode.push((output, Op::BoolNot, output));
            false
        },
    );

    vm.add_op_injector(
        "setThreadModePrivileged",
        move |_: &Arch, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let is_privileged = inputs.first();

            // nPRIV bit is 0 if privileged and 1 if unprivileged so we need to invert the
            // `is_privileged` flag here.
            let npriv_bit = b.pcode.alloc_tmp(1);
            b.pcode.push((npriv_bit, Op::BoolNot, is_privileged));

            // Write the bit to the CONTROL register.
            b.pcode.push((control, Op::IntAnd, (control, !0b1_u32)));
            b.pcode.push((control.truncate(1), Op::IntOr, (control.truncate(1), npriv_bit)));
            false
        },
    );

    vm.add_op_injector(
        "isThreadMode",
        move |_: &Arch, _, _, output: pcode::VarNode, b: &mut BlockState| {
            // Processor is in thread mode if there is no active interrupt
            let tmp = b.pcode.alloc_tmp(4);
            b.pcode.push((tmp, Op::IntAnd, (xpsr_reg, 0x1ff_u32)));
            b.pcode.push((output, Op::IntEqual, (tmp, 0)));
            false
        },
    );

    vm.add_op_injector(
        "isUsingMainStack",
        move |_: &Arch, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntEqual, (current_sp_mode_is_psp, 0_u32)));
            false
        },
    );

    // Copy of the inactive stack pointer.
    let other_sp_reg = vm.cpu.arch.sleigh.add_custom_reg("other_sp", 4).unwrap();
    let sp_reg = vm.cpu.arch.reg_sp;

    // Note: The processor ignores writes to control bit that sets the current stack pointer in
    // handler mode, so this will never be called unless the current processor state is thread mode
    // (handled in the SLEIGH speicification).
    vm.add_op_injector(
        "setStackMode",
        move |_: &Arch, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let is_main_stack = inputs.first();
            let is_process_stack = b.pcode.alloc_tmp(1);
            b.pcode.push((is_process_stack, Op::BoolNot, is_main_stack));

            let mode = b.pcode.alloc_tmp(4);
            b.pcode.push((mode, Op::ZeroExtend, is_process_stack));

            // Switch stacks if required.
            let mode_changed = b.pcode.alloc_tmp(1);
            b.pcode.push((mode_changed, Op::IntNotEqual, (current_sp_mode_is_psp, mode)));
            let new_sp = b.pcode.alloc_tmp(4);
            b.pcode.select(new_sp, mode_changed, other_sp_reg, sp_reg);
            b.pcode.select(other_sp_reg, mode_changed, sp_reg, other_sp_reg);
            b.pcode.push((sp_reg, Op::Copy, new_sp));

            // Update registers that keep track of the current stack mode.
            b.pcode.push((current_sp_mode_is_psp, Op::Copy, mode));
            b.pcode.push((mode, Op::IntLeft, (mode, 1_u32)));
            b.pcode.push((control, Op::IntAnd, (control, !0b10_u32)));
            b.pcode.push((control, Op::IntOr, (control, mode)));
            false
        },
    );

    vm.add_op_injector("getMainStackPointer", move |_: &Arch, _, _, output, b: &mut BlockState| {
        b.pcode.select(output, current_sp_mode_is_psp, other_sp_reg, sp_reg);
        false
    });

    vm.add_op_injector(
        "setMainStackPointer",
        move |_: &Arch, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let val = inputs.first();
            b.pcode.select(sp_reg, current_sp_mode_is_psp, sp_reg, val);
            b.pcode.select(other_sp_reg, current_sp_mode_is_psp, val, other_sp_reg);
            false
        },
    );

    vm.add_op_injector(
        "getProcessStackPointer",
        move |_: &Arch, _, _, output, b: &mut BlockState| {
            b.pcode.select(output, current_sp_mode_is_psp, sp_reg, other_sp_reg);
            false
        },
    );

    vm.add_op_injector(
        "setProcessStackPointer",
        move |_: &Arch, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let val = inputs.first();
            b.pcode.select(sp_reg, current_sp_mode_is_psp, val, sp_reg);
            b.pcode.select(other_sp_reg, current_sp_mode_is_psp, other_sp_reg, val);
            false
        },
    );
}

/// Returns a mapping from Unicorn Register IDs to Icicle varnodes. This is needed for compatability
/// with the C code in Fuzzware.
pub(crate) fn map_uc_to_varnodes(cpu: &Cpu) -> Vec<pcode::VarNode> {
    let mut vars = vec![pcode::VarNode::NONE; UC_ARM_REG_ENDING as usize];

    let mut map = |id: uc_arm_reg::Type, name: &str| match cpu.arch.sleigh.get_varnode(name) {
        Some(reg) => vars[id as usize] = reg,
        None => eprintln!("{name} not found in Sleigh spec"),
    };

    // map(UC_ARM_REG_APSR, "apsr");
    // map(UC_ARM_REG_APSR_NZCV, "apsr_nzcv");
    map(UC_ARM_REG_CPSR, "cpsr");
    map(UC_ARM_REG_FPEXC, "fpexc");
    // map(UC_ARM_REG_FPINST, "fpinst");
    map(UC_ARM_REG_FPSCR, "fpscr");
    // map(UC_ARM_REG_FPSCR_NZCV, "fpscr_nzcv");
    map(UC_ARM_REG_FPSID, "fpsid");
    // map(UC_ARM_REG_ITSTATE, "itstate");
    map(UC_ARM_REG_LR, "lr");
    map(UC_ARM_REG_PC, "pc");
    map(UC_ARM_REG_SP, "sp");
    map(UC_ARM_REG_SPSR, "spsr");
    map(UC_ARM_REG_D0, "d0");
    map(UC_ARM_REG_D1, "d1");
    map(UC_ARM_REG_D2, "d2");
    map(UC_ARM_REG_D3, "d3");
    map(UC_ARM_REG_D4, "d4");
    map(UC_ARM_REG_D5, "d5");
    map(UC_ARM_REG_D6, "d6");
    map(UC_ARM_REG_D7, "d7");
    map(UC_ARM_REG_D8, "d8");
    map(UC_ARM_REG_D9, "d9");
    map(UC_ARM_REG_D10, "d10");
    map(UC_ARM_REG_D11, "d11");
    map(UC_ARM_REG_D12, "d12");
    map(UC_ARM_REG_D13, "d13");
    map(UC_ARM_REG_D14, "d14");
    map(UC_ARM_REG_D15, "d15");
    map(UC_ARM_REG_D16, "d16");
    map(UC_ARM_REG_D17, "d17");
    map(UC_ARM_REG_D18, "d18");
    map(UC_ARM_REG_D19, "d19");
    map(UC_ARM_REG_D20, "d20");
    map(UC_ARM_REG_D21, "d21");
    map(UC_ARM_REG_D22, "d22");
    map(UC_ARM_REG_D23, "d23");
    map(UC_ARM_REG_D24, "d24");
    map(UC_ARM_REG_D25, "d25");
    map(UC_ARM_REG_D26, "d26");
    map(UC_ARM_REG_D27, "d27");
    map(UC_ARM_REG_D28, "d28");
    map(UC_ARM_REG_D29, "d29");
    map(UC_ARM_REG_D30, "d30");
    map(UC_ARM_REG_D31, "d31");
    // map(UC_ARM_REG_FPINST2, "fpinst2");
    map(UC_ARM_REG_MVFR0, "mvfr0");
    map(UC_ARM_REG_MVFR1, "mvfr1");
    // map(UC_ARM_REG_MVFR2, "mvfr2");
    map(UC_ARM_REG_Q0, "q0");
    map(UC_ARM_REG_Q1, "q1");
    map(UC_ARM_REG_Q2, "q2");
    map(UC_ARM_REG_Q3, "q3");
    map(UC_ARM_REG_Q4, "q4");
    map(UC_ARM_REG_Q5, "q5");
    map(UC_ARM_REG_Q6, "q6");
    map(UC_ARM_REG_Q7, "q7");
    map(UC_ARM_REG_Q8, "q8");
    map(UC_ARM_REG_Q9, "q9");
    map(UC_ARM_REG_Q10, "q10");
    map(UC_ARM_REG_Q11, "q11");
    map(UC_ARM_REG_Q12, "q12");
    map(UC_ARM_REG_Q13, "q13");
    map(UC_ARM_REG_Q14, "q14");
    map(UC_ARM_REG_Q15, "q15");
    map(UC_ARM_REG_R0, "r0");
    map(UC_ARM_REG_R1, "r1");
    map(UC_ARM_REG_R2, "r2");
    map(UC_ARM_REG_R3, "r3");
    map(UC_ARM_REG_R4, "r4");
    map(UC_ARM_REG_R5, "r5");
    map(UC_ARM_REG_R6, "r6");
    map(UC_ARM_REG_R7, "r7");
    map(UC_ARM_REG_R8, "r8");
    map(UC_ARM_REG_R9, "r9");
    map(UC_ARM_REG_R10, "r10");
    map(UC_ARM_REG_R11, "r11");
    map(UC_ARM_REG_R12, "r12");
    map(UC_ARM_REG_S0, "s0");
    map(UC_ARM_REG_S1, "s1");
    map(UC_ARM_REG_S2, "s2");
    map(UC_ARM_REG_S3, "s3");
    map(UC_ARM_REG_S4, "s4");
    map(UC_ARM_REG_S5, "s5");
    map(UC_ARM_REG_S6, "s6");
    map(UC_ARM_REG_S7, "s7");
    map(UC_ARM_REG_S8, "s8");
    map(UC_ARM_REG_S9, "s9");
    map(UC_ARM_REG_S10, "s10");
    map(UC_ARM_REG_S11, "s11");
    map(UC_ARM_REG_S12, "s12");
    map(UC_ARM_REG_S13, "s13");
    map(UC_ARM_REG_S14, "s14");
    map(UC_ARM_REG_S15, "s15");
    map(UC_ARM_REG_S16, "s16");
    map(UC_ARM_REG_S17, "s17");
    map(UC_ARM_REG_S18, "s18");
    map(UC_ARM_REG_S19, "s19");
    map(UC_ARM_REG_S20, "s20");
    map(UC_ARM_REG_S21, "s21");
    map(UC_ARM_REG_S22, "s22");
    map(UC_ARM_REG_S23, "s23");
    map(UC_ARM_REG_S24, "s24");
    map(UC_ARM_REG_S25, "s25");
    map(UC_ARM_REG_S26, "s26");
    map(UC_ARM_REG_S27, "s27");
    map(UC_ARM_REG_S28, "s28");
    map(UC_ARM_REG_S29, "s29");
    map(UC_ARM_REG_S30, "s30");
    map(UC_ARM_REG_S31, "s31");
    // map(UC_ARM_REG_C1_C0_2, "c1_c0_2");
    // map(UC_ARM_REG_C13_C0_2, "c13_c0_2");
    // map(UC_ARM_REG_C13_C0_3, "c13_c0_3");
    // map(UC_ARM_REG_IPSR, "ipsr");
    // map(UC_ARM_REG_MSP, "msp");
    // map(UC_ARM_REG_PSP, "psp");
    // map(UC_ARM_REG_CONTROL, "control");

    // Registers missing from SLEIGH spec
    map(UC_ARM_REG_XPSR, "xpsr");
    map(UC_ARM_REG_OTHER_SP, "other_sp");
    map(UC_ARM_REG_CURR_SP_MODE_IS_PSP, "curr_sp_mode_is_psp");
    map(UC_ARM_REG_SPSEL, "spsel");
    map(UC_ARM_REG_BASEPRI, "basepri");
    map(UC_ARM_REG_PRIMASK, "primask");

    // These are aliases to other registers.
    // map(UC_ARM_REG_R13, "sp");
    // map(UC_ARM_REG_R14, "lr");
    // map(UC_ARM_REG_R15, "pc");
    // map(UC_ARM_REG_SB, "r9");
    // map(UC_ARM_REG_SL, "r10");
    // map(UC_ARM_REG_FP, "r11");
    // map(UC_ARM_REG_IP, "r12");

    vars
}
