use std::collections::HashMap;

use hashbrown::HashSet;
use icicle_vm::{
    cpu::{
        exec::const_eval::{self, Bit, BitVecExt, ConstEval, OutputExprId},
        lifter,
        mem::IoHandler,
        BlockGroup, Cpu, DecodeError,
    },
    BlockTable,
};

#[derive(Debug)]
pub enum Error {
    LifterError,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::LifterError => f.write_str("Error lifting child blocks"),
        }
    }
}

impl From<DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Self::LifterError
    }
}

pub struct LoadResizeInjector {
    resizer: LoadResizer,

    /// Controls whether a zero-extend and shift operation is injected when only the upper bits of
    /// an load are used.
    optimize_upper_bits: bool,

    /// A reference to the MMIO memory handler.
    mmio_ref: IoHandler,
}

impl LoadResizeInjector {
    pub fn new(mmio_ref: IoHandler, multiblock: bool, optimize_upper_bits: bool) -> Self {
        Self { mmio_ref, optimize_upper_bits, resizer: LoadResizer::new(multiblock) }
    }

    pub fn mark_as_temporary(&mut self, var: pcode::VarId) {
        self.resizer.state.extra_temps.insert(var);
    }
}

/// A code injector that allows the lifter to shrink the size of loads operations if the upper bits
/// are unused within basic blocks.
struct LoadResizer {
    /// State that keeps track of what is known at translation time.
    state: EvalState,

    /// Used for lifting blocks we have yet to reach yet to allow multiblock analysis.
    lifter: Option<LocalLifter>,
}

impl LoadResizer {
    fn new(multiblock: bool) -> Self {
        let lifter = multiblock.then(|| {
            let settings = lifter::Settings::default();
            let instruction_lifter = lifter::InstructionLifter::new();
            LocalLifter {
                code: icicle_vm::cpu::BlockTable::default(),
                lifter: lifter::BlockLifter::new(settings, instruction_lifter),
            }
        });
        Self { state: EvalState::default(), lifter }
    }

    fn compute_load_usage(
        &mut self,
        cpu: &mut Cpu,
        code: &BlockTable,
        block: usize,
    ) -> Result<(), Error> {
        self.state.reset();
        if let Some(lifter) = self.lifter.as_mut() {
            lifter.code.flush_code();
        }

        let current_block = &code.blocks[block];
        self.state.block = current_block.pcode.first_addr().unwrap_or(0);
        self.state.find_loads_and_uses(current_block, true);
        self.calculate_used_bits(cpu, code, current_block)
    }

    pub fn get_loads(
        &mut self,
        cpu: &mut Cpu,
        code: &BlockTable,
        block: usize,
    ) -> Result<Vec<(u64, LoadMetadata)>, Error> {
        self.compute_load_usage(cpu, code, block)?;

        let mut output = vec![];
        let pcode = &code.blocks[block].pcode;

        let mut current_pc = 0;
        for (idx, stmt) in pcode.instructions.iter().enumerate() {
            if stmt.op == pcode::Op::InstructionMarker {
                current_pc = stmt.inputs.first().as_u64();
            }

            if let Some(metadata) = self.state.loads.values().find(|x| x.offset == idx) {
                if metadata.required_bits() < stmt.output.size * 8 {
                    output.push((current_pc, metadata.clone()));
                }
            }
        }

        Ok(output)
    }

    /// Applies resize operations to all loads where upper bits are unused. Note: this approach is
    /// unable to remove unused low bits from the operation, to allow the starting address to
    /// always remains the same.
    pub fn resize_loads(
        &mut self,
        cpu: &mut Cpu,
        code: &mut BlockTable,
        block: usize,
    ) -> Result<bool, Error> {
        self.compute_load_usage(cpu, code, block)?;
        let pcode = &mut code.blocks[block].pcode;

        // Early exit if there are no loads to resize.
        if !self
            .state
            .loads
            .values()
            .any(|x| x.required_bytes() < pcode.instructions[x.offset].output.size)
        {
            return Ok(false);
        }

        let mut new_block = pcode::Block::new();
        pcode.recompute_next_tmp();
        new_block.next_tmp = pcode.next_tmp;

        let mut current_pc = 0;
        for (idx, stmt) in pcode.instructions.iter().enumerate() {
            if stmt.op == pcode::Op::InstructionMarker {
                current_pc = stmt.inputs.first().as_u64();
            }

            let Some(metadata) = self.state.loads.values().find(|x| x.offset == idx)
            else {
                new_block.push(*stmt);
                continue;
            };

            tracing::info!("[{current_pc:#x}] adjusting load",);
            push_with_resize(&mut new_block, *stmt, *metadata);
        }

        *pcode = new_block;

        Ok(true)
    }

    fn calculate_used_bits(
        &mut self,
        cpu: &mut Cpu,
        code: &BlockTable,
        from: &lifter::Block,
    ) -> Result<(), Error> {
        let Some(lifter) = self.lifter.as_mut()
        else {
            self.state.calculate_used_bits();
            return Ok(());
        };

        if let lifter::BlockExit::Branch {
            target: lifter::Target::External(pcode::Value::Const(target, _)),
            fallthrough: lifter::Target::External(pcode::Value::Const(fallthrough, _)),
            ..
        } = from.exit
        {
            let target = lifter.get_or_lift_block(cpu, code, from.context, target)?;

            // Fork evaluation state and evaluate uses in the target branch.
            let mut fork = self.state.clone();
            fork.find_loads_and_uses(&target, false);
            fork.calculate_used_bits();

            let fallthrough = lifter.get_or_lift_block(cpu, code, from.context, fallthrough)?;

            // Evaluate uses in the fallthrough from the current branch.
            self.state.find_loads_and_uses(&fallthrough, false);
            self.state.calculate_used_bits();

            self.state.merge(&fork);
        }
        else {
            self.state.calculate_used_bits();
        }

        Ok(())
    }
}

/// Pushes the resized version of `stmt` to `block`.
fn push_with_resize(block: &mut pcode::Block, stmt: pcode::Instruction, metadata: LoadMetadata) {
    let output = stmt.output;
    let new_size = metadata.required_bytes();
    if new_size == 0 {
        // If there were any loads that ended up zero bytes in size, then we replace them
        // with a copy from a constant. However, emit warning since this could be an
        // indicator of an error.
        tracing::warn!("removed zero sized load");
        block.push(pcode::Value::Const(0, output.size).copy_to(output));
    }
    else if output.size > new_size {
        tracing::info!(
            "adjusting load {stmt:?}: {} -> {new_size} (bits: {}..={})",
            output.size,
            metadata.min_bit,
            metadata.max_bit,
        );
        // Replace the old load, with a load to a smaller temporary.
        let tmp = block.alloc_tmp(new_size);
        block.push((tmp, stmt.op, stmt.inputs));
        // Copy a zero extended value to the correct destination.
        block.push((output, pcode::Op::ZeroExtend, tmp));
    }
    else {
        // Load was unmodified.
        block.push(stmt);
    }
}

struct LocalLifter {
    code: icicle_vm::cpu::BlockTable,
    lifter: lifter::BlockLifter,
}

impl LocalLifter {
    /// Attempts to get the block at `target` from `code` or lifts it if it doesn't exist.
    fn get_or_lift_block<'a>(
        &'a mut self,
        cpu: &mut Cpu,
        _code: &'a BlockTable,
        ctx: u64,
        vaddr: u64,
    ) -> Result<&'a lifter::Block, Error> {
        #[cfg(not(test))]
        {
            let target = self.lift_block(cpu, ctx, vaddr)?;
            Ok(&self.code.blocks[target.blocks.0])
        }

        // There is a chance that the pcode in `code.map` is different from a fresh lift (e.g., from
        // instrumentation or optimizations). Since the `code.map` may be initialized differently
        // depending on the path the fuzzer takes this could cause discrepancies during replay, so
        // for now we just pay the extra overhead of lifting the block again.
        #[cfg(test)]
        match _code.map.get(&icicle_vm::cpu::BlockKey { vaddr, isa_mode: cpu.isa_mode() as u64 }) {
            Some(target) => Ok(&_code.blocks[target.blocks.0]),
            None => {
                let target = self.lift_block(cpu, ctx, vaddr)?;
                Ok(&self.code.blocks[target.blocks.0])
            }
        }
    }

    fn lift_block(&mut self, cpu: &mut Cpu, ctx: u64, target: u64) -> Result<BlockGroup, Error> {
        self.lifter.set_context(ctx);
        Ok(self.lifter.lift_block(&mut lifter::Context::new(cpu, &mut self.code, target))?)
    }
}

#[derive(Default, Clone)]
pub struct EvalState {
    /// Extra varnodes consider to be temporaries
    extra_temps: HashSet<pcode::VarId>,

    /// Constant evaluator used for determinine which bits are statically known to be used/unused.
    const_eval: ConstEval,

    /// Keeps track of all the expressions that load bits from memory.
    loads: HashMap<OutputExprId, LoadMetadata>,

    /// A mapping from the output of a statement (indexed by ID in the const evaluation state) to
    /// both direct and indirect uses of bits that originate from memory loads.
    uses: HashMap<OutputExprId, HashMap<OutputExprId, Use>>,

    /// Address of the block we are evaluating (for debugging).
    block: u64,
}

impl EvalState {
    fn reset(&mut self) {
        self.const_eval.clear();
        self.loads.clear();
        self.uses.clear();
        self.block = 0;
    }

    /// Track any bits in `value` that originate from load expressions.
    fn add_usage(&mut self, dst: OutputExprId, has_side_effects: bool, value: &[Bit]) {
        for bit in value {
            self.add_bit_use(dst, has_side_effects, *bit);
        }
    }

    /// Tracks a usage of `bit` as part of the expression at `dst`.
    fn add_bit_use(&mut self, dst: OutputExprId, has_side_effects: bool, bit: Bit) {
        let Bit::Expr(expr) = bit
        else {
            return;
        };

        if self.loads.contains_key(&expr.id) {
            // Handle direct usages of loads.
            let for_expr = self.uses.entry(dst).or_default();
            let for_load = for_expr.entry(expr.id).or_default();
            for_load.update(expr.offset, has_side_effects);
        }
        else if let Some(usage) = self.uses.get(&expr.id) {
            // Handle indirect usages of loads.
            let prev_usage = usage.clone();
            let for_expr = self.uses.entry(dst).or_default();
            for (load_expr_id, prev_use) in prev_usage {
                let for_load = for_expr.entry(load_expr_id).or_default();
                for_load.has_side_effect |= has_side_effects;
                // Since this usage was not constant propagated back to the original load, we
                // conservatively assume that this bit may depend on any of the bits loaded in the
                // previous use.
                for_load.max_bit = for_load.max_bit.max(prev_use.max_bit);
                for_load.min_bit = for_load.min_bit.min(prev_use.min_bit);
            }
        }
    }

    /// Returns the number of bits we need from `load` to compute `var`.
    fn get_used_bits(&self, value: const_eval::Value, load: OutputExprId) -> (u8, u8) {
        let mut min_bit = u128::BITS as u8;
        let mut max_bit = 0;
        for bit in value.slice() {
            let Bit::Expr(expr) = bit
            else {
                continue;
            };
            if self.loads.contains_key(&expr.id) {
                max_bit = max_bit.max(expr.offset);
                min_bit = min_bit.min(expr.offset);
            }
            else if let Some(indirect_use) = self.uses.get(&expr.id).and_then(|x| x.get(&load)) {
                max_bit = max_bit.max(indirect_use.max_bit);
                min_bit = min_bit.min(indirect_use.min_bit);
            }
        }
        (min_bit, max_bit)
    }

    fn find_loads_and_uses(&mut self, block: &lifter::Block, track_loads: bool) {
        for (i, stmt) in block.pcode.instructions.iter().enumerate() {
            let inputs = stmt.inputs.get();

            let arg1 = self.const_eval.get_value(inputs[0]);
            let arg2 = self.const_eval.get_value(inputs[1]);

            let dst_expr = self.const_eval.eval(*stmt);
            let has_side_effects = stmt.op.has_side_effects();

            let (used_arg1, used_arg2) = resize_used_bits(stmt.op, arg1.slice(), arg2.slice());

            self.add_usage(dst_expr, has_side_effects, used_arg1);
            self.add_usage(dst_expr, has_side_effects, used_arg2);

            if track_loads && matches!(stmt.op, pcode::Op::Load(_)) {
                // Start add metadata indicating that no bits have been used for this load yet.
                self.loads.insert(dst_expr, LoadMetadata {
                    offset: i,
                    min_bit: (stmt.output.size * 8) - 1,
                    max_bit: 0,
                });
                // Make sure we keep track of `dst_expr` as a full use of the load (if `dst_expr`
                // lives outside the block).
                self.uses.entry(dst_expr).or_default().insert(dst_expr, Use {
                    has_side_effect: false,
                    min_bit: 0,
                    max_bit: (stmt.output.size * 8) - 1,
                });
            }
        }

        let exit = block.exit;
        let expr_id = self.const_eval.eval(exit.to_pcode());
        for target in exit.targets() {
            if let lifter::Target::External(val) = target {
                let val = self.const_eval.get_value(val);
                self.add_usage(expr_id, true, val.slice());
            }
        }

        // Keep track of uses that appear in the block exit conditions or destinations.
        if let Some(cond) = exit.cond() {
            let cond = self.const_eval.get_value(cond);
            self.add_usage(expr_id, true, cond.slice());
        }
    }

    /// Determine the maximum number of bits that persist for every load.
    fn calculate_used_bits(&mut self) {
        for (use_expr_id, used_loads) in &self.uses {
            let out_var = self.const_eval.get_output_of(*use_expr_id);
            for (&load_expr, load_use) in used_loads {
                // For ops with side effects, treat all bits as used.
                if load_use.has_side_effect {
                    self.loads.get_mut(&load_expr).unwrap().add_use(load_use);
                    continue;
                }

                // Ignore bits that only exist in temporaries.
                if out_var.is_temp() || self.extra_temps.contains(&out_var.id) {
                    continue;
                }

                // Check that the final value of the non-temporary variable still contains bits from
                // a load operation.
                let value = self.const_eval.get_value(out_var.into());
                let (min_bit, max_bit) = self.get_used_bits(value.clone(), load_expr);

                let entry = self.loads.get_mut(&load_expr).unwrap();
                entry.min_bit = entry.min_bit.min(min_bit);
                entry.max_bit = entry.max_bit.max(max_bit);
            }
        }
    }

    fn merge(&mut self, fork: &EvalState) {
        for (src, metadata) in &fork.loads {
            match self.loads.entry(*src) {
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    slot.get_mut().max_bit = slot.get_mut().max_bit.max(metadata.max_bit);
                    slot.get_mut().min_bit = slot.get_mut().min_bit.min(metadata.min_bit);
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(*metadata);
                }
            }
        }
    }
}

/// Removes upper bits from `a` and `b` for operations with partial constants.
///
/// Handles cases like:
///
/// ```pcode
///     value:4 = load(value_addr)
///     mask:1 = load(mask_addr);
///     mask_zxt:4 = zext(mask);
///     output = value & mask_zxt;
/// ```
fn resize_used_bits<'a, 'b>(op: pcode::Op, a: &'a [Bit], b: &'b [Bit]) -> (&'a [Bit], &'b [Bit]) {
    /// We didn't support this in the original implementation, so this flag can be set to enable
    /// compatability with old traces.
    const SKIP_AND_USAGE_ADJUSTMENT: bool = false;
    if SKIP_AND_USAGE_ADJUSTMENT {
        return (a, b);
    }

    match op {
        pcode::Op::IntAnd => {
            let a_zeros = a.known_leading_zeros();
            let b_zeros = b.known_leading_zeros();
            (&a[..a.len() - b_zeros], &b[..b.len() - a_zeros])
        }

        // TODO: add additional operations (e.g., IntOr with upper ones, Bool* operations, shift
        // operations).
        _ => (a, b),
    }
}

impl icicle_vm::CodeInjector for LoadResizeInjector {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        for block in group.blocks.0..group.blocks.1 {
            if !self.optimize_upper_bits {
                // Directly resize the underlying load pcode ops.
                if let Err(e) = self.resizer.resize_loads(cpu, code, block) {
                    tracing::warn!("[{:#x}] failed to resize load ops: {e}", group.start);
                }
            }
            else {
                // Apply resize operations as models.
                match self.resizer.get_loads(cpu, code, block) {
                    Ok(metadata) => {
                        let mem = cpu
                            .mem
                            .get_io_memory_mut(self.mmio_ref)
                            .as_mut_any()
                            .downcast_mut::<crate::input::MultiStreamMmio>()
                            .unwrap();

                        for (pc, load) in metadata {
                            mem.add_extract_model(pc, load.min_bit, load.max_bit)
                        }
                    }
                    Err(e) => tracing::warn!("[{:#x}] failed to resize load ops: {e}", group.start),
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct LoadMetadata {
    /// The offset of the load expression in the pcode array.
    offset: usize,
    /// The minimum bit of the load that persists outside of the current block.
    min_bit: u8,
    /// The maximum bit of the load that persists outside of the current block.
    max_bit: u8,
}

impl LoadMetadata {
    fn add_use(&mut self, new_use: &Use) {
        self.min_bit = self.min_bit.min(new_use.min_bit);
        self.max_bit = self.max_bit.max(new_use.max_bit);
    }

    /// Return the amount of bytes required for the load operation (Note: we do not allow the
    /// starting address of the load to be adjusted, and require the size to be a power of 2).
    fn required_bytes(&self) -> u8 {
        if self.max_bit < self.min_bit {
            // No bits are used.
            return 0;
        }
        let required_bits = self.max_bit + 1;
        (required_bits.next_power_of_two() / 8).max(1)
    }

    fn required_bits(&self) -> u8 {
        if self.max_bit < self.min_bit {
            return 0;
        }
        self.max_bit - self.min_bit + 1
    }
}

#[derive(Debug, Copy, Clone)]
struct Use {
    has_side_effect: bool,
    min_bit: u8,
    max_bit: u8,
}

impl Default for Use {
    fn default() -> Self {
        Self { has_side_effect: false, min_bit: u128::BITS as u8 - 1, max_bit: 0 }
    }
}

impl Use {
    fn update(&mut self, bit: u8, has_side_effect: bool) {
        self.has_side_effect |= has_side_effect;
        self.min_bit = self.min_bit.min(bit);
        self.max_bit = self.max_bit.max(bit);
    }
}

#[cfg(test)]
fn check(pcode: pcode::Block, load_offset: usize, resize: Option<(u8, u8)>) {
    use pcode::PcodeDisplay;

    let sleigh = sleigh_runtime::SleighData::default();
    for (i, entry) in pcode.instructions.iter().enumerate() {
        eprintln!("[{i}] {}", entry.display(&sleigh));
    }

    let mut code = BlockTable::default();
    code.blocks.push(icicle_vm::cpu::lifter::Block {
        pcode,
        entry: None,
        start: 0x0,
        end: 0x0,
        context: 0x0,
        exit: lifter::BlockExit::invalid(),
        breakpoints: 0x0,
        num_instructions: 0x1,
    });

    let mut cpu = Cpu::new_boxed(icicle_vm::cpu::Arch::none());
    let mut resizer = LoadResizer::new(false);
    let loads = resizer.get_loads(&mut cpu, &code, 0).unwrap();

    if let Some((min_bit, max_bit)) = resize {
        assert_eq!(&loads, &[(0, LoadMetadata { offset: load_offset, min_bit, max_bit })]);
    }
    else {
        assert_eq!(&loads, &[]);
    }
}

#[cfg(test)]
fn check_multiblock(blocks: [pcode::Block; 3], load_offset: usize, resize: Option<(u8, u8)>) {
    use icicle_vm::cpu::BlockKey;
    use pcode::PcodeDisplay;

    let sleigh = sleigh_runtime::SleighData::default();
    for (block_id, block) in blocks.iter().enumerate() {
        eprintln!("{block_id}:");
        for (i, entry) in block.instructions.iter().enumerate() {
            eprintln!("[{i}] {}", entry.display(&sleigh));
        }
        eprintln!("");
    }

    let [parent, fallthrough, jump] = blocks;

    let mut code = BlockTable::default();
    code.blocks.push(icicle_vm::cpu::lifter::Block {
        pcode: parent,
        entry: None,
        start: 0x0,
        end: 0x0,
        context: 0x0,
        exit: lifter::BlockExit::new(
            pcode::VarNode::new(0x1000, 1).into(),
            lifter::Target::External(0x2.into()),
            lifter::Target::External(0x1.into()),
        ),
        breakpoints: 0x0,
        num_instructions: 0x1,
    });
    code.map.insert(BlockKey { vaddr: 0x1, isa_mode: 0 }, BlockGroup {
        blocks: (1, 2),
        start: 0x1,
        end: 0x2,
    });
    code.blocks.push(icicle_vm::cpu::lifter::Block {
        pcode: fallthrough,
        entry: None,
        start: 0x1,
        end: 0x0,
        context: 0x0,
        exit: lifter::BlockExit::invalid(),
        breakpoints: 0x0,
        num_instructions: 0x1,
    });
    code.map.insert(BlockKey { vaddr: 0x2, isa_mode: 0 }, BlockGroup {
        blocks: (2, 3),
        start: 0x2,
        end: 0x3,
    });
    code.blocks.push(icicle_vm::cpu::lifter::Block {
        pcode: jump,
        entry: None,
        start: 0x2,
        end: 0x0,
        context: 0x0,
        exit: lifter::BlockExit::invalid(),
        breakpoints: 0x0,
        num_instructions: 0x1,
    });

    let mut cpu = Cpu::new_boxed(icicle_vm::cpu::Arch::none());
    let mut resizer = LoadResizer::new(true);
    let loads = resizer.get_loads(&mut cpu, &code, 0).unwrap();

    if let Some((min_bit, max_bit)) = resize {
        assert_eq!(&loads, &[(0, LoadMetadata { offset: load_offset, min_bit, max_bit })]);
    }
    else {
        assert_eq!(&loads, &[]);
    }
}

#[test]
fn test_used() {
    let mut block = pcode::Block::new();
    let reg = pcode::VarNode::new(1, 2);
    block.push((reg, pcode::Op::Load(0), 0x1000));
    // If all bits of the load are used then we must keep the original load size.
    check(block, 0, None);
}

#[test]
fn test_unused() {
    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(2);
    block.push((tmp, pcode::Op::Load(0), 0x1000));
    // If the load is never used, then set load size to 0.
    check(block, 0, Some((15, 0)));
}

#[test]
fn test_low_bits() {
    let reg = pcode::VarNode::new(1, 2);

    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(2);
    block.push((tmp, pcode::Op::Load(0), 0x1000));
    block.push((reg, pcode::Op::Copy, tmp));

    let tmp2 = block.alloc_tmp(1);
    block.push((tmp2, pcode::Op::Copy, reg.slice(0, 1)));
    block.push((reg, pcode::Op::ZeroExtend, tmp2));

    // If only the low bits are used, then adjust the load size.
    check(block, 0, Some((0, 7)));
}

#[test]
fn test_lowest_bit() {
    let reg = pcode::VarNode::new(1, 2);

    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(2);
    block.push((tmp, pcode::Op::Load(0), 0x1000));
    block.push((reg, pcode::Op::IntAnd, (tmp, 1_u16)));
    check(block, 0, Some((0, 0)));
}

#[test]
fn test_high_bits() {
    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(2);
    block.push((tmp, pcode::Op::Load(0), 0x1000));
    let tmp2 = block.alloc_tmp(1);
    block.push((tmp2, pcode::Op::Copy, tmp.slice(1, 1)));
    let reg = pcode::VarNode::new(1, 2);
    block.push((reg, pcode::Op::ZeroExtend, tmp2));

    // If only the high bits are used then check that we support a zero-extend and shift.
    check(block, 0, Some((8, 15)));
}

#[test]
fn test_shift_and_slt() {
    let reg = pcode::VarNode::new(1, 1);

    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(4);
    block.push((tmp, pcode::Op::Load(0), 0x1000));

    // Common pattern on THUMB is to check a particular bit by shifting it to the sign-bit and
    // checking if the value is less than zero.
    block.push((tmp, pcode::Op::IntLeft, tmp, 21));
    block.push((reg, pcode::Op::IntSignedLess, (tmp, 0)));

    check(block, 0, Some((10, 10)));
}

#[test]
fn test_branch() {
    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(8);
    block.push((tmp, pcode::Op::Load(0), 0x1000));
    block.push((pcode::Op::Branch(pcode::BranchHint::Call), (1_u8, tmp)));

    // Need all bits for a call/branch operation.
    check(block, 0, None);
}

#[test]
fn test_branch_with_tmps() {
    let r1 = pcode::VarNode::new(1, 8);

    let mut block = pcode::Block::new();
    let load_addr_tmp = block.alloc_tmp(8);
    block.push((load_addr_tmp, pcode::Op::IntAdd, (r1, 0x10_u64)));

    let result_tmp = block.alloc_tmp(4);
    block.push((result_tmp, pcode::Op::Load(0), load_addr_tmp));

    block.push((r1, pcode::Op::IntSub, (r1, 1_u64)));

    block.push((pcode::Op::Branch(pcode::BranchHint::Call), (1_u8, result_tmp)));

    // Need all bits for a call/branch operation.
    check(block, 1, None);
}

#[test]
fn with_right_shift() {
    let r1 = pcode::VarNode::new(1, 8);
    let r2 = pcode::VarNode::new(2, 8);

    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(8);
    block.push((tmp, pcode::Op::Load(0), 0x1000));

    block.push((r2, pcode::Op::IntRight, (tmp, r1)));
    check(block, 0, None);
}

#[test]
fn with_left_shift() {
    let r1 = pcode::VarNode::new(1, 4);

    let mut block = pcode::Block::new();
    block.push((r1, pcode::Op::Load(0), 0x1000));
    block.push((r1, pcode::Op::IntLeft, (r1, 0x18)));
    check(block, 0, Some((0, 7)));
}

#[test]
fn with_bool_op() {
    let r1 = pcode::VarNode::new(1, 4);
    let r2 = pcode::VarNode::new(1, 4);
    let r3 = pcode::VarNode::new(1, 1);

    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(4);
    block.push((tmp, pcode::Op::Load(0), 0x1000));
    let tmp2 = block.alloc_tmp(4);
    block.push((tmp2, pcode::Op::IntRight, (tmp, r1)));
    block.push((r3, pcode::Op::IntEqual, (tmp2, r2)));
    check(block, 0, None);
}

#[test]
fn test_with_store() {
    let reg = pcode::VarNode::new(1, 2);

    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(2);
    block.push((tmp, pcode::Op::Load(0), 0x1000));
    block.push((reg, pcode::Op::IntAnd, (tmp, 1_u16)));

    let bool_out = block.alloc_tmp(1);
    block.push((bool_out, pcode::Op::IntSignedLess, (reg, 0_u16)));
    block.push((bool_out, pcode::Op::IntEqual, (reg, 0_u16)));

    block.push((pcode::Op::Store(0), (0x2000, reg)));
    check(block, 0, Some((0, 0)));
}

#[test]
fn test_load_of_load() {
    let reg = pcode::VarNode::new(1, 2);

    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(2);
    block.push((tmp, pcode::Op::Load(0), 0x1000));
    block.push((reg, pcode::Op::Load(0), tmp));

    check(block, 0, None);
}

#[test]
fn test_with_zxt_and() {
    let reg = pcode::VarNode::new(1, 2);

    let mut block = pcode::Block::new();
    let tmp = block.alloc_tmp(2);
    block.push((tmp, pcode::Op::Load(0), 0x1000));

    let mask = block.alloc_tmp(1);
    block.push((mask, pcode::Op::Load(0), 0x2000));
    let zxt_mask = block.alloc_tmp(2);
    block.push((zxt_mask, pcode::Op::ZeroExtend, mask));

    block.push((reg, pcode::Op::IntAnd, (tmp, zxt_mask)));

    check(block, 0, Some((0, 7)));
}

#[test]
fn test_multiblock() {
    let reg = pcode::VarNode::new(1, 2);

    let mut block1 = pcode::Block::new();
    block1.push((reg, pcode::Op::Load(0), 0x1000));

    // Load cannot be resized just looking at the current block.
    check(block1.clone(), 0, None);

    let mut block2 = pcode::Block::new();
    block2.push((reg, pcode::Op::Copy, 0xaa_u16));

    let mut block3 = pcode::Block::new();
    block3.push((reg, pcode::Op::Copy, 0xaa_u16));

    // Modified by both so can be successfully resized.
    check_multiblock([block1.clone(), block2.clone(), block3], 0, Some((15, 0)));

    // Does not overwrite reg.
    let block4 = pcode::Block::new();

    // Modified in only one block (cannot be resized).
    check_multiblock([block1.clone(), block2.clone(), block4.clone()], 0, None);
    check_multiblock([block1.clone(), block4.clone(), block2.clone()], 0, None);
}
