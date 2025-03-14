use std::{
    ops::Range,
    path::{Path, PathBuf},
};

use anyhow::Context;
use indexmap::IndexMap;
use object::{
    read::elf::{FileHeader, ProgramHeader, SectionHeader},
    Endianness, Object, ObjectSection, ObjectSymbol,
};

use crate::config::{
    cortexm_memory_map, FirmwareConfig, Memory, Permissions, TriggerKind, TriggerMode,
};

pub fn generate_and_save(path: &Path, force: bool) -> anyhow::Result<()> {
    let mut path = path.to_path_buf();

    // If path a directory, then look for an elf file in the target directory.
    if path.is_dir() {
        path = find_elf_in_dir(&path)?;
    }

    let parent_dir = path.parent().ok_or_else(|| {
        anyhow::format_err!("unable to determine directory to save config for: {}", path.display())
    })?;
    let config_file = parent_dir.join("config.yml");

    if config_file.exists() && !force {
        tracing::warn!("{} already exists, skipping config generation.", config_file.display());
        return Ok(());
    }

    // Keep track of whether we think this is a config file for better error messages.
    let is_likely_config_file = path
        .file_name()
        .and_then(|x| x.to_str())
        .map_or(false, |name| name.contains("config") || name.ends_with(".yml"));

    let config = from_elf(&path).with_context(|| {
        let help =
            if is_likely_config_file { " (input looks like an existing config)" } else { "" };
        format!("error generating config for: {}{help}", path.display())
    })?;

    let file = match force {
        true => std::fs::File::create(&config_file),
        false => {
            std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&config_file)
        }
    };

    let mut writer = std::io::BufWriter::new(
        file.with_context(|| format!("failed to create: {}", config_file.display()))?,
    );
    serialize_firmware_config_yml(&mut writer, &config)
        .with_context(|| format!("error serializing config: {}", config_file.display()))?;

    Ok(())
}

fn find_elf_in_dir(dir: &Path) -> anyhow::Result<PathBuf> {
    let mut found_path = None;
    for entry in
        dir.read_dir().with_context(|| format!("error reading directory: {}", dir.display()))?
    {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }

        let child_path = entry.path();
        // If the file either has no extension, or ends with `.elf or `.out` or something
        // unparsable then assume it is the fiel we are looking for (unless we find
        // something better in the same directory).
        match child_path.extension().map(|x| x.to_str()) {
            Some(Some(ext)) => {
                if ext.ends_with("elf") {
                    // Return immediately if the file ends with `.elf` since this is probably what
                    // we are looking for.
                    return Ok(child_path);
                }
                else if ext.ends_with("out") {
                    found_path = Some(child_path);
                }
            }
            _ => found_path = Some(child_path),
        }
    }

    found_path.ok_or_else(|| anyhow::format_err!("failed to find ELF file in: {}", dir.display()))
}

const KNOWN_IVT_SYMBOLS: &[&str] = &["_vector_table", "_vector_start", "cortex_vector_base"];

/// Attempts to generate a Fuzzware compatible config file from an ELF binary.
///
/// Note: Unlike the original Fuzzware implementation, we rely entirely on the information included
/// in the ELF file. We never attempt to manually identify sections.
pub fn from_elf(path: &Path) -> anyhow::Result<FirmwareConfig> {
    let data = std::fs::read(path)?;

    // TODO: we parse the binary as a generic file, just to find names of sections we could avoid
    // this by directly getting names specialized reader.
    let obj_file = object::File::parse(data.as_slice())?;

    let elf = object::elf::FileHeader32::<Endianness>::parse(data.as_slice())?;
    let endian = elf.endian()?;

    let file_name = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow::format_err!("unable to extract file name"))?;

    // Start with initial cortexm memory map.
    let mut memory = cortexm_memory_map();
    let ram_range = memory.get("ram").map(|x| (x.base_addr..x.base_addr + x.size));

    for section in obj_file.sections() {
        tracing::info!(
            "section \"{}\" address={:#x} size={:#x}",
            section.name()?,
            section.address(),
            section.size()
        );
    }

    // Determine what needs to be loaded by inspecting program headers
    let program_headers = elf.program_headers(endian, data.as_slice())?;

    for (idx, segment) in program_headers.into_iter().enumerate() {
        if segment.p_type(endian) != object::elf::PT_LOAD {
            continue;
        }

        let p_flags = segment.p_flags(endian);
        let base_addr = segment.p_paddr(endian) as u64;
        let vaddr = segment.p_vaddr(endian) as u64;
        let in_memory_size = segment.p_memsz(endian) as u64;

        // Find a name to use for the segment by looking at section headers (note: segments don't
        // have a name for ELF files).
        let range = vaddr..vaddr + in_memory_size.max(1);
        let mut name =
            find_section_name(&obj_file, range).unwrap_or_else(|| format!("memory_{base_addr:#x}"));

        if let Some(suffix) = name.strip_prefix(".") {
            name = suffix.into();
        }

        tracing::info!(
            "PL_LOAD base_addr={base_addr:#x} (vaddr={vaddr:#x}) size={in_memory_size:#x} (name={name})"
        );

        if in_memory_size == 0 {
            tracing::debug!("ignoring zero sized segment: Idx={idx}: {base_addr:#x} ({name})");
            continue;
        }

        // Ignore sections that overlap with RAM
        if let Some(range) = ram_range.as_ref() {
            if range.contains(&base_addr) {
                tracing::warn!("ignoring RAM segment: Idx={idx}: {base_addr:#x} ({name})");
                continue;
            }
        }

        // Check if this was assigned the same name as a previous section.
        if memory.contains_key(&name) {
            name.push_str(&format!("_{:#x}", base_addr));
        }

        let (file, (file_offset, file_size)) = match segment.file_range(endian) {
            (_, 0) => (None, (0, 0)), // uninitialized data
            range => (Some(file_name.to_string()), range),
        };

        let readable = (p_flags & object::elf::PF_R) != 0;
        let writable = (p_flags & object::elf::PF_W) != 0;
        let executable = (p_flags & object::elf::PF_X) != 0;

        let mem_end = base_addr + in_memory_size;
        // Check if the newly added memory mapping overlaps with an existing memory region.
        if let Some((existing_name, existing)) = memory.iter_mut().find(|(_, mem)| {
            let existing_start = mem.base_addr;
            let existing_end = mem.base_addr + mem.size;
            base_addr < existing_end && existing_start < mem_end
        }) {
            tracing::warn!("Section {name} overlaps with {existing_name} (automatically merging)");
            existing.base_addr = existing.base_addr.min(base_addr);
            existing.size = existing.memory_range().end.max(mem_end) - existing.base_addr
        }
        else {
            memory.insert(name, Memory {
                base_addr,
                permissions: Permissions::new(readable, writable, executable),
                size: in_memory_size,
                file,
                file_offset,
                file_size: Some(file_size),
                is_entry: false,
                ivt_offset: None,
                fill: None,
            });
        }
    }

    // Attempt to identify the MCU model to avoid needing to edit the config for some well known
    // targets.
    let mut is_nrf_target = false;
    let mut is_stm32_target = false;

    let mut found_ivt = false;
    let mut symbols = IndexMap::new();
    let mut handlers = IndexMap::new();
    for sym in obj_file.symbols() {
        let name = sym.name()?;
        if name.contains("nrf5") || name.contains("NRF5") || name == "ftpan_32" {
            is_nrf_target = true;
        }
        if name.contains("stm32") || name.contains("STM32") {
            is_stm32_target = true;
        }

        if KNOWN_IVT_SYMBOLS.contains(&name) {
            let address = sym.address();
            if let Some((_, ivt_section)) =
                memory.iter_mut().find(|(_, info)| info.memory_range().contains(&address))
            {
                found_ivt = true;
                ivt_section.is_entry = true;
                ivt_section.ivt_offset = Some(address - ivt_section.base_addr);
            }
        }

        if !name.starts_with("$") && !name.starts_with(".L") {
            symbols.insert(sym.address(), name.to_owned());
        }

        // Check if the current binary has an panic handler (Rust binaries), if so, mark the address
        // as a crashing address.
        if name == "rust_begin_unwind" {
            handlers.insert(name.to_owned(), Some("crash".to_owned()));
        }
    }

    if !found_ivt {
        // Try to infer IVT location from the .text section.
        if let Some(text_section) = elf.section_headers(endian, data.as_slice())?.iter().find(|x| {
            match x.strings(endian, data.as_slice()) {
                Ok(Some(strings)) => x.name(endian, strings).map_or(false, |x| x == b".text"),
                _ => false,
            }
        }) {
            let text_addr = text_section.sh_addr(endian) as u64;
            let ivt_section = memory
                .values_mut()
                .find(|info| info.memory_range().contains(&text_addr))
                .ok_or_else(|| {
                    anyhow::format_err!("Failed to find section containing entry point")
                })?;
            ivt_section.is_entry = true;
            ivt_section.ivt_offset = Some(text_addr.saturating_sub(ivt_section.base_addr));
        }
        else {
            // Try to find a region containing the program entry point.
            let entry_point = (elf.e_entry.get(endian) & !1) as u64;
            let ivt_section = memory
                .values_mut()
                .find(|info| info.memory_range().contains(&entry_point))
                .ok_or_else(|| {
                    anyhow::format_err!("Failed to find section containing entry point")
                })?;
            ivt_section.is_entry = true;
            ivt_section.ivt_offset = Some(0);
        }
    };

    if is_nrf_target {
        memory.insert(
            "nrf_registers".into(),
            Memory::new(0xf0000000, 0x1000, "rw-".parse().unwrap()),
        );
    }
    if is_stm32_target {
        memory.insert(
            "stm32_uid_regs".into(),
            Memory::new(0x1ffff000, 0x1000, "rw-".parse().unwrap()),
        );
    }

    Ok(FirmwareConfig { memory_map: memory, symbols, handlers, ..FirmwareConfig::default() })
}

fn find_section_name(obj_file: &object::File, range: Range<u64>) -> Option<String> {
    let section = obj_file
        .sections()
        .filter(|section| section.size() != 0)
        .find(|x| range.contains(&x.address()))?;
    section.name().ok().map(|x| x.to_owned())
}

/// Manually serializes a firmware configuration to allow for more human readable formatting.
///
/// Note: This does not currently support all configuration options.
fn serialize_firmware_config_yml<W: std::io::Write>(
    out: &mut W,
    config: &FirmwareConfig,
) -> std::io::Result<()> {
    // Write global configuration options if they are not set to the default value.
    macro_rules! write_if_changed {
        ($field:ident, $default:expr) => {{
            if config.$field != $default {
                writeln!(out, "{}: {}", stringify!($field), config.$field)?;
            }
        }};
    }
    write_if_changed!(use_nvic, true);
    write_if_changed!(use_systick, true);
    write_if_changed!(global_timer_scale, 1);
    write_if_changed!(fuzz_consumption_timeout, 150000);
    write_if_changed!(instr_limit, 30000000);

    if let Some(entry_point) = config.entry_point {
        writeln!(out, "entry_point: 0x{entry_point:x}")?;
    }

    writeln!(out, "interrupt_triggers:")?;
    for (name, value) in &config.interrupt_triggers {
        writeln!(out, "  {name}:")?;
        match &value.mode {
            TriggerMode::Addr(sym) => writeln!(out, "    addr: {sym}")?,
            TriggerMode::EveryNthTick(tick) => writeln!(out, "    every_nth_tick: {tick}")?,
        }
        match &value.kind {
            TriggerKind::Fixed { irq } => writeln!(out, "    irq: {irq}")?,
            TriggerKind::Dynamic { fuzz_mode } => writeln!(out, "    fuzz_mode: {fuzz_mode}")?,
        }
    }

    writeln!(out, "memory_map:")?;
    for (name, value) in &config.memory_map {
        writeln!(out, "  {name}:")?;
        if value.is_entry {
            writeln!(out, "    is_entry: true")?;
        }
        writeln!(out, "    base_addr: 0x{:08x}", value.base_addr)?;
        writeln!(out, "    permissions: {}", value.permissions.to_str())?;
        writeln!(out, "    size: 0x{:x}", value.size)?;

        if let Some(file) = &value.file {
            writeln!(out, "    file: {file}")?;
            if value.file_offset != 0 {
                writeln!(out, "    file_offset: 0x{:x}", value.file_offset)?;
            }
            if let Some(size) = value.file_size {
                writeln!(out, "    file_size: 0x{size:x}")?;
            }
        }

        if let Some(ivt_offset) = value.ivt_offset {
            writeln!(out, "    ivt_offset: 0x{ivt_offset:x}")?;
        }
    }

    writeln!(out, "symbols:")?;
    for (address, name) in &config.symbols {
        writeln!(out, "  0x{address:08x}: {name}")?;
    }

    Ok(())
}
