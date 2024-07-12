use std::path::PathBuf;

use anyhow::Context;
use icicle_vm::cpu::mem::perm;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::fuzzware;

fn default_true() -> bool {
    true
}

fn default_global_timer_scale() -> u32 {
    1
}

fn default_fuzz_consumption_timeout() -> u64 {
    150000
}

fn default_instr_limit() -> u64 {
    3000_0000
}

fn default_interrupt_trigger() -> IndexMap<String, Trigger> {
    [("trigger".into(), Trigger {
        mode: TriggerMode::EveryNthTick(Tick::Number(1000)),
        kind: TriggerKind::Dynamic { fuzz_mode: FuzzMode::Fuzzed },
    })]
    .into_iter()
    .collect()
}

/// Fuzzware configuration (Fuzzware compatible with extensions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareConfig {
    /// The path to the config file. Used for reading other files relative to the config path.
    #[serde(skip)]
    pub path: PathBuf,

    /// A manually configured entry point to use for the target. If none is provided it will be
    /// loaded from the interrupt vector of the memory section listed as the entry section.
    pub entry_point: Option<u32>,

    /// Controls how interrupts are triggered by the emulator.
    #[serde(default = "default_interrupt_trigger")]
    pub interrupt_triggers: IndexMap<String, Trigger>,

    /// The memory map for the target.
    pub memory_map: IndexMap<String, Memory>,

    /// Use include PC in lookups for for mmio handlers.
    #[serde(default)]
    pub use_access_contexts: bool,

    /// Fuzzware models for peripheral accesses.
    #[serde(default)]
    pub mmio_models: MmioModels,

    /// Controls NVIC behavior.
    #[serde(default)]
    pub nvic: Nvic,

    /// Controls whether the NVIC is fully disabled. If disabled, interrupts set via NVIC writes
    /// will never be trigged.
    #[serde(default = "default_true")]
    pub use_nvic: bool,

    /// Controls whether the systick interrupt is enabled.
    #[serde(default = "default_true")]
    pub use_systick: bool,

    /// The number to multiply timer reload values by. Increasing this value causes timers to
    /// execute less frequently.
    #[serde(default = "default_global_timer_scale")]
    pub global_timer_scale: u32,

    /// The maximum number of blocks without consuming fuzzing input to execute before reporting a
    /// hang to the fuzzer.
    #[serde(default = "default_fuzz_consumption_timeout")]
    pub fuzz_consumption_timeout: u64,

    /// The maximum number of blocks to execute before reporting a hang to the fuzzer.
    #[serde(default = "default_instr_limit")]
    pub instr_limit: u64,

    /// A list of handlers to use for certain functions. If set to null then the call is skipped.
    #[serde(default)]
    pub handlers: IndexMap<String, Option<String>>,

    /// A list of functions that the program should exit at.
    #[serde(default)]
    pub exit_at: IndexMap<String, Option<String>>,

    /// Locations to inject code for patching register values.
    #[serde(default)]
    pub patch: IndexMap<u64, ValuePatch>,

    /// Locations to inject code for patching register values.
    #[serde(default)]
    pub mem_patch: IndexMap<u64, Vec<u8>>,

    /// A mapping from addresses to symbol names that can be used for handlers.
    #[serde(default)]
    pub symbols: IndexMap<u64, String>,
}

impl Default for FirmwareConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            entry_point: None,
            interrupt_triggers: default_interrupt_trigger(),
            memory_map: IndexMap::new(),
            use_access_contexts: false,
            mmio_models: MmioModels::default(),
            nvic: Nvic::default(),
            use_nvic: true,
            use_systick: true,
            global_timer_scale: default_global_timer_scale(),
            fuzz_consumption_timeout: default_fuzz_consumption_timeout(),
            instr_limit: default_instr_limit(),
            handlers: IndexMap::default(),
            exit_at: IndexMap::default(),
            patch: IndexMap::default(),
            mem_patch: IndexMap::default(),
            symbols: IndexMap::default(),
        }
    }
}

impl FirmwareConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        // Note: we fallback to trying to find a config file called `FUZZWARE_CONFIG` for
        // compatibility with earlier version of the code.
        let config_path = std::env::var_os("TARGET_CONFIG")
            .or_else(|| std::env::var_os("FUZZWARE_CONFIG"))
            .ok_or_else(|| anyhow::format_err!("TARGET_CONFIG not set"))?;
        Self::from_path(config_path.as_ref())
    }

    pub fn from_path(target: &std::path::Path) -> anyhow::Result<Self> {
        // Allow the config to specified either with a full path to a config file or to a folder
        // containing a `config.yml`.
        let (root, config_path) = match target.extension().map_or(false, |x| x == "yml") {
            true => {
                let root = target.parent().unwrap_or(std::path::Path::new(".")).to_owned();
                (root, target.to_owned())
            }
            false => (target.to_owned(), target.join("config.yml")),
        };

        // If config file does not exist, attempt to generate one for the user.
        if root.exists() && !config_path.exists() {
            eprintln!(
                "WARNING: Config file not found. Generating default config at: {}",
                config_path.display()
            );
            crate::genconfig::generate_and_save(target, false)?;
        }

        let mut config: Self = serde_yaml::from_slice(
            &std::fs::read(&config_path)
                .with_context(|| format!("failed to read '{}'", config_path.display()))?,
        )
        .with_context(|| format!("error parsing: {}", config_path.display()))?;
        config.path = root;

        let num_entry_regions = config.memory_map.values().filter(|x| x.is_entry).count();
        if num_entry_regions > 1 {
            anyhow::bail!("expected at most one memory region (got {num_entry_regions})");
        }

        // Try to automatically set entry region if none was specified.
        if num_entry_regions == 0 && config.entry_point.is_none() {
            // Find the file-backed region with the lowest base address.
            let mut min_region = None;
            for (name, region) in config.memory_map.iter() {
                let file = match &region.file {
                    Some(name) => name,
                    None => continue,
                };

                let (_, prev_region) = min_region.unwrap_or((name, region));
                if file != prev_region.file.as_ref().unwrap() {
                    anyhow::bail!(
                        "explicit entry point must be set when there are multiple file regions."
                    );
                }
                if prev_region.base_addr < region.base_addr {
                    // Previous region was at a lower base address.
                    continue;
                }
                min_region = Some((name, region));
            }

            let (name, _) = min_region.ok_or_else(|| {
                anyhow::format_err!("No entrypoints and no file backed regions were defined")
            })?;

            // Mark the region as the entrypoint.
            let name = name.clone();
            config.memory_map.get_mut(&name).unwrap().is_entry = true;
        }

        // We only support _either_ a list of enabled interrupt or a list of disabled interrupts.
        if config.nvic.enabled_irqs.is_some() && !config.nvic.disabled_irqs.is_empty() {
            anyhow::bail!(
                "Providing both a list of enabled and a list of disabled interrupts is unsupported"
            );
        }

        // Overwrite limits if specified by environment variables (useful for quickly testing).
        if let Some(limit) = get_u64_env("INSTR_LIMIT")? {
            config.instr_limit = limit;
        }
        if let Some(limit) = get_u64_env("INTERRUPT_LIMIT")? {
            config.nvic.interrupt_limit = limit as u32;
        }
        if let Some(limit) = get_u64_env("FUZZ_CONSUMPTION_TIMEOUT")? {
            config.fuzz_consumption_timeout = limit;
        }
        if let Ok(trigger_mode) = std::env::var("TRIGGER_FUZZ_MODE") {
            if let Some((_, trigger)) = config.interrupt_triggers.first_mut() {
                if trigger_mode.eq_ignore_ascii_case("round_robin") {
                    trigger.kind = TriggerKind::Dynamic { fuzz_mode: FuzzMode::RoundRobin };
                }
                else if trigger_mode.eq_ignore_ascii_case("fuzzed") {
                    trigger.kind = TriggerKind::Dynamic { fuzz_mode: FuzzMode::Fuzzed };
                }
            }
        }

        Ok(config)
    }

    pub fn lookup_symbol(&self, sym: &str) -> Option<u64> {
        self.symbols.iter().find(|(_, name)| *name == sym).map(|(addr, _)| *addr & !1)
    }

    pub fn is_mapped(&self, start: u64, end: u64) -> bool {
        self.memory_map.iter().any(|(_, mem)| {
            let mem_end = mem.base_addr + mem.size;
            mem.base_addr < end && start < mem_end
        })
    }
}

fn get_u64_env(name: &str) -> anyhow::Result<Option<u64>> {
    match std::env::var_os(name) {
        Some(value) => Ok(Some(
            value
                .to_str()
                .and_then(icicle_fuzzing::parse_u64_with_prefix)
                .ok_or_else(|| anyhow::format_err!("Invalid value for {name}"))?,
        )),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    #[serde(flatten)]
    pub mode: TriggerMode,
    #[serde(flatten)]
    pub kind: TriggerKind,
}

impl Trigger {
    pub fn irq(&self) -> u32 {
        match self.kind {
            TriggerKind::Fixed { irq } => irq,
            _ => 0,
        }
    }

    pub fn addr(&self) -> Option<&str> {
        match &self.mode {
            TriggerMode::Addr(sym) => Some(sym.as_str()),
            _ => None,
        }
    }

    pub fn fuzz_mode(&self) -> u32 {
        match self.kind {
            TriggerKind::Fixed { .. } => fuzzware::IRQ_FUZZ_MODE_FIXED,
            TriggerKind::Dynamic { fuzz_mode: FuzzMode::Fuzzed } => {
                fuzzware::IRQ_FUZZ_MODE_FUZZ_ENABLED_IRQ_INDEX
            }
            TriggerKind::Dynamic { fuzz_mode: FuzzMode::RoundRobin } => {
                fuzzware::IRQ_FUZZ_MODE_ROUND_ROBIN
            }
        }
    }

    pub fn trigger_mode(&self) -> u32 {
        match &self.mode {
            TriggerMode::Addr(_) => fuzzware::IRQ_TRIGGER_MODE_ADDRESS,
            TriggerMode::EveryNthTick(Tick::Name(_)) => fuzzware::IRQ_TRIGGER_MODE_TIME_FUZZED,
            TriggerMode::EveryNthTick(_) => fuzzware::IRQ_TRIGGER_MODE_TIME,
        }
    }

    pub fn every_nth_tick(&self) -> u64 {
        match &self.mode {
            TriggerMode::EveryNthTick(Tick::Number(ticks)) => *ticks,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerMode {
    Addr(String),
    EveryNthTick(Tick),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TickKind {
    Fuzzed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Tick {
    Name(TickKind),
    Number(u64),
}

impl From<TickKind> for Tick {
    fn from(value: TickKind) -> Self {
        Self::Name(value)
    }
}

impl std::fmt::Display for Tick {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(TickKind::Fuzzed) => f.write_str("fuzzed"),
            Self::Number(x) => f.write_fmt(format_args!("{x}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TriggerKind {
    Fixed { irq: u32 },
    Dynamic { fuzz_mode: FuzzMode },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    Fuzzed,
    RoundRobin,
}

impl std::fmt::Display for FuzzMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fuzzed => f.write_str("fuzzed"),
            Self::RoundRobin => f.write_str("round_robin"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory {
    pub base_addr: u64,
    pub permissions: Permissions,
    pub size: u64,
    pub file: Option<String>,
    #[serde(default)]
    pub file_offset: u64,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub is_entry: bool,
    pub fill: Option<u8>,
    pub ivt_offset: Option<u64>,
}

impl Memory {
    pub fn new(base_addr: u64, size: u64, permissions: Permissions) -> Self {
        Self {
            base_addr,
            permissions,
            size,
            file: None,
            file_offset: 0,
            file_size: None,
            is_entry: false,
            ivt_offset: None,
            fill: None,
        }
    }

    pub(crate) fn memory_range(&self) -> std::ops::Range<u64> {
        self.base_addr..(self.base_addr + self.size)
    }
}

#[derive(Copy, Clone)]
pub struct Permissions(pub u8);

impl Permissions {
    pub fn new(readable: bool, writable: bool, executable: bool) -> Self {
        let r = if readable { perm::READ } else { perm::NONE };
        let w = if writable { perm::WRITE } else { perm::NONE };
        let x = if executable { perm::EXEC } else { perm::NONE };
        Self(perm::MAP | r | w | x)
    }

    pub fn to_str(&self) -> &'static str {
        match (self.0 & perm::READ != 0, self.0 & perm::WRITE != 0, self.0 & perm::EXEC != 0) {
            (true, true, true) => "rwx",
            (true, true, false) => "rw-",
            (true, false, true) => "r-x",
            (true, false, false) => "r--",
            (false, true, true) => "-wx",
            (false, true, false) => "-w-",
            (false, false, true) => "--x",
            (false, false, false) => "---",
        }
    }
}

impl std::fmt::Debug for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        icicle_vm::cpu::mem::perm::display(self.0).fmt(f)
    }
}

impl std::str::FromStr for Permissions {
    type Err = ();

    fn from_str(str: &str) -> Result<Self, ()> {
        let bytes = str.as_bytes();
        if bytes.len() != 3 {
            return Err(());
        }

        let mut perm = perm::MAP;
        perm |= match bytes[0] {
            b'r' => perm::READ,
            b'-' => perm::NONE,
            _ => return Err(()),
        };
        perm |= match bytes[1] {
            b'w' => perm::WRITE,
            b'-' => perm::NONE,
            _ => return Err(()),
        };
        perm |= match bytes[2] {
            b'x' => perm::EXEC,
            b'-' => perm::NONE,
            _ => return Err(()),
        };
        Ok(Self(perm))
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str: std::borrow::Cow<str> = Deserialize::deserialize(deserializer)?;
        str.parse().map_err(|_| serde::de::Error::custom(format!("invalid permission bits: {str}")))
    }
}

impl Serialize for Permissions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buf = String::with_capacity(3);
        buf.push(if self.0 & perm::READ != 0 { 'r' } else { '-' });
        buf.push(if self.0 & perm::WRITE != 0 { 'w' } else { '-' });
        buf.push(if self.0 & perm::EXEC != 0 { 'x' } else { '-' });
        serializer.serialize_str(&buf)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MmioModels {
    #[serde(default)]
    pub bitextract: IndexMap<String, Bitextract>,
    #[serde(default)]
    pub constant: IndexMap<String, Constant>,
    #[serde(default)]
    pub passthrough: IndexMap<String, Passthrough>,
    #[serde(default)]
    pub set: IndexMap<String, Set>,
    #[serde(default)]
    pub unmodeled: IndexMap<String, Unmodeled>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bitextract {
    pub access_size: u64,
    pub addr: u64,
    pub left_shift: u8,
    pub mask: u32,
    pub pc: u32,
    pub size: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constant {
    pub access_size: u64,
    pub addr: u64,
    pub pc: u32,
    pub val: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passthrough {
    #[serde(default = "default_access_size")]
    pub access_size: u64,
    pub addr: u64,
    pub pc: u32,
    #[serde(default)]
    pub init_val: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Set {
    #[serde(default = "default_access_size")]
    pub access_size: u64,
    pub addr: u64,
    pub pc: u32,
    pub vals: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unmodeled {
    #[serde(default = "default_access_size")]
    pub access_size: u64,
    pub addr: u64,
    pub pc: u32,
}

fn default_access_size() -> u64 {
    4
}

fn default_num_vecs() -> u32 {
    256
}

fn default_interrupt_limit() -> u32 {
    3000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nvic {
    #[serde(default = "default_num_vecs")]
    pub num_vecs: u32,
    #[serde(default = "default_interrupt_limit")]
    pub interrupt_limit: u32,
    #[serde(default)]
    pub disabled_irqs: Vec<u32>,
    #[serde(default)]
    pub enabled_irqs: Option<Vec<u32>>,
    #[serde(default)]
    pub enable_nested_interrupts: bool,
    #[serde(default = "default_true")]
    pub allow_active_interrupt_pending: bool,
}

impl Default for Nvic {
    fn default() -> Self {
        Self {
            num_vecs: default_num_vecs(),
            interrupt_limit: default_interrupt_limit(),
            disabled_irqs: vec![],
            enabled_irqs: None,
            enable_nested_interrupts: false,
            allow_active_interrupt_pending: true,
        }
    }
}

/// Matches `DEFAULT_MEM_MAP` from Fuzzware.
pub fn cortexm_memory_map() -> IndexMap<String, Memory> {
    [
        ("ram".into(), Memory::new(0x20000000, 0x00100000, "rw-".parse().unwrap())),
        ("mmio".into(), Memory::new(0x40000000, 0x20000000, "rw-".parse().unwrap())),
        ("nvic".into(), Memory::new(0xe0000000, 0x10000000, "rw-".parse().unwrap())),
        ("irq_ret".into(), Memory::new(0xfffff000, 0x1000, "--x".parse().unwrap())),
    ]
    .into_iter()
    .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValuePatch {
    pub register: String,
    pub value: u64,
}
