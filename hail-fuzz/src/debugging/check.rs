use std::io::Write;

use bstr::ByteSlice;
use icicle_vm::{
    cpu::{mem::perm, Exception, ExceptionCode, ValueSource},
    Vm,
};

pub fn init(vm: &mut Vm) -> anyhow::Result<()> {
    let canary = icicle_fuzzing::parse_bool_env("ENABLE_CANARY")?.unwrap_or(false);
    let debug = icicle_fuzzing::parse_bool_env("ENABLE_DEBUG")?.unwrap_or(false);

    if let Ok(print_hook) = std::env::var("PRINT_HOOK") {
        if let Some((addr, reglist)) = icicle_fuzzing::parse_func_hook(vm, &print_hook) {
            match reglist.as_slice() {
                &[reg] => {
                    let (reg, mode) = reg.split_once(":").unwrap_or((reg, "char"));
                    match mode {
                        "str" => register_cstr_printer(vm, addr, reg),
                        "char" => register_char_out_printer(vm, addr, reg),
                        _ => tracing::warn!("unknown print mode: {mode}"),
                    }
                }
                &[data_reg, len_reg] => register_write_printer(vm, addr, data_reg, len_reg),
                x => tracing::warn!("Invalid number of registers for `PRINT_HOOK`: {}", x.len()),
            }
        }
        else {
            tracing::warn!("`PRINT_HOOK` is invalid: {print_hook}")
        }
    }

    let debug = match (canary, debug) {
        (true, false) => DebugConfig::enable_canary(),
        (canary, true) => DebugConfig::new_with_output(canary, std::io::stderr(), true),
        _ => return Ok(()),
    };

    let Some(target_path) =
        vm.env_ref::<icicle_cortexm::FuzzwareEnvironment>().and_then(|x| x.elf_path.as_ref())
    else {
        tracing::warn!("Unable to enable debugging and canaries for unknown target");
        return Ok(());
    };

    let Some(target) = KnownTargets::detect_from_path(target_path)
    else {
        tracing::warn!(
            "Unable to enable debugging and canaries for unknown binary: {}",
            target_path.display()
        );
        return Ok(());
    };

    // @todo: port remaining checkers to new approach.
    match target {
        KnownTargets::Gateway => debug_gateway(vm, debug),
        KnownTargets::HeatPress => debug_heatpress(vm, debug),
        KnownTargets::Thermostat => debug_thermostat(vm, debug),
        KnownTargets::ZephyrSocketCan => debug_zephyr_socket_can(vm, debug),
        KnownTargets::SteeringControl => register_write_printer(vm, 0x081060, "r1", "r2"),
        KnownTargets::Cnc => debug_cnc(vm, debug),
        KnownTargets::Printer => register_char_out_printer(vm, 0x80004ea, "r1"),
        KnownTargets::Console => register_write_printer(vm, 0x15c0, "r1", "r2"),
        KnownTargets::UtaskerModbus => debug_utasker_modbus(vm, debug),
        KnownTargets::UtaskerUsb => debug_usb(vm, debug),
        KnownTargets::GpsTracker => debug_gps_tracker(vm, debug),
        KnownTargets::XmlParser => debug_xml_parser(vm, debug),
        KnownTargets::Lowpan => debug_lowpan(vm, debug),
        KnownTargets::RiotCcnLiteRelay => {
            let _ = debug_riot_ccn_lite_relay(vm, debug);
        }
        KnownTargets::RiotGnrcNetworking => {
            let _ = debug_riot_gnrc_networking(vm, debug);
        }
    }

    Ok(())
}

enum KnownTargets {
    Gateway,
    HeatPress,
    Thermostat,
    ZephyrSocketCan,
    SteeringControl,
    Cnc,
    Printer,
    Console,
    UtaskerModbus,
    UtaskerUsb,
    GpsTracker,
    XmlParser,
    Lowpan,
    RiotCcnLiteRelay,
    RiotGnrcNetworking,
}

impl KnownTargets {
    pub fn detect_from_path(path: &std::path::Path) -> Option<KnownTargets> {
        match path.file_stem()?.to_str()? {
            "uEmu.3Dprinter" => Some(Self::Printer),
            "uEmu.GPSTracker" => Some(Self::GpsTracker),
            "XML_Parser" => Some(Self::XmlParser),
            "Pretender.max32_rf_door_lock" => None,
            "Pretender.max32_thermostat" => Some(Self::Thermostat),
            "uEmu.LiteOS_IoT" => None,
            "HAL.atmel_6lowpan_udp_tx" | "HAL.atmel_6lowpan_udp_rx" => Some(Self::Lowpan),
            "uEmu.uTaskerV1.4_USB_STM32429ZI" => Some(Self::UtaskerUsb),
            "uEmu.uTasker_MODBUS" => Some(Self::UtaskerModbus),
            "uEmu.zephyrsocketcan" => Some(Self::ZephyrSocketCan),
            "Steering_Control" => Some(Self::SteeringControl),
            "Console" => Some(Self::Console),
            "CNC" => Some(Self::Cnc),
            "Gateway" => Some(Self::Gateway),
            "Heat_Press" => Some(Self::HeatPress),
            "Robot" => None,
            "Soldering_Iron" => None,
            "ccn-lite-relay" => Some(Self::RiotCcnLiteRelay),
            "gnrc_networking" => Some(Self::RiotGnrcNetworking),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct DebugConfig {
    canary: bool,
    output: Option<std::sync::Arc<std::sync::Mutex<Box<dyn std::io::Write>>>>,
    colorize: bool,
}

impl DebugConfig {
    #[allow(unused)]
    pub fn enable_canary() -> Self {
        Self { canary: true, output: None, colorize: false }
    }

    pub fn new_with_output<W>(canary: bool, output: W, colorize: bool) -> Self
    where
        W: std::io::Write + 'static,
    {
        Self {
            canary,
            output: Some(std::sync::Arc::new(std::sync::Mutex::new(Box::new(output)))),
            colorize,
        }
    }

    fn error(&self, cpu: &mut icicle_vm::cpu::Cpu, msg: &str, code: u64) {
        if let Some(output) = self.output.as_ref() {
            let mut out = output.lock().unwrap();
            if self.colorize {
                writeln!(out, "\n\x1b[0;31m[{}] {msg}\x1b[0m", cpu.icount()).unwrap();
            }
            else {
                out.write_all(msg.as_bytes()).unwrap()
            }
        }

        if self.canary {
            cpu.exception = Exception::new(ExceptionCode::Environment, code);
        }
    }
}

const fn binary_id(dataset_code: u64, binary_id: u8) -> u64 {
    dataset_code | ((binary_id as u64) << 8)
}

const fn bug(binary_code: u64, bug_id: u8) -> u64 {
    binary_code | bug_id as u64
}

const P2IM_BASE: u64 = 0x10000;
const GATEWAY: u64 = binary_id(P2IM_BASE, 3);

const UEMU_BASE: u64 = 0x20000;
const LOWPAN_SENDER: u64 = binary_id(UEMU_BASE, 0);
const UTASKER_USB: u64 = binary_id(UEMU_BASE, 8);
const XML_PARSER: u64 = binary_id(UEMU_BASE, 9);

const MULTI_FUZZ_BASE: u64 = 0x40000;
const RIOT_GNRC_NETWORKING: u64 = binary_id(MULTI_FUZZ_BASE, 0);
const RIOT_CCN_LITE_RELAY: u64 = binary_id(MULTI_FUZZ_BASE, 1);

fn debug_cnc(vm: &mut Vm, debug: DebugConfig) {
    if debug.output.is_some() {
        register_char_out_printer(vm, 0x8007db4, "r0");
    }

    const SET_SETTINGS_DECIMAL_PLACES: u64 = 0x8004f8a;
    let reg_r2 = vm.cpu.arch.sleigh.get_varnode("r2").unwrap();
    let out = debug;
    vm.hook_address(SET_SETTINGS_DECIMAL_PLACES, move |cpu, _addr| {
        let value = cpu.read_reg(reg_r2);
        if value > 9 {
            out.error(cpu, &format!("settings.decimal_places={value}"), 11);
        }
    });
}

fn debug_gateway(vm: &mut Vm, debug: DebugConfig) {
    let reg_r0 = vm.cpu.arch.sleigh.get_varnode("r0").unwrap();
    let reg_r1 = vm.cpu.arch.sleigh.get_varnode("r1").unwrap();
    let reg_r2 = vm.cpu.arch.sleigh.get_varnode("r2").unwrap();
    let reg_r3 = vm.cpu.arch.sleigh.get_varnode("r3").unwrap();

    // User provided `pin` argument is not bounds checked.
    const SET_PIN_STATE: u64 = 0x08002fc6;
    let out = debug.clone();
    vm.hook_address(SET_PIN_STATE, move |cpu, _addr| {
        let pin = cpu.read_reg(reg_r1);
        if pin >= 60 {
            out.error(cpu, &format!("setPinState called with pin >= 60 (pin = {pin})"), 12);
        }
    });

    // (false-positive) initialization race in `HAL_UART_TxCpltCallback`
    const EXECUTE_TX_CALLBACK: u64 = 0x800878e;
    let out = debug.clone();
    vm.hook_address(EXECUTE_TX_CALLBACK, move |cpu, _addr| {
        let tx_callback = cpu.read_reg(reg_r3);
        if tx_callback == 0 {
            out.error(cpu, "(FP) HAL_UART_TxCpltCallback called before init", 21);
        }
    });

    // (false-positive) initialization race in `HAL_UART_RxCpltCallback`
    const EXECUTE_RX_CALLBACK: u64 = 0x8008768;
    let out = debug.clone();
    vm.hook_address(EXECUTE_RX_CALLBACK, move |cpu, _addr| {
        let rx_callback = cpu.read_reg(reg_r3);
        if rx_callback == 0 {
            out.error(cpu, "(FP) HAL_UART_RxCpltCallback called before init", 21);
        }
    });

    // Use of dangling pointer set in `pwm_start`
    const TIMER2_HANDLER: u64 = 0x80077c0;
    const PWM_START_TIMER_INIT: u64 = 0x800716a;
    const PWM_START_RETURN: u64 = 0x80071aa;
    let pwm_active_flag = vm.cpu.trace.register_store(vec![0_u8]);
    vm.hook_address(PWM_START_TIMER_INIT, move |cpu, _addr| {
        cpu.trace[pwm_active_flag].data_mut()[0] = 1;
    });
    vm.hook_address(PWM_START_RETURN, move |cpu, _addr| {
        cpu.trace[pwm_active_flag].data_mut()[0] = 0;
    });
    let out = debug.clone();
    vm.hook_address(TIMER2_HANDLER, move |cpu, _addr| {
        let is_pwm_active = cpu.trace[pwm_active_flag].data_mut()[0] != 0;
        if !is_pwm_active {
            out.error(cpu, "use of expired timer_handles[1] reference", 23);
        }
    });

    // Unchecked error in `FirmataParser::decodeByteStream`
    const RETURN_FROM_BUFFER_AT_POSITION: u64 = 0x800348a;
    let out = debug.clone();
    vm.hook_address(RETURN_FROM_BUFFER_AT_POSITION, move |cpu, _addr| {
        let is_error = cpu.read_reg(reg_r0);
        if is_error != 0 {
            out.error(cpu, "error from `decodeByteStream` was unchecked", bug(GATEWAY, 4));
        }
    });

    // Integer underflow when length of SYSEX message is zero.
    const DECODE_BYTE_STREAM_Q: u64 = 0x8003422;
    let out = debug.clone();
    vm.hook_address(DECODE_BYTE_STREAM_Q, move |cpu, _addr| {
        let sysex_bytes_read = cpu.read_reg(reg_r1);
        if sysex_bytes_read == 0 {
            out.error(cpu, "integer underflow in SYSEX message handling.", bug(GATEWAY, 5));
        }
    });

    // (false positive) Use of uninitialized hi2c->pBuffPtr
    const I2C_IT_ERROR_BUF_STORE: &[u64] = &[0x80050da, 0x0800501c];
    let out = debug.clone();
    vm.hook_many_addresses(I2C_IT_ERROR_BUF_STORE, move |cpu, _addr| {
        let buffer_ptr = cpu.read_reg(reg_r2);
        if buffer_ptr == 0 {
            out.error(cpu, "(FP) use of uninitialized hi2c->pBuffPtr", 22);
        }
        if buffer_ptr > 0x200003d0 {
            out.error(
                cpu,
                &format!("(FP) hi2c->pBuffPtr exceeds parser buffer (writing to {buffer_ptr:#x})"),
                bug(GATEWAY, 6),
            );
        }
    });

    // (false positive) Use of uninitialized hi2c->hdmatx
    const I2C_SLAVE_STOPF_DMA_READ: u64 = 0x80050da;
    let out = debug.clone();
    vm.hook_address(I2C_SLAVE_STOPF_DMA_READ, move |cpu, _addr| {
        let dma_instance = cpu.read_reg(reg_r2);
        if dma_instance == 0 {
            out.error(
                cpu,
                "(FP) use of uninitialized DMA instance in I2C_Slave_STOPF",
                bug(GATEWAY, 7),
            );
        }
    });
    const I2C_IT_ERROR_DMA_READ: u64 = 0x8004f8e;
    let out = debug.clone();
    vm.hook_address(I2C_IT_ERROR_DMA_READ, move |cpu, _addr| {
        let dma_instance = cpu.read_reg(reg_r3);
        if dma_instance == 0 {
            out.error(
                cpu,
                "(FP) use of uninitialized DMA instance in I2C_IT_ERROR",
                bug(GATEWAY, 7),
            );
        }
    });
}

pub fn debug_heatpress(vm: &mut Vm, debug: DebugConfig) {
    let reg_r4 = vm.cpu.arch.sleigh.get_varnode("r4").unwrap();
    let reg_r6 = vm.cpu.arch.sleigh.get_varnode("r6").unwrap();

    // Buffer overflow in `get_FC3`
    const GET_FC3_STORE: u64 = 0x80432;
    let out = debug.clone();
    vm.hook_address(GET_FC3_STORE, move |cpu, _addr| {
        const AU16DATA: u64 = 0x200708c8;
        const DATA8024: u64 = 0x200709c8;

        let buffer = cpu.read_reg(reg_r6);
        let buffer_offset = cpu.read_reg(reg_r4);
        let ptr = buffer + buffer_offset * 2;
        if !(AU16DATA..AU16DATA + 2 * 32).contains(&ptr)
            || (DATA8024..DATA8024 + 2 * 10).contains(&ptr)
        {
            out.error(cpu, &format!("(FP) Buffer overflow in `get_FC3` ({ptr:#x})"), 13);
        }
    });
}

fn debug_thermostat(vm: &mut Vm, debug: DebugConfig) {
    if debug.output.is_some() {
        const SERIAL_PUTC: u64 = 0x0000151a;
        register_char_out_printer(vm, SERIAL_PUTC, "r1");
    }
}

fn debug_zephyr_socket_can(vm: &mut Vm, debug: DebugConfig) {
    if debug.output.is_some() {
        const CHAR_OUT: u64 = 0x08000b2c;
        register_char_out_printer(vm, CHAR_OUT, "r0");

        const WRITE: u64 = 0x800c6ec;
        register_write_printer(vm, WRITE, "r1", "r2");
    }

    const SET_FILTER: u64 = 0x080058e6;
    let reg_r3 = vm.cpu.arch.sleigh.get_varnode("r3").unwrap();
    let reg_r6 = vm.cpu.arch.sleigh.get_varnode("r6").unwrap();
    let out = debug;
    vm.hook_address(SET_FILTER, move |cpu, _addr| {
        let filter_index = cpu.read_reg(reg_r6);
        if filter_index > 4 {
            let base_ptr = cpu.read_reg(reg_r3);
            let msg = format!(
                "can_stm32_attach with filter_index={filter_index}\n{:#x} and {:#x} corrupted\x1b[0m",
                base_ptr + 0xa0 + (filter_index * 4),
                base_ptr + 0xb4 + (filter_index * 4),
            );
            out.error(cpu, &msg, 200);
        }
    });
}

fn debug_gps_tracker(vm: &mut Vm, debug: DebugConfig) {
    if debug.output.is_some() {
        const UART_WRITE: u64 = 0x83cc4;
        register_char_out_printer(vm, UART_WRITE, "r1");
    }

    // Stack overflow in `USB_SendStringDescriptor`
    const USB_SEND_STRING_DESCRIPTOR: u64 = 0x8424c;
    let reg_r1 = vm.cpu.arch.sleigh.get_varnode("r1").unwrap();
    vm.hook_address(USB_SEND_STRING_DESCRIPTOR, move |cpu, _addr| {
        let w_len = cpu.read_reg(reg_r1);
        if w_len > 0xc000 {
            debug.error(cpu, &format!("USB_SendStringDescriptor with wLength={w_len:#x}"), 30);
        }
    });
}

fn debug_usb(vm: &mut Vm, debug: DebugConfig) {
    if debug.output.is_some() {
        const FN_WRITE: u64 = 0x800f1f6;
        register_write_printer(vm, FN_WRITE, "r1", "r2");
    }

    const FN_USB_HANDLE_FRAME: u64 = 0x800fc2c;
    let reg_r2 = vm.cpu.arch.sleigh.get_varnode("r2").unwrap();
    let out = debug.clone();
    vm.hook_address(FN_USB_HANDLE_FRAME, move |cpu, _addr| {
        let endpoint = cpu.read_reg(reg_r2);
        if endpoint > 1 {
            out.error(cpu, &format!("fnUSB_handle_frame with iEndpoint={endpoint:#x}"), 45);
        }
    });

    const FN_EXTRACT_FIFO: u64 = 0x800d658;
    let reg_r3 = vm.cpu.arch.sleigh.get_varnode("r3").unwrap();
    let out = debug.clone();
    vm.hook_address(FN_EXTRACT_FIFO + 0x6, move |cpu, _addr| {
        let len = cpu.read_reg(reg_r3);
        if len > 64 {
            out.error(cpu, &format!("fnExtractFIFO with length={len:#x}"), 27);
        }
    });

    const CALL_NEW_UART_SETTINGS: u64 = 0x8011c10;
    let reg_r1 = vm.cpu.arch.sleigh.get_varnode("r1").unwrap();
    let out = debug.clone();
    vm.hook_address(CALL_NEW_UART_SETTINGS, move |cpu, _addr| {
        let interface = cpu.read_reg(reg_r1);
        if interface > 1 {
            let msg = format!("fnNewUART_settings with iInterface={interface:#0x}");
            out.error(cpu, &msg, bug(UTASKER_USB, 2));
        }
    });

    const FN_SCI_TX_BYTE: u64 = 0x800f0c2;
    const FN_SCI_RX_BYTE: u64 = 0x800efea;
    const SERIAL_HANDLE: u64 = 0x20000948;
    let out = debug;
    vm.hook_many_addresses(&[FN_SCI_TX_BYTE, FN_SCI_RX_BYTE], move |cpu, addr| {
        let serial_handle = cpu.mem.read_u8(SERIAL_HANDLE, perm::NONE).unwrap_or(0);
        if serial_handle == 0 {
            let msg = format!("{addr:#x} SCI_Interrupt trigged before initialization");
            out.error(cpu, &msg, bug(UTASKER_USB, 3));
        }
    });
}

fn debug_xml_parser(vm: &mut Vm, debug: DebugConfig) {
    let mut hook_injected_bug = move |addr: u64, msg: &'static str, code: u64| {
        let out = debug.clone();
        vm.hook_address(addr, move |cpu, _| out.error(cpu, msg, code));
    };

    hook_injected_bug(0x800b55a, "Hit double free", 32);
    hook_injected_bug(0x800b682, "Hit stack based buffer overflow", 33);
    hook_injected_bug(0x800b6ba, "Null pointer dereference hit", 34);
    hook_injected_bug(0x800b6cc, "Format-string vulnerability hit", 35);
    hook_injected_bug(0x800b6a4, "Hit heap based buffer overflow", bug(XML_PARSER, 6));
}

fn debug_lowpan(vm: &mut Vm, debug: DebugConfig) {
    if debug.output.is_some() {
        const USART_SERIAL_PUTCHAR: u64 = 0x2a1c;
        register_char_out_printer(vm, USART_SERIAL_PUTCHAR, "r1");
    }

    let reg_r0 = vm.cpu.arch.sleigh.get_varnode("r0").unwrap();

    // Fragment offset is not bounds-checked in `sicslowpan::input`
    let out = debug.clone();
    vm.hook_address(0x4806, move |cpu, _addr| {
        let r0 = cpu.read_reg(reg_r0);
        // uncomp_hdr_len + (uint16_t)(frag_offset << 3) > UIP_BUFSIZE
        if r0 >= 400 {
            out.error(
                cpu,
                &format!("uncomp_hdr_len + (frag_offset << 3) > UIP_BUFSIZE (size = {r0})"),
                bug(LOWPAN_SENDER, 2),
            );
        }
    });
}

fn debug_utasker_modbus(vm: &mut Vm, debug: DebugConfig) {
    if debug.output.is_some() {
        const FN_WRITE: u64 = 0x800e9de;
        register_write_printer(vm, FN_WRITE, "r1", "r2");
    }
}

fn debug_riot_ccn_lite_relay(vm: &mut Vm, debug: DebugConfig) -> Option<()> {
    if debug.output.is_some() {
        let stdio_write = vm.env.lookup_symbol("stdio_write")?;
        register_write_printer(vm, stdio_write, "r0", "r1");
    }

    let reg_r0 = vm.cpu.arch.sleigh.get_varnode("r0").unwrap();

    // Use after free for interest timeout.
    let ccnl_face_remove_free = vm.env.lookup_symbol("ccnl_face_remove")? + 0xa6;
    let out = debug.clone();
    vm.hook_address(ccnl_face_remove_free, move |cpu, _addr| {
        let interface = cpu.read_reg(reg_r0);
        out.error(
            cpu,
            &format!("free called for interface ({interface:#x}) without removing from timer list"),
            bug(RIOT_CCN_LITE_RELAY, 0),
        );
    });

    // Re-initialization of shared global variable.
    let ccnl_open_ccnl_start = vm.env.lookup_symbol("_ccnl_open")? + 0x3c;
    let out = debug.clone();
    vm.hook_address(ccnl_open_ccnl_start, move |cpu, _addr| {
        out.error(
            cpu,
            "reinitialization of global variable `ccnl_evtimer`",
            bug(RIOT_CCN_LITE_RELAY, 1),
        );
    });

    Some(())
}

fn debug_riot_gnrc_networking(vm: &mut Vm, debug: DebugConfig) -> Option<()> {
    if debug.output.is_some() {
        let ssputs_r = vm.env.lookup_symbol("__ssputs_r")?;
        register_write_printer(vm, ssputs_r, "r2", "r3");
    }

    let gnrc_icmpv6_echo_build = vm.env.lookup_symbol("gnrc_icmpv6_echo_build")?;
    let out = debug.clone();
    vm.hook_address(gnrc_icmpv6_echo_build, move |cpu, _addr| {
        // Length is the 4th argument
        let stack = cpu.read_reg(cpu.arch.reg_sp);
        let Ok(length) = cpu.mem.read_u32(stack, perm::NONE)
        else {
            return;
        };

        // 8 is added the length before it is passed to `gnrc_icmpv6_build`
        if length.checked_add(8).is_none() {
            out.error(
                cpu,
                &format!("integer overflow in gnrc_icmpv6_build (length={length:#x})"),
                bug(RIOT_GNRC_NETWORKING, 0),
            );
        }
    });

    Some(())
}

fn register_char_out_printer(vm: &mut Vm, char_out_ptr: u64, reg: &str) {
    tracing::debug!("registering `char_out({reg})` hook at {char_out_ptr:#x}");
    let reg = vm.cpu.arch.sleigh.get_varnode(reg).unwrap();
    vm.hook_address(char_out_ptr, move |cpu: &mut icicle_vm::cpu::Cpu, _| {
        let char = cpu.read_var::<u32>(reg);
        print!("{}", char as u8 as char);
        let _ = std::io::stdout().flush();
    });
}

fn register_cstr_printer(vm: &mut Vm, addr: u64, reg: &str) {
    tracing::debug!("registering `cstr({reg})` hook at {addr:#x}");
    let reg = vm.cpu.arch.sleigh.get_varnode(reg).unwrap();
    let mut buf = [0; 64];
    vm.hook_address(addr, move |cpu: &mut icicle_vm::cpu::Cpu, _| {
        let ptr = cpu.read_var::<u32>(reg) as u64;
        print!("{}", read_cstr(&mut buf, cpu, ptr).as_bstr());
        let _ = std::io::stdout().flush();
    });
}

fn read_cstr<'a>(buf: &'a mut [u8], cpu: &mut icicle_vm::cpu::Cpu, ptr: u64) -> &'a [u8] {
    buf[0] = 0;
    let _ = cpu.mem.read_bytes(ptr, buf, perm::NONE);
    let len = buf.find_byte(0).unwrap_or(buf.len());
    &buf[..len]
}

fn register_write_printer(vm: &mut Vm, addr: u64, data_reg: &str, len_reg: &str) {
    tracing::debug!("registering `write(data={data_reg}, len={len_reg})` hook at {addr:#x}");
    let data = vm.cpu.arch.sleigh.get_varnode(data_reg).unwrap();
    let len = vm.cpu.arch.sleigh.get_varnode(len_reg).unwrap();

    let mut buf = vec![];
    vm.hook_address(addr, move |cpu: &mut icicle_vm::cpu::Cpu, _| {
        let ptr = cpu.read_var::<u32>(data);
        let len = cpu.read_var::<u32>(len);
        buf.resize((len as usize).min(64), 0);
        let _ = cpu.mem.read_bytes(ptr as u64, &mut buf, perm::NONE);
        print!("{}", buf.as_bstr());
        let _ = std::io::stdout().flush();
    });
}
