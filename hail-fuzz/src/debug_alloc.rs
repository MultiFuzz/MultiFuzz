use std::{
    alloc::{GlobalAlloc, System},
    io::Write,
};

#[global_allocator]
static ALLOC: DebuggingAlloc = DebuggingAlloc::new();

struct DebuggingAlloc {
    alloc_failure: std::sync::atomic::AtomicBool,
}

impl DebuggingAlloc {
    const fn new() -> Self {
        Self { alloc_failure: std::sync::atomic::AtomicBool::new(false) }
    }

    #[inline(always)]
    fn check_alloc_failure(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        if ptr.is_null() && !self.alloc_failure.swap(true, std::sync::atomic::Ordering::AcqRel) {
            self.print_alloc_failure(layout);
        }
    }

    #[cold]
    #[inline(never)]
    fn print_alloc_failure(&self, layout: std::alloc::Layout) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "allocation of {} bytes failed, attempting to capture backtrace",
            layout.size()
        );
        let bt = std::backtrace::Backtrace::force_capture();
        let _ = write!(stderr, "{bt}");
        let _ = stderr.flush();
    }
}

unsafe impl GlobalAlloc for DebuggingAlloc {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        self.check_alloc_failure(ptr, layout);
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        self.check_alloc_failure(ptr, layout);
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        self.check_alloc_failure(new_ptr, layout);
        new_ptr
    }
}
