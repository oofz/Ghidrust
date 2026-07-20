/// Custom allocation hooks .
pub trait AllocHooks: Send + Sync {
    fn malloc(&self, size: usize) -> *mut u8 {
        let layout = std::alloc::Layout::from_size_align(size, 8).unwrap_or_else(|_| {
 std::alloc::Layout::from_size_align(1, 1).expect("fallback layout")
        });
        unsafe { std::alloc::alloc(layout) }
    }

    fn calloc(&self, n: usize, size: usize) -> *mut u8 {
        let total = n.saturating_mul(size);
        let ptr = self.malloc(total);
        if !ptr.is_null() && total > 0 {
            unsafe { std::ptr::write_bytes(ptr, 0, total) };
        }
        ptr
    }

    fn realloc(&self, ptr: *mut u8, size: usize) -> *mut u8 {
        if ptr.is_null() {
            return self.malloc(size);
        }
        let layout = std::alloc::Layout::from_size_align(size, 8).unwrap_or_else(|_| {
 std::alloc::Layout::from_size_align(1, 1).expect("fallback layout")
        });
        unsafe { std::alloc::realloc(ptr, layout, size) }
    }

    fn free(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }
 let layout = std::alloc::Layout::from_size_align(1, 1).expect("free layout");
        unsafe { std::alloc::dealloc(ptr, layout) }
    }
}

/// Default Rust global allocator hooks.
#[derive(Debug, Default)]
pub struct GlobalAllocHooks;

impl AllocHooks for GlobalAllocHooks {}

static GLOBAL_HOOKS: GlobalAllocHooks = GlobalAllocHooks;

pub fn global_hooks() -> &'static dyn AllocHooks {
    &GLOBAL_HOOKS
}
