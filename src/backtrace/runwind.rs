use std::{ops::Range, rc::Rc, sync::Mutex};

use addr2line::{
    gimli::{EndianReader, RunTimeEndian},
    Context,
};
use once_cell::sync::Lazy;
use runwind::{CacheNative, MustNotAllocateDuringUnwind, UnwindRegsNative, Unwinder};

static CONTEXTS: Lazy<Vec<(usize, Range<usize>, Mutex<SendContext>)>> = Lazy::new(|| {
    let mut contexts = Vec::new();
    for obj in runwind::get_objects() {
        let context = Context::new(obj.obj_file()).unwrap();
        contexts.push((
            obj.base_addr(),
            obj.text_svma(),
            Mutex::new(SendContext(context)),
        ));
    }
    contexts.sort_by_key(|(base_addr, _, _)| *base_addr);
    contexts
});

struct SendContext(Context<EndianReader<RunTimeEndian, Rc<[u8]>>>);

unsafe impl Send for SendContext {}

#[derive(Default)]
pub struct Trace {
    unwinder: Unwinder<MustNotAllocateDuringUnwind>,
    cache: CacheNative<&'static [u8], MustNotAllocateDuringUnwind>,
}

#[derive(Clone, Debug)]
pub struct Frame {
    addr: usize,
}

pub struct Symbol {
    name: String,
    addr: *mut libc::c_void,
}

impl super::Frame for Frame {
    type S = Symbol;

    fn ip(&self) -> usize {
        self.addr
    }

    fn resolve_symbol<F: FnMut(&Self::S)>(&self, mut cb: F) {
        match CONTEXTS.binary_search_by_key(&self.addr, |(base_addr, _, _)| *base_addr) {
            Ok(_) => {
                cb(&Symbol {
                    name: "<unknown>".to_string(),
                    addr: self.addr as _,
                });
                return;
            }
            Err(idx) => {
                if idx == 0 {
                    cb(&Symbol {
                        name: "<unknown>".to_string(),
                        addr: self.addr as _,
                    });
                    return;
                }
                let (base_addr, text_range, context) = &CONTEXTS[idx - 1];
                let svma = self.addr - base_addr;
                if !text_range.contains(&svma) {
                    cb(&Symbol {
                        name: "<unknown>".to_string(),
                        addr: self.addr as _,
                    });
                    return;
                }
                let context = context.lock().unwrap();
                let mut frames = match context.0.find_frames(svma as u64) {
                    Ok(frames) => frames,
                    Err(_) => {
                        cb(&Symbol {
                            name: "<unknown>".to_string(),
                            addr: self.addr as _,
                        });
                        return;
                    }
                };
                loop {
                    match frames.next() {
                        Ok(Some(frame)) => {
                            cb(&Symbol {
                                name: frame
                                    .function
                                    .as_ref()
                                    .and_then(|f| f.raw_name().ok())
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| "<unknown>".to_string()),
                                addr: self.addr as _,
                            });
                            return;
                        }
                        Ok(None) => break,
                        Err(_e) => {
                            cb(&Symbol {
                                name: "<unknown>".to_string(),
                                addr: self.addr as _,
                            });
                            return;
                        }
                    }
                }
            }
        };
    }

    fn symbol_address(&self) -> *mut libc::c_void {
        self.addr as _
    }
}

impl super::Symbol for Symbol {
    fn name(&self) -> Option<Vec<u8>> {
        Some(self.name.as_bytes().to_vec())
    }

    fn addr(&self) -> Option<*mut libc::c_void> {
        Some(self.addr as _)
    }

    fn lineno(&self) -> Option<u32> {
        None
    }

    fn filename(&self) -> Option<std::path::PathBuf> {
        None
    }
}

impl super::Trace for Trace {
    type Frame = Frame;

    fn trace<F: FnMut(&Self::Frame) -> bool>(&mut self, ucontext: *mut libc::c_void, mut cb: F) {
        let ucontext: *mut libc::ucontext_t = ucontext as *mut libc::ucontext_t;
        let ip = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RIP as usize] as u64 };
        let sp = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RSP as usize] as u64 };
        let bp = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RBP as usize] as u64 };
        let regs = UnwindRegsNative::new(ip, sp, bp);
        let mut iter = self
            .unwinder
            .iter_frames_with_regs(ip as usize, regs, &mut self.cache);
        while let Ok(Some(frame)) = iter.try_next() {
            if !cb(&Frame { addr: frame }) {
                break;
            }
        }
    }
}
