//! Itanium Level I adapter over Desenredo physical unwinding.
//!
//! The compiler ABI is a thin caller-owned surface over a type-selected
//! Desenredo unwinder. The traversal engine remains expressed in Desenredo
//! register images, frames, and memory authority.

use core::{
    ffi::{c_int, c_void},
    mem::transmute,
    num::NonZeroUsize,
    ptr::{self, NonNull},
};

use desenredo_abi::{
    class::ExceptionClass,
    unwind::{Actions, Context, Exception, PersonalityFn, ReasonCode, StopFn, TraceFn},
};
use gimli::{Register, X86_64};

use crate::{
    arch::x86_64::state::State,
    cursor::{Cursor, Key},
    error::UnwindError,
    source::{Image, Info},
};

/// Itanium personality protocol version supported by this adapter.
const VERSION: c_int = 1;

/// Terminates after an unrecoverable Level I protocol failure.
fn trap() -> ! {
    // SAFETY:
    // UD2 is an intentional terminal instruction and touches no memory or stack state.
    unsafe { core::arch::asm!("ud2", options(att_syntax, noreturn, nomem, nostack)) }
}

/// Static policy and memory authority for one native unwinder.
///
/// The implementing type selects image discovery and memory access at compile
/// time. Compiler propagation enters through this module so caller-state
/// capture occurs before ordinary Rust forwarding frames exist.
///
/// # Safety
///
/// Every image returned by [`Unwinder::image`] must describe the exact live code
/// image containing the requested instruction. Every successful [`Unwinder::read`]
/// must return the exact bytes at the requested mapped address without faulting
/// or exceeding the implementation authority.
pub unsafe trait Unwinder: Sized {
    /// Returns the live unwind image containing one instruction.
    fn image(address: usize) -> Option<Image<'static>>;

    /// Reads one unsigned value with the requested byte width.
    fn read(address: usize, size: u8) -> Option<u64>;
}

/// Deletes an exception through its producer callback.
///
/// # Safety
///
/// `exception` must be live and exclusively owned for deletion.
#[inline]
pub unsafe fn delete(exception: *mut Exception) {
    if let Some(exception) = NonNull::new(exception) {
        // SAFETY:
        // The function contract keeps the producer-owned header live here.
        let cleanup = unsafe { exception.as_ref().cleanup() };

        if let Some(cleanup) = cleanup {
            // SAFETY:
            // The producer installed this callback to consume the exception.
            unsafe { cleanup(ReasonCode::FOREIGN, exception.as_ptr()) }
        }
    }
}

/// Reads one DWARF register from an active callback context.
///
/// # Safety
///
/// `context` must be the live context supplied by a callback from `U`.
#[inline]
pub unsafe fn reg<U>(context: *mut Context, index: c_int) -> usize
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance for U.
    unsafe { Callback::<U>::reg(context, index) }
}

/// Writes one DWARF register in an active cleanup context.
///
/// # Safety
///
/// `context` must be the live mutable cleanup context supplied by a callback from `U`.
#[inline]
pub unsafe fn write<U>(context: *mut Context, index: c_int, value: usize)
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance for U.
    unsafe { Callback::<U>::write(context, index, value) }
}

/// Reads the instruction pointer from an active callback context.
///
/// # Safety
///
/// `context` must be the live context supplied by a callback from `U`.
#[inline]
pub unsafe fn ip<U>(context: *mut Context) -> usize
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance for U.
    unsafe { Callback::<U>::ip(context) }
}

/// Reads the instruction pointer relation into the supplied output.
///
/// # Safety
///
/// `context` must be live for a callback from `U`. `before` must be writable for the call.
#[inline]
pub unsafe fn info<U>(context: *mut Context, before: *mut c_int) -> usize
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance and output validity.
    unsafe { Callback::<U>::info(context, before) }
}

/// Writes the landing-pad instruction pointer.
///
/// # Safety
///
/// `context` must be the live mutable cleanup context supplied by a callback from `U`.
/// `value` must name executable landing-pad code for that frame.
#[inline]
pub unsafe fn jump<U>(context: *mut Context, value: usize)
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance and landing-pad validity.
    unsafe { Callback::<U>::jump(context, value) }
}

/// Reads the canonical frame address.
///
/// # Safety
///
/// `context` must be the live context supplied by a callback from `U`.
#[inline]
pub unsafe fn cfa<U>(context: *mut Context) -> usize
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance for U.
    unsafe { Callback::<U>::cfa(context) }
}

/// Reads the LSDA pointer for the active frame.
///
/// # Safety
///
/// `context` must be the live context supplied by a callback from `U`.
#[inline]
pub unsafe fn lsda<U>(context: *mut Context) -> *const u8
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance for U.
    unsafe { Callback::<U>::lsda(context) }
}

/// Reads the code region start for the active frame.
///
/// # Safety
///
/// `context` must be the live context supplied by a callback from `U`.
#[inline]
pub unsafe fn start<U>(context: *mut Context) -> usize
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance for U.
    unsafe { Callback::<U>::start(context) }
}

/// Reads the text relative base for the active frame.
///
/// # Safety
///
/// `context` must be the live context supplied by a callback from `U`.
#[inline]
pub unsafe fn text<U>(context: *mut Context) -> usize
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance for U.
    unsafe { Callback::<U>::text(context) }
}

/// Reads the data relative base for the active frame.
///
/// # Safety
///
/// `context` must be the live context supplied by a callback from `U`.
#[inline]
pub unsafe fn data<U>(context: *mut Context) -> usize
where
    U: Unwinder,
{
    // SAFETY:
    // The function contract establishes callback provenance for U.
    unsafe { Callback::<U>::data(context) }
}

/// Type-erased callback state borrowed by one personality or trace invocation. borrowed by one
/// personality or trace invocation.
// NOTE(invariant): cursor names the live traversal state and frame, when present,
// names metadata resolved from that same cursor position until the callback returns.
struct Callback<U: Unwinder> {
    /// Mutable physical cursor exposed through the opaque ABI context.
    cursor: NonNull<Cursor<U>>,

    /// Resolved frame associated with the cursor position when one exists.
    frame: Option<NonNull<Info>>,
}

impl<U: Unwinder> Callback<U> {
    /// Borrows one cursor as an opaque callback context.
    fn new(cursor: &mut Cursor<U>, frame: Option<&Info>) -> Self {
        let cursor = NonNull::from(cursor);
        let frame = frame.map(NonNull::from);

        Self { cursor, frame }
    }

    /// Reinterprets the callback value as the public opaque context.
    #[inline]
    const fn ptr(&mut self) -> *mut Context {
        ptr::from_mut(self).cast()
    }

    /// Recovers the internal callback value from an ABI context pointer.
    ///
    /// # Safety
    ///
    /// `context` must be the live pointer created by [`Callback::ptr`] for the
    /// active Desenredo callback invocation using this same `U`.
    unsafe fn borrow<'a>(context: *mut Context) -> Option<&'a mut Self> {
        let mut raw = NonNull::new(context.cast::<Self>())?;

        // SAFETY:
        // The method contract proves the pointer was created from one live Callback.
        Some(unsafe { raw.as_mut() })
    }

    /// Returns read-only access to the current physical cursor.
    const fn view(&self) -> &Cursor<U> {
        let &Self { cursor, .. } = self;

        // SAFETY:
        // The Callback invariant keeps this pointer live for the complete callback.
        unsafe { cursor.as_ref() }
    }

    /// Returns unique mutable access to the current physical cursor.
    const fn cursor(&mut self) -> &mut Cursor<U> {
        let &mut Self { ref mut cursor, .. } = self;

        // SAFETY:
        // The active callback owns the unique mutation capability for the cursor.
        unsafe { cursor.as_mut() }
    }

    /// Returns the resolved frame when this is not the end callback.
    const fn frame(&self) -> Option<&Info> {
        let &Self { frame, .. } = self;

        match frame {
            Some(frame) => {
                // SAFETY:
                // The Callback invariant ties the resolved frame to this callback lifetime.
                Some(unsafe { frame.as_ref() })
            },
            None => None,
        }
    }

    /// Converts a C ABI register number into a DWARF register identity.
    #[inline]
    fn decode(index: c_int) -> Option<Register> {
        u16::try_from(index).ok().map(Register)
    }

    /// Reads one ABI-visible register value.
    fn read(&self, index: c_int) -> usize {
        let register = Self::decode(index);
        let end = Self::frame(self).is_none();

        match (register, end) {
            (Some(X86_64::RSP), true) => 0,
            (Some(register), _) => Self::view(self).read(register).unwrap_or(0),
            (None, _) => 0,
        }
    }

    /// Writes one ABI-visible register value.
    fn set(&mut self, index: c_int, value: usize) {
        let register = Self::decode(index);

        if let Some(register) = register {
            let _: Result<(), UnwindError> = Self::cursor(self).write(register, value);
        }
    }

    /// Returns the ABI instruction pointer.
    #[inline]
    const fn pc(&self) -> usize {
        match Self::view(self).ip() {
            Some(ip) => ip,
            None => 0,
        }
    }

    /// Returns the ABI canonical frame address.
    #[inline]
    const fn base(&self) -> usize {
        match Self::frame(self) {
            Some(_) => match Self::view(self).stack() {
                Ok(stack) => stack,
                Err(_) => 0,
            },
            None => 0,
        }
    }

    /// Reads one DWARF register from an active callback context.
    ///
    /// # Safety
    ///
    /// `context` must be the live Desenredo context for the current ABI callback.
    unsafe fn reg(context: *mut Context, index: c_int) -> usize {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };

        match callback {
            Some(callback) => callback.read(index),
            None => 0,
        }
    }

    /// Writes one DWARF register in an active cleanup callback context.
    ///
    /// # Safety
    ///
    /// `context` must be the live mutable Desenredo context for the current
    /// cleanup callback and `index` must identify a writable target register.
    unsafe fn write(context: *mut Context, index: c_int, value: usize) {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };

        if let Some(callback) = callback {
            callback.set(index, value);
        }
    }

    /// Reads the instruction pointer from an active callback context.
    ///
    /// # Safety
    ///
    /// `context` must be the live Desenredo context for the current ABI callback.
    unsafe fn ip(context: *mut Context) -> usize {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };

        match callback {
            Some(callback) => callback.pc(),
            None => 0,
        }
    }

    /// Reads the instruction pointer and its instruction relation.
    ///
    /// # Safety
    ///
    /// `context` must be live for the active callback and `before` must point to
    /// writable `c_int` storage.
    unsafe fn info(context: *mut Context, before: *mut c_int) -> usize {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };

        match callback {
            Some(callback) => {
                let flag = c_int::from(Self::view(callback).relation().before());

                if let Some(output) = NonNull::new(before) {
                    // SAFETY:
                    // The method contract proves this output pointer is writable.
                    unsafe { output.as_ptr().write(flag) };
                }

                callback.pc()
            },
            None => 0,
        }
    }

    /// Writes the instruction pointer in an active cleanup callback context.
    ///
    /// # Safety
    ///
    /// `context` must be the live mutable Desenredo context and `value` must name
    /// a valid landing pad.
    unsafe fn jump(context: *mut Context, value: usize) {
        let Register(index) = X86_64::RA;

        let index = c_int::from(index);

        // SAFETY:
        // The method contract is the same mutation contract required by write.
        unsafe { Self::write(context, index, value) }
    }

    /// Reads the canonical frame address from an active callback context.
    ///
    /// # Safety
    ///
    /// `context` must be the live Desenredo context for the current ABI callback.
    unsafe fn cfa(context: *mut Context) -> usize {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };

        match callback {
            Some(callback) => callback.base(),
            None => 0,
        }
    }

    /// Reads the LSDA pointer for the active callback frame.
    ///
    /// # Safety
    ///
    /// `context` must be the live Desenredo context for the current ABI callback.
    unsafe fn lsda(context: *mut Context) -> *const u8 {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };
        let address = match callback.and_then(|callback| callback.frame()) {
            Some(frame) => frame.lsda::<U>().ok().flatten(),
            None => None,
        };

        match address {
            Some(address) => ptr::with_exposed_provenance(address),
            None => ptr::null(),
        }
    }

    /// Reads the code region start for the active callback frame.
    ///
    /// # Safety
    ///
    /// `context` must be the live Desenredo context for the current ABI callback.
    unsafe fn start(context: *mut Context) -> usize {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };

        match callback.and_then(|callback| callback.frame()) {
            Some(frame) => frame.start().unwrap_or(0),
            None => 0,
        }
    }

    /// Reads the text relative base for the active callback frame.
    ///
    /// # Safety
    ///
    /// `context` must be the live Desenredo context for the current ABI callback.
    unsafe fn text(context: *mut Context) -> usize {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };

        match callback.and_then(|callback| callback.frame()) {
            Some(frame) => frame.text(),
            None => 0,
        }
    }

    /// Reads the data relative base for the active callback frame.
    ///
    /// # Safety
    ///
    /// `context` must be the live Desenredo context for the current ABI callback.
    unsafe fn data(context: *mut Context) -> usize {
        // SAFETY:
        // The method contract establishes Callback provenance for context.
        let callback = unsafe { Self::borrow(context) };

        let data = callback.and_then(|callback| callback.frame()).and_then(Info::data);

        data.unwrap_or_default()
    }
}

/// Forced unwind state retained in the exception private words.
#[derive(Copy, Clone)]
// NOTE(invariant): stop and parameter remain a valid callback pair for the
// complete forced traversal and are encoded and decoded together.
struct Forced {
    /// External stop callback controlling the forced traversal.
    stop: StopFn,

    /// Opaque parameter forwarded to the stop callback.
    parameter: *mut c_void,
}

/// Resume state encoded in the two unwinder-private exception words.
// Normal state encodes a zero first word and one frame key while forced state
// encodes a nonzero stop function and its paired parameter.
#[derive(Copy, Clone)]
enum Resume {
    /// Normal phase two using the handler selected during phase one.
    Normal(Key),

    /// Single-phase forced traversal controlled by an external stop callback.
    Forced(Forced),
}

impl Resume {
    /// Stores one resume state in the active exception object.
    ///
    /// # Safety
    ///
    /// `exception` must be exclusively owned by the active Desenredo unwinder.
    unsafe fn write(self, mut exception: NonNull<Exception>) {
        let words = match self {
            Self::Normal(handler) => [0, handler.get()],
            Self::Forced(Forced { stop, parameter }) => [stop as usize, parameter.addr()],
        };

        // SAFETY:
        // The method contract grants this invocation exclusive private-word access.
        let mut private = unsafe { exception.as_mut().private() };

        private.write(words);
    }

    /// Recovers the resume state stored by this unwinder.
    ///
    /// # Safety
    ///
    /// `exception` must still carry private words written by [`Resume::write`].
    unsafe fn read(mut exception: NonNull<Exception>) -> Self {
        // SAFETY:
        // The method contract grants this invocation exclusive private-word access.
        let private = unsafe { exception.as_mut().private() };

        let [first, second] = private.words();

        match NonZeroUsize::new(first) {
            None => {
                // SAFETY:
                // Resume::write stored the exact key produced by Cursor::key.
                Self::Normal(unsafe { Key::new(second) })
            },
            Some(stop) => {
                // SAFETY:
                // Resume::write stores the exact StopFn representation in this word.
                let stop = unsafe { transmute::<usize, StopFn>(stop.get()) };
                let parameter = ptr::with_exposed_provenance_mut(second);

                Self::Forced(Forced { stop, parameter })
            },
        }
    }
}

/// One active physical propagation pass.
// NOTE(invariant): cursor, exception, and class describe one live propagation and remain coherent
// until the pass terminates or installs a landing pad. Construction consumes one captured caller
// state and one live exception ownership capability.
struct Walk<U: Unwinder> {
    /// Physical cursor for the current pass.
    cursor: Cursor<U>,

    /// Live exception owned by this propagation.
    exception: NonNull<Exception>,

    /// Exception class copied from the live header.
    class: ExceptionClass,
}

impl<U: Unwinder> Walk<U> {
    /// Creates one propagation pass from a captured machine state.
    const fn new(state: State, exception: NonNull<Exception>, class: ExceptionClass) -> Self {
        let cursor = Cursor::<U>::new(state);

        Self {
            cursor,
            exception,
            class,
        }
    }

    /// Starts a fresh normal propagation from one validated caller state.
    ///
    /// # Safety
    ///
    /// `exception` must remain exclusively owned by this unwinder until the
    /// propagation returns or transfers control to a landing pad.
    unsafe fn begin(state: State, exception: NonNull<Exception>) -> ReasonCode {
        // SAFETY:
        // The method contract keeps the producer-owned header live here.
        let class = unsafe { exception.as_ref().class() };
        let search = Self::new(state.clone(), exception, class);
        let handler = match search.search() {
            Ok(handler) => handler,
            Err(reason) => return reason,
        };

        // SAFETY:
        // Search has finished and the unwinder now owns resume state.
        unsafe { Resume::Normal(handler).write(exception) };

        Self::new(state, exception, class).normal(handler)
    }

    /// Starts normal two phase exception propagation.
    ///
    /// # Safety
    ///
    /// `exception` must satisfy the active unwinder ownership contract from
    /// [`Exception`].
    unsafe fn raise(state: State, exception: *mut Exception) -> ReasonCode {
        let root = state;
        let exception = match NonNull::new(exception) {
            Some(exception) => exception,
            None => return ReasonCode::FATAL1,
        };

        // SAFETY:
        // The entry contract transfers this live exception into fresh propagation.
        unsafe { Self::begin(root, exception) }
    }

    /// Starts a forced single phase unwind.
    ///
    /// # Safety
    ///
    /// `exception`, `stop`, and `parameter` must satisfy the Level I forced
    /// unwind ownership and callback contracts.
    unsafe fn forced(state: State, exception: *mut Exception, stop: StopFn, parameter: *mut c_void) -> ReasonCode {
        let root = state;
        let exception = match NonNull::new(exception) {
            Some(exception) => exception,
            None => return ReasonCode::FATAL2,
        };
        // SAFETY:
        // The method contract keeps the producer-owned header live here.
        let class = unsafe { exception.as_ref().class() };
        let forced = Forced { stop, parameter };

        // SAFETY:
        // The unwinder owns the exception private words for this traversal.
        unsafe { Resume::Forced(forced).write(exception) };

        Self::new(root, exception, class).force(forced)
    }

    /// Resumes the active unwind after one cleanup landing pad.
    ///
    /// # Safety
    ///
    /// `exception` must carry resume state written by the active Desenredo
    /// unwind.
    unsafe fn resume(state: State, exception: *mut Exception) -> ! {
        let exception = match NonNull::new(exception) {
            Some(exception) => exception,
            None => trap(),
        };
        // SAFETY:
        // The method contract proves these private words belong to this unwind.
        let resume = unsafe { Resume::read(exception) };
        // SAFETY:
        // The method contract keeps the producer-owned class field live.
        let class = unsafe { exception.as_ref().class() };

        match resume {
            Resume::Normal(handler) => {
                Self::new(state, exception, class).normal(handler);
            },
            Resume::Forced(forced) => {
                Self::new(state, exception, class).force(forced);
            },
        }

        trap()
    }

    /// Resumes forced propagation or starts a fresh normal rethrow.
    ///
    /// # Safety
    ///
    /// `exception` must be the live object owned by the current handler or
    /// forced traversal according to the GNU Level I extension contract.
    unsafe fn rethrow(state: State, exception: *mut Exception) -> ReasonCode {
        let exception = match NonNull::new(exception) {
            Some(exception) => exception,
            None => return ReasonCode::FATAL2,
        };
        // SAFETY:
        // The method contract proves these private words belong to this unwind.
        let resume = unsafe { Resume::read(exception) };

        match resume {
            Resume::Normal(_) => {
                // SAFETY:
                // Normal rethrow starts a fresh propagation with this live object.
                unsafe { Self::begin(state, exception) }
            },
            Resume::Forced(forced) => {
                // SAFETY:
                // The method contract keeps the producer-owned class field live.
                let class = unsafe { exception.as_ref().class() };

                Self::new(state, exception, class).force(forced)
            },
        }
    }

    /// Walks physical frames without executing cleanup landing pads.
    ///
    /// # Safety
    ///
    /// `visit` and `parameter` must remain valid for the complete callback
    /// sequence.
    unsafe fn trace(state: State, visit: TraceFn, parameter: *mut c_void) -> ReasonCode {
        let mut cursor = Cursor::<U>::new(state);

        loop {
            let info = match cursor.current() {
                Ok(Some(info)) => info,
                Ok(None) => return ReasonCode::END,
                Err(_) => return ReasonCode::FATAL1,
            };
            let reason = {
                let mut callback = Callback::new(&mut cursor, Some(&info));

                // SAFETY:
                // The callback receives one live context and caller-owned data.
                unsafe { visit(callback.ptr(), parameter) }
            };

            match reason {
                ReasonCode::NONE => match cursor.advance(&info) {
                    Ok(()) => {},
                    Err(_) => return ReasonCode::FATAL1,
                },
                _ => return ReasonCode::FATAL1,
            }
        }
    }

    /// Invokes the current frame personality.
    fn personality(
        cursor: &mut Cursor<U>,
        exception: NonNull<Exception>,
        class: ExceptionClass,
        info: &Info,
        actions: Actions,
    ) -> Result<Option<ReasonCode>, UnwindError> {
        let personality = info.personality::<U>()?;

        match personality {
            None => Ok(None),
            Some(address) => {
                let address = NonZeroUsize::new(address).ok_or(UnwindError::Address)?;

                // SAFETY:
                // Trusted FDE metadata identifies this nonzero address as a personality routine.
                let personality = unsafe { transmute::<usize, PersonalityFn>(address.get()) };
                let mut callback = Callback::new(cursor, Some(info));

                // SAFETY:
                // The frame metadata supplies the callback and all arguments remain live for this
                // call.
                let reason = unsafe { personality(VERSION, actions, class, exception.as_ptr(), callback.ptr()) };

                Ok(Some(reason))
            },
        }
    }

    /// Searches older physical frames for one handler.
    fn search(self) -> Result<Key, ReasonCode> {
        let Self {
            mut cursor,
            exception,
            class,
        } = self;

        loop {
            let info = cursor.current().map_err(|_error| ReasonCode::FATAL1)?;
            let info = match info {
                Some(info) => info,
                None => return Err(ReasonCode::END),
            };
            let reason = Self::personality(&mut cursor, exception, class, &info, Actions::SEARCH)
                .map_err(|_error| ReasonCode::FATAL1)?;

            match reason {
                None | Some(ReasonCode::CONTINUE) => {
                    cursor.advance(&info).map_err(|_error| ReasonCode::FATAL1)?;
                },
                Some(ReasonCode::HANDLER) => return cursor.key().map_err(|_error| ReasonCode::FATAL1),
                Some(_) => return Err(ReasonCode::FATAL1),
            }
        }
    }

    /// Runs normal phase two from this physical root.
    fn normal(self, handler: Key) -> ReasonCode {
        let Self {
            mut cursor,
            exception,
            class,
        } = self;

        loop {
            let info = match cursor.current() {
                Ok(Some(info)) => info,
                Ok(None) | Err(_) => return ReasonCode::FATAL2,
            };
            let selected = match cursor.key() {
                Ok(key) => key == handler,
                Err(_) => return ReasonCode::FATAL2,
            };
            let actions = if selected {
                Actions::CLEANUP | Actions::HANDLER
            } else {
                Actions::CLEANUP
            };
            let reason = Self::personality(&mut cursor, exception, class, &info, actions);

            match (selected, reason) {
                (_, Ok(Some(ReasonCode::INSTALL))) => {
                    let size = match info.args() {
                        Ok(size) => size,
                        Err(_) => return ReasonCode::FATAL2,
                    };

                    match cursor.adjust(size) {
                        Ok(()) => {},
                        Err(_) => return ReasonCode::FATAL2,
                    }

                    let state = cursor.take();
                    let install = match state.install() {
                        Ok(install) => install,
                        Err(_) => return ReasonCode::FATAL2,
                    };

                    // SAFETY:
                    // The personality prepared this live phase two state for installation.
                    unsafe { install.restore() }
                },
                (false, Ok(None | Some(ReasonCode::CONTINUE))) => match cursor.advance(&info) {
                    Ok(()) => {},
                    Err(_) => return ReasonCode::FATAL2,
                },
                (true, Ok(None | Some(ReasonCode::CONTINUE))) | (_, Ok(Some(_))) | (_, Err(_)) => {
                    return ReasonCode::FATAL2;
                },
            }
        }
    }

    /// Runs one forced cleanup pass from this physical root.
    fn force(self, forced: Forced) -> ReasonCode {
        let Self {
            mut cursor,
            exception,
            class,
        } = self;

        let Forced { stop, parameter } = forced;

        loop {
            let info = match cursor.current() {
                Ok(info) => info,
                Err(_) => return ReasonCode::FATAL2,
            };
            let actions = match info {
                Some(_) => Actions::FORCE | Actions::CLEANUP,
                None => Actions::FORCE | Actions::CLEANUP | Actions::END,
            };
            let stop_reason = {
                let mut callback = Callback::new(&mut cursor, info.as_ref());

                // SAFETY:
                // The forced state owns this callback and parameter until traversal finishes.
                unsafe { stop(VERSION, actions, class, exception.as_ptr(), callback.ptr(), parameter) }
            };

            match stop_reason {
                ReasonCode::NONE => {},
                _ => return ReasonCode::FATAL2,
            }

            let info = match info {
                Some(info) => info,
                None => return ReasonCode::END,
            };
            let reason = Self::personality(&mut cursor, exception, class, &info, Actions::FORCE | Actions::CLEANUP);

            match reason {
                Ok(None | Some(ReasonCode::CONTINUE)) => match cursor.advance(&info) {
                    Ok(()) => {},
                    Err(_) => return ReasonCode::FATAL2,
                },
                Ok(Some(ReasonCode::INSTALL)) => {
                    let size = match info.args() {
                        Ok(size) => size,
                        Err(_) => return ReasonCode::FATAL2,
                    };

                    match cursor.adjust(size) {
                        Ok(()) => {},
                        Err(_) => return ReasonCode::FATAL2,
                    }

                    let state = cursor.take();
                    let install = match state.install() {
                        Ok(install) => install,
                        Err(_) => return ReasonCode::FATAL2,
                    };

                    // SAFETY:
                    // The forced personality prepared this live cleanup state.
                    unsafe { install.restore() }
                },
                Ok(Some(_)) | Err(_) => return ReasonCode::FATAL2,
            }
        }
    }
}

/// Starts normal propagation from one architecture-validated caller state.
///
/// # Safety
///
/// `exception` must satisfy the Level I live exception ownership contract.
#[doc(hidden)]
#[inline]
pub unsafe fn raise<U>(state: State, exception: *mut Exception) -> ReasonCode
where
    U: Unwinder,
{
    // SAFETY:
    // The caller supplies one architecture-validated semantic state and live exception.
    unsafe { Walk::<U>::raise(state, exception) }
}

/// Starts forced propagation from one architecture-validated caller state.
///
/// # Safety
///
/// The exception, stop callback, and parameter must satisfy the Level I forced
/// unwind contract for the complete traversal.
#[doc(hidden)]
#[inline]
pub unsafe fn force<U>(state: State, exception: *mut Exception, stop: StopFn, parameter: *mut c_void) -> ReasonCode
where
    U: Unwinder,
{
    // SAFETY:
    // The caller supplies one validated state and the complete forced-unwind capability.
    unsafe { Walk::<U>::forced(state, exception, stop, parameter) }
}

/// Resumes propagation from one architecture-validated cleanup caller state.
///
/// # Safety
///
/// `exception` must carry Desenredo resume state for the active propagation.
#[doc(hidden)]
#[inline]
pub unsafe fn resume<U>(state: State, exception: *mut Exception) -> !
where
    U: Unwinder,
{
    // SAFETY:
    // The caller supplies the semantic state captured at the cleanup resume boundary.
    unsafe { Walk::<U>::resume(state, exception) }
}

/// Reraises or resumes forced propagation from one validated caller state.
///
/// # Safety
///
/// `exception` must be the live object owned by the current handler or forced traversal.
#[doc(hidden)]
#[inline]
pub unsafe fn rethrow<U>(state: State, exception: *mut Exception) -> ReasonCode
where
    U: Unwinder,
{
    // SAFETY:
    // The caller supplies one validated semantic state and active exception object.
    unsafe { Walk::<U>::rethrow(state, exception) }
}

/// Walks physical frames from one architecture-validated caller state.
///
/// # Safety
///
/// `visit` and `parameter` must remain valid for the complete callback sequence.
#[doc(hidden)]
#[inline]
pub unsafe fn trace<U>(state: State, visit: TraceFn, parameter: *mut c_void) -> ReasonCode
where
    U: Unwinder,
{
    // SAFETY:
    // The caller supplies one validated state and a live trace callback pair.
    unsafe { Walk::<U>::trace(state, visit, parameter) }
}
