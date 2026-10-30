//! KeyOS: the SDK's patched getrandom 0.2, which reads the hardware TRNG.
//! Added by my-app's vendored copy; not part of upstream getrandom.
use crate::Error;
use core::mem::MaybeUninit;

pub use crate::util::{inner_u32, inner_u64};

pub fn fill_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    dest.fill(MaybeUninit::new(0));
    // SAFETY: every byte was just initialized.
    let dest = unsafe { &mut *(dest as *mut [MaybeUninit<u8>] as *mut [u8]) };
    getrandom02::getrandom(dest).map_err(|_| Error::UNEXPECTED)
}
