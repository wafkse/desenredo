//! Compiler ABI selection for a concrete Desenredo unwinder.
//!
//! The attribute validates one concrete unsafe `Unwinder` implementation and
//! emits only the process global Level I forwarding symbols required by compiler
//! generated exception handling code.
//!
//! ```text
//! unsafe impl Unwinder for Image
//!              |
//!       `#[desenredo::unwind]`
//!              |
//!              v
//!     process global `_Unwind_*`
//!              |
//!              v
//!   `desenredo-unwind::arch::x86_64::entry`
//!              |
//!              v
//!       physical traversal
//! ```
//!
//! The generated symbol names and calling contracts are the Level I interface
//! from the [Itanium C++ ABI exception handling specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! The macro does not choose image lookup, memory authority, linker placement, or
//! language personality policy. Those remain properties of the selected runtime
//! and final image.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::quote;
use syn::{ItemImpl, PathArguments};

/// Selects one concrete `Unwinder` implementation for the final image ABI.
///
/// The attribute accepts no arguments. It requires a concrete non-generic unsafe
/// implementation of `desenredo::unwind::runtime::Unwinder`. The original implementation
/// is preserved and thin `_Unwind_*` forwarding symbols are emitted beside it.
#[proc_macro_attribute]
#[inline]
pub fn unwind(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = Tokens::from(args);
    let item = syn::parse_macro_input!(item as ItemImpl);

    match expand(args, item) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// Validates the selected implementation and emits its ABI forwarding surface.
fn expand(args: Tokens, item: ItemImpl) -> syn::Result<Tokens> {
    let arguments = if args.is_empty() {
        Ok(())
    } else {
        Err(syn::Error::new_spanned(args, "unwind attribute accepts no arguments"))
    };

    arguments?;
    validate(&item)?;

    let ty = &item.self_ty;
    let generated = quote! {
        #item

        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        unsafe extern "C-unwind" fn _Unwind_RaiseException(
            _exception: *mut ::desenredo::abi::unwind::Exception,
        ) -> ::desenredo::abi::unwind::ReasonCode {
            ::core::arch::naked_asm!(
                "jmp {target}",
                target = sym ::desenredo::unwind::arch::x86_64::entry::raise::<#ty>,
                options(att_syntax),
            );
        }

        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        unsafe extern "C-unwind" fn _Unwind_ForcedUnwind(
            _exception: *mut ::desenredo::abi::unwind::Exception,
            _stop: ::desenredo::abi::unwind::StopFn,
            _parameter: *mut ::core::ffi::c_void,
        ) -> ::desenredo::abi::unwind::ReasonCode {
            ::core::arch::naked_asm!(
                "jmp {target}",
                target = sym ::desenredo::unwind::arch::x86_64::entry::force::<#ty>,
                options(att_syntax),
            );
        }
    };

    let generated = quote! {
        #generated

        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        unsafe extern "C-unwind" fn _Unwind_Resume(
            _exception: *mut ::desenredo::abi::unwind::Exception,
        ) {
            ::core::arch::naked_asm!(
                "jmp {target}",
                target = sym ::desenredo::unwind::arch::x86_64::entry::resume::<#ty>,
                options(att_syntax),
            );
        }

        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        unsafe extern "C-unwind" fn _Unwind_Resume_or_Rethrow(
            _exception: *mut ::desenredo::abi::unwind::Exception,
        ) -> ::desenredo::abi::unwind::ReasonCode {
            ::core::arch::naked_asm!(
                "jmp {target}",
                target = sym ::desenredo::unwind::arch::x86_64::entry::rethrow::<#ty>,
                options(att_syntax),
            );
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_DeleteException(
            exception: *mut ::desenredo::abi::unwind::Exception,
        ) {
            unsafe { ::desenredo::unwind::runtime::delete(exception) }
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_GetGR(
            context: *mut ::desenredo::abi::unwind::Context,
            index: ::core::ffi::c_int,
        ) -> usize {
            unsafe { ::desenredo::unwind::runtime::reg::<#ty>(context, index) }
        }
    };

    let generated = quote! {
        #generated

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_SetGR(
            context: *mut ::desenredo::abi::unwind::Context,
            index: ::core::ffi::c_int,
            value: usize,
        ) {
            unsafe { ::desenredo::unwind::runtime::write::<#ty>(context, index, value) }
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_GetIP(
            context: *mut ::desenredo::abi::unwind::Context,
        ) -> usize {
            unsafe { ::desenredo::unwind::runtime::ip::<#ty>(context) }
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_GetIPInfo(
            context: *mut ::desenredo::abi::unwind::Context,
            before: *mut ::core::ffi::c_int,
        ) -> usize {
            unsafe { ::desenredo::unwind::runtime::info::<#ty>(context, before) }
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_SetIP(
            context: *mut ::desenredo::abi::unwind::Context,
            value: usize,
        ) {
            unsafe { ::desenredo::unwind::runtime::jump::<#ty>(context, value) }
        }
    };

    let generated = quote! {
        #generated

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_GetCFA(
            context: *mut ::desenredo::abi::unwind::Context,
        ) -> usize {
            unsafe { ::desenredo::unwind::runtime::cfa::<#ty>(context) }
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_GetLanguageSpecificData(
            context: *mut ::desenredo::abi::unwind::Context,
        ) -> *const u8 {
            unsafe { ::desenredo::unwind::runtime::lsda::<#ty>(context) }
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_GetRegionStart(
            context: *mut ::desenredo::abi::unwind::Context,
        ) -> usize {
            unsafe { ::desenredo::unwind::runtime::start::<#ty>(context) }
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_GetTextRelBase(
            context: *mut ::desenredo::abi::unwind::Context,
        ) -> usize {
            unsafe { ::desenredo::unwind::runtime::text::<#ty>(context) }
        }
    };

    let generated = quote! {
        #generated

        #[unsafe(no_mangle)]
        unsafe extern "C" fn _Unwind_GetDataRelBase(
            context: *mut ::desenredo::abi::unwind::Context,
        ) -> usize {
            unsafe { ::desenredo::unwind::runtime::data::<#ty>(context) }
        }

        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        unsafe extern "C" fn _Unwind_Backtrace(
            _trace: ::desenredo::abi::unwind::TraceFn,
            _parameter: *mut ::core::ffi::c_void,
        ) -> ::desenredo::abi::unwind::ReasonCode {
            ::core::arch::naked_asm!(
                "jmp {target}",
                target = sym ::desenredo::unwind::arch::x86_64::entry::trace::<#ty>,
                options(att_syntax),
            );
        }
    };

    Ok(generated)
}

/// Verifies that the selected item is one concrete unsafe `Unwinder` impl.
fn validate(item: &ItemImpl) -> syn::Result<()> {
    let &ItemImpl {
        ref modifiers,
        ref unsafety,
        ref generics,
        ref trait_,
        ..
    } = item;

    let modifier = modifiers.defaultness.is_none() && modifiers.polarity.is_none();
    let unsafe_ = unsafety.is_some();
    let generic = generics.params.is_empty() && generics.where_clause.is_none();
    let target = match trait_ {
        &Some((ref path, _)) => {
            let mut segments = path.segments.iter();
            let parts = (
                segments.next(),
                segments.next(),
                segments.next(),
                segments.next(),
                segments.next(),
            );

            match parts {
                (Some(root), Some(module), Some(runtime), Some(target), None) => {
                    root.ident == "desenredo"
                        && module.ident == "unwind"
                        && runtime.ident == "runtime"
                        && target.ident == "Unwinder"
                        && matches!(&root.arguments, PathArguments::None)
                        && matches!(&module.arguments, PathArguments::None)
                        && matches!(&runtime.arguments, PathArguments::None)
                        && matches!(&target.arguments, PathArguments::None)
                },
                _ => false,
            }
        },
        &None => false,
    };

    match (modifier, unsafe_, generic, target) {
        (true, true, true, true) => Ok(()),
        (false, _, _, _) => Err(syn::Error::new_spanned(
            item,
            "unwind attribute does not accept impl modifiers",
        )),
        (_, false, _, _) => Err(syn::Error::new_spanned(
            item,
            "unwind attribute requires an unsafe desenredo::unwind::runtime::Unwinder implementation",
        )),
        (_, _, false, _) => Err(syn::Error::new_spanned(
            &item.generics,
            "unwind attribute requires a concrete non-generic implementation",
        )),
        (_, _, _, false) => Err(syn::Error::new_spanned(
            item,
            "unwind attribute requires desenredo::unwind::runtime::Unwinder",
        )),
    }
}

#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream as Tokens;
    use syn::{ItemImpl, parse_quote};

    use super::{expand, validate};

    #[test]
    fn valid() {
        let item: ItemImpl = parse_quote!(
            unsafe impl desenredo::unwind::runtime::Unwinder for Image {}
        );

        assert!(validate(&item).is_ok());
    }

    #[test]
    fn safe() {
        let item: ItemImpl = parse_quote!(impl desenredo::unwind::runtime::Unwinder for Image {});

        assert!(validate(&item).is_err());
    }

    #[test]
    fn generic() {
        let item: ItemImpl = parse_quote!(
            unsafe impl<T> desenredo::unwind::runtime::Unwinder for Image<T> {}
        );

        assert!(validate(&item).is_err());
    }

    #[test]
    fn wrong() {
        let item: ItemImpl = parse_quote!(
            unsafe impl Other for Image {}
        );

        assert!(validate(&item).is_err());
    }

    #[test]
    fn short() {
        let item: ItemImpl = parse_quote!(
            unsafe impl Unwinder for Image {}
        );

        assert!(validate(&item).is_err());
    }

    #[test]
    fn args() {
        let item: ItemImpl = parse_quote!(
            unsafe impl desenredo::unwind::runtime::Unwinder for Image {}
        );
        let args: Tokens = quote::quote!(extra);

        assert!(expand(args, item).is_err());
    }

    #[test]
    fn symbols() {
        let item: ItemImpl = parse_quote!(
            unsafe impl desenredo::unwind::runtime::Unwinder for Image {}
        );
        let tokens = expand(Tokens::new(), item).expect("valid concrete unwinder implementation");
        let rendered = tokens.to_string();

        assert_eq!(rendered.matches("_Unwind_").count(), 16);
        assert_eq!(rendered.matches("naked_asm").count(), 5);
        assert!(rendered.contains("entry :: raise"));
        assert!(rendered.contains("entry :: trace"));
        assert_eq!(rendered.matches("att_syntax").count(), 5);
    }
}
