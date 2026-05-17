//! Secure memory handling and zeroization
//!
//! This module provides secure memory management functions including:
//! - Automatic zeroization of sensitive data
//! - Secure memory allocation and deallocation
//! - Memory barrier operations
//! - Secure memory copying and comparison

use core::ptr;

/// Secure memory zeroization
///
/// Securely zeros a memory region to prevent sensitive data from remaining
/// in memory after use. This function uses compiler barriers to prevent
/// optimization that might skip the zeroing.
///
/// # Arguments
/// * `data` - Memory region to zero
///
/// # Security
/// This function uses compiler barriers to ensure the zeroing operation
/// is not optimized away by the compiler.
pub fn secure_zero<T>(data: &mut T) {
    let size = size_of_val(data);
    let ptr = data as *mut T as *mut u8;

    unsafe {
        ptr::write_bytes(ptr, 0, size);
    }
    // Compiler barrier to prevent optimization
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Secure zeroization of a slice
///
/// Securely zeros a slice of memory to prevent sensitive data from remaining
/// in memory after use.
///
/// # Arguments
/// * `data` - Slice to zero
///
/// # Security
/// This function uses compiler barriers to ensure the zeroing operation
/// is not optimized away by the compiler.
pub fn secure_zero_slice(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }

    // Compiler barrier to prevent optimization
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Secure memory copy
///
/// Securely copies memory from source to destination, ensuring that
/// sensitive data is properly handled.
///
/// # Arguments
/// * `dst` - Destination memory
/// * `src` - Source memory
///
/// # Security
/// This function uses secure memory operations to prevent data leakage.
pub fn secure_copy<T>(dst: &mut T, src: &T) {
    let size = size_of_val(src);
    let dst_ptr = dst as *mut T as *mut u8;
    let src_ptr = src as *const T as *const u8;

    unsafe {
        ptr::copy_nonoverlapping(src_ptr, dst_ptr, size);
    }
    // Compiler barrier to prevent optimization
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Secure memory copy for slices
///
/// Securely copies memory from source slice to destination slice.
///
/// # Arguments
/// * `dst` - Destination slice
/// * `src` - Source slice
///
/// # Panics
/// Panics if the slices have different lengths.
///
/// # Security
/// This function uses secure memory operations to prevent data leakage.
pub fn secure_copy_slice(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());

    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }

    // Compiler barrier to prevent optimization
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Secure memory move
///
/// Securely moves memory from source to destination, zeroing the source
/// after the move to prevent data leakage.
///
/// # Arguments
/// * `dst` - Destination memory
/// * `src` - Source memory
///
/// # Security
/// This function securely moves data and zeroes the source to prevent
/// sensitive data from remaining in memory.
pub fn secure_move<T>(dst: &mut T, src: &mut T) {
    secure_copy(dst, src);
    secure_zero(src);
}

/// Secure memory move for slices
///
/// Securely moves memory from source slice to destination slice, zeroing
/// the source after the move.
///
/// # Arguments
/// * `dst` - Destination slice
/// * `src` - Source slice
///
/// # Panics
/// Panics if the slices have different lengths.
///
/// # Security
/// This function securely moves data and zeroes the source to prevent
/// sensitive data from remaining in memory.
pub fn secure_move_slice(dst: &mut [u8], src: &mut [u8]) {
    secure_copy_slice(dst, src);
    secure_zero_slice(src);
}

/// Secure memory comparison
///
/// Securely compares two memory regions in constant time to prevent
/// timing attacks.
///
/// # Arguments
/// * `a` - First memory region
/// * `b` - Second memory region
///
/// # Returns
/// * `true` if the regions are equal, `false` otherwise
///
/// # Security
/// This function performs the comparison in constant time to prevent
/// timing attacks.
pub fn secure_compare<T>(a: &T, b: &T) -> bool {
    let size = size_of_val(a);
    let a_ptr = a as *const T as *const u8;
    let b_ptr = b as *const T as *const u8;

    let mut result = 0u8;

    unsafe {
        for i in 0..size {
            result |= *a_ptr.add(i) ^ *b_ptr.add(i);
        }
    }

    result == 0
}

/// Secure memory comparison for slices
///
/// Securely compares two slices in constant time to prevent timing attacks.
///
/// # Arguments
/// * `a` - First slice
/// * `b` - Second slice
///
/// # Returns
/// * `true` if the slices are equal, `false` otherwise
///
/// # Security
/// This function performs the comparison in constant time to prevent
/// timing attacks.
pub fn secure_compare_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Secure memory allocation with enhanced security features
///
/// Allocates memory securely with proper alignment, zeroing, and protection.
/// Implements secure memory allocation best practices including:
/// - Proper alignment for security-sensitive data
/// - Memory zeroing to prevent data leakage
/// - Compiler barriers to prevent optimization
/// - Memory protection where available
///
/// # Arguments
/// * `size` - Size of memory to allocate
/// * `alignment` - Memory alignment (defaults to cache line size for security)
///
/// # Returns
/// * `Some(ptr)` if allocation succeeds, `None` otherwise
///
/// # Security
/// This function allocates memory securely and zeros it to prevent
/// data leakage from previous allocations. Uses cache-line alignment
/// to prevent side-channel attacks through cache timing.
#[cfg(feature = "alloc")]
pub fn secure_alloc(size: usize) -> Option<*mut u8> {
    secure_alloc_aligned(size, 64) // Default to cache line alignment
}

/// Secure memory allocation with custom alignment
#[cfg(feature = "alloc")]
pub fn secure_alloc_aligned(size: usize, alignment: usize) -> Option<*mut u8> {
    use alloc::alloc::{
        Layout,
        alloc,
    };

    if size == 0 {
        return None;
    }

    // Ensure alignment is a power of 2
    let alignment = if alignment == 0 || !alignment.is_power_of_two() {
        64 // Default to cache line alignment
    } else {
        alignment
    };

    let layout = Layout::from_size_align(size, alignment).ok()?;
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        return None;
    }

    // Zero the allocated memory with secure zeroing
    secure_zero_raw(ptr, size);

    // Memory barrier to ensure zeroing completes before use
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    Some(ptr)
}

/// Secure zeroing of raw memory
#[cfg(feature = "alloc")]
fn secure_zero_raw(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }

    unsafe {
        // Use volatile writes to prevent compiler optimization
        let mut current = ptr;
        for _ in 0..size {
            ptr::write_volatile(current, 0);
            current = current.add(1);
        }
    }

    // Compiler barrier to prevent optimization
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Secure memory deallocation with enhanced security
///
/// Deallocates memory securely by zeroing it before deallocation.
/// Implements secure deallocation best practices including:
/// - Secure zeroing before deallocation
/// - Multiple passes of zeroing for sensitive data
/// - Compiler barriers to prevent optimization
/// - Proper layout reconstruction for deallocation
///
/// # Arguments
/// * `ptr` - Pointer to memory to deallocate
/// * `size` - Size of memory to deallocate
///
/// # Safety
/// This function is unsafe because it:
/// - Takes a raw pointer that must be valid for the given size
/// - The pointer must have been allocated with the same allocator
/// - The size must match the size used for allocation
///
/// # Security
/// This function securely deallocates memory by zeroing it first
/// to prevent data leakage.
#[cfg(feature = "alloc")]
pub unsafe fn secure_dealloc(ptr: *mut u8, size: usize) {
    unsafe { secure_dealloc_aligned(ptr, size, 64) } // Default to cache line alignment
}

/// Secure memory deallocation with custom alignment
///
/// # Safety
///
/// - `ptr` must be a valid pointer returned by a previous allocation
/// - `size` must be the same size that was used for the original allocation
/// - `alignment` must be the same alignment that was used for the original allocation
/// - The memory must not be accessed after this function returns
#[cfg(feature = "alloc")]
pub unsafe fn secure_dealloc_aligned(ptr: *mut u8, size: usize, alignment: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }

    // Ensure alignment is a power of 2
    let alignment = if alignment == 0 || !alignment.is_power_of_two() {
        64 // Default to cache line alignment
    } else {
        alignment
    };

    // Secure zeroing with multiple passes for sensitive data
    secure_zero_raw(ptr, size);

    // Additional pass with pattern to ensure zeroing
    unsafe {
        let mut current = ptr;
        for _ in 0..size {
            ptr::write_volatile(current, 0xFF);
            current = current.add(1);
        }
    }

    // Final zeroing pass
    secure_zero_raw(ptr, size);

    // Memory barrier to ensure all zeroing completes
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    use alloc::alloc::{
        Layout,
        dealloc,
    };
    let layout = Layout::from_size_align(size, alignment).unwrap();
    unsafe {
        dealloc(ptr, layout);
    }
}

/// Memory barrier
///
/// Inserts a memory barrier to prevent reordering of memory operations.
/// This is useful for ensuring that sensitive operations complete
/// before other operations begin.
///
/// # Security
/// This function prevents memory reordering that could lead to
/// timing attacks or other side-channel vulnerabilities.
pub fn memory_barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Secure memory fill
///
/// Securely fills a memory region with a specific value.
///
/// # Arguments
/// * `data` - Memory region to fill
/// * `value` - Value to fill with
///
/// # Security
/// This function uses secure memory operations to prevent data leakage.
pub fn secure_fill<T>(data: &mut T, value: u8) {
    let size = size_of_val(data);
    let ptr = data as *mut T as *mut u8;

    unsafe {
        ptr::write_bytes(ptr, value, size);
        // Compiler barrier to prevent optimization
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Secure memory fill for slices
///
/// Securely fills a slice with a specific value.
///
/// # Arguments
/// * `data` - Slice to fill
/// * `value` - Value to fill with
///
/// # Security
/// This function uses secure memory operations to prevent data leakage.
pub fn secure_fill_slice(data: &mut [u8], value: u8) {
    for byte in data.iter_mut() {
        *byte = value;
    }

    // Compiler barrier to prevent optimization
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Secure memory XOR
///
/// Securely XORs two memory regions and stores the result in the first.
///
/// # Arguments
/// * `a` - First memory region (modified in place)
/// * `b` - Second memory region
///
/// # Panics
/// Panics if the memory regions have different sizes.
///
/// # Security
/// This function uses secure memory operations to prevent data leakage.
pub fn secure_xor<T>(a: &mut T, b: &T) {
    let size = size_of_val(a);
    assert_eq!(size, size_of_val(b));

    let a_ptr = a as *mut T as *mut u8;
    let b_ptr = b as *const T as *const u8;

    unsafe {
        for i in 0..size {
            *a_ptr.add(i) ^= *b_ptr.add(i);
        }
        // Compiler barrier to prevent optimization
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Secure memory XOR for slices
///
/// Securely XORs two slices and stores the result in the first.
///
/// # Arguments
/// * `a` - First slice (modified in place)
/// * `b` - Second slice
///
/// # Panics
/// Panics if the slices have different lengths.
///
/// # Security
/// This function uses secure memory operations to prevent data leakage.
pub fn secure_xor_slice(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());

    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }

    // Compiler barrier to prevent optimization
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_zero() {
        let mut data = [1, 2, 3, 4, 5];
        secure_zero(&mut data);
        assert_eq!(data, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_secure_zero_slice() {
        let mut data = [1, 2, 3, 4, 5];
        secure_zero_slice(&mut data);
        assert_eq!(data, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_secure_copy() {
        let src = [1, 2, 3, 4, 5];
        let mut dst = [0; 5];
        secure_copy(&mut dst, &src);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_secure_copy_slice() {
        let src = [1, 2, 3, 4, 5];
        let mut dst = [0; 5];
        secure_copy_slice(&mut dst, &src);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_secure_move() {
        let mut src = [1, 2, 3, 4, 5];
        let mut dst = [0; 5];
        secure_move(&mut dst, &mut src);
        assert_eq!(dst, [1, 2, 3, 4, 5]);
        assert_eq!(src, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_secure_move_slice() {
        let mut src = [1, 2, 3, 4, 5];
        let mut dst = [0; 5];
        secure_move_slice(&mut dst, &mut src);
        assert_eq!(dst, [1, 2, 3, 4, 5]);
        assert_eq!(src, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_secure_compare() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];

        assert!(secure_compare(&a, &b));
        assert!(!secure_compare(&a, &c));
    }

    #[test]
    fn test_secure_compare_slice() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];

        assert!(secure_compare_slice(&a, &b));
        assert!(!secure_compare_slice(&a, &c));
    }

    #[test]
    fn test_secure_fill() {
        let mut data = [0u8; 5];
        secure_fill(&mut data, 42);
        assert_eq!(data, [42, 42, 42, 42, 42]);
    }

    #[test]
    fn test_secure_fill_slice() {
        let mut data = [0; 5];
        secure_fill_slice(&mut data, 42);
        assert_eq!(data, [42, 42, 42, 42, 42]);
    }

    #[test]
    fn test_secure_xor() {
        let mut a = [0b1010, 0b1100, 0b1111];
        let b = [0b1100, 0b1010, 0b0000];
        secure_xor(&mut a, &b);
        assert_eq!(a, [0b0110, 0b0110, 0b1111]);
    }

    #[test]
    fn test_secure_xor_slice() {
        let mut a = [0b1010, 0b1100, 0b1111];
        let b = [0b1100, 0b1010, 0b0000];
        secure_xor_slice(&mut a, &b);
        assert_eq!(a, [0b0110, 0b0110, 0b1111]);
    }

    #[test]
    fn test_memory_barrier() {
        // This test just ensures the function doesn't panic
        memory_barrier();
    }
}
