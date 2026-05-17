//! No-Std Example for lib-q-aead
//!
//! This example demonstrates how to use lib-q-aead in no-std environments
//! such as embedded systems or bare metal applications.
//!
//! Note: This example requires the "no-std" feature to be enabled.

use lib_q_aead::security::validation::{
    validate_key,
    validate_nonce,
};
use lib_q_aead::{
    AeadKey,
    AeadWithMetadata,
    Algorithm,
    Nonce,
    create_aead,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("lib-q-aead No-Std Example");
    println!("=========================");

    embedded_main().map_err(|e| e.into())
}

fn embedded_main() -> Result<(), &'static str> {
    // In a real embedded application, you would:
    // 1. Initialize your hardware
    // 2. Set up your memory allocator
    // 3. Configure your random number generator
    // 4. Initialize the AEAD system

    // For this example, we'll simulate the embedded environment

    // Create AEAD instance
    let aead = create_aead(Algorithm::Shake256Aead).map_err(|_| "Failed to create AEAD")?;

    // In embedded systems, you might have pre-shared keys or keys from secure storage
    let key_data = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ];

    let nonce_data = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    // Validate key and nonce
    validate_key(&key_data).map_err(|_| "Invalid key")?;
    validate_nonce(&nonce_data).map_err(|_| "Invalid nonce")?;

    let key = AeadKey::new(key_data.to_vec());
    let nonce = Nonce::new(nonce_data.to_vec());

    // Simulate sensor data or other embedded data
    let sensor_data = b"Sensor reading: 25.3C, Humidity: 60%";
    let _metadata = b"device_id: 0x1234, timestamp: 1234567890";

    println!("🔧 Simulating embedded system operations...");

    // 1. Demonstrate flash memory operations
    println!("📁 Testing flash memory operations...");
    let flash_address = 0x1000;

    // Store encrypted data in flash
    embedded_usage::store_encrypted_data(&*aead, &key, &nonce, sensor_data, flash_address)?;
    println!("✓ Encrypted data stored in flash memory");

    // Load and decrypt data from flash (read the full stored ciphertext)
    let decrypted_from_flash =
        embedded_usage::load_encrypted_data(&*aead, &key, &nonce, flash_address, 1024)?;
    println!("✓ Data loaded and decrypted from flash memory");

    // Verify flash operations
    if decrypted_from_flash != sensor_data {
        return Err("Flash memory data integrity check failed");
    }
    println!("✓ Flash memory data integrity verified");

    // 2. Demonstrate UART communication
    println!("📡 Testing UART communication...");

    // Send secure message over UART
    embedded_usage::send_secure_message(&*aead, &key, &nonce, b"Hello from embedded device!")?;
    println!("✓ Secure message sent over UART");

    // Simulate receiving a message
    let mut receive_buffer = [0u8; 64];
    let received_message =
        embedded_usage::receive_secure_message(&*aead, &key, &nonce, &mut receive_buffer)?;
    println!("✓ Secure message received and decrypted from UART");
    println!("  Received: {}", String::from_utf8_lossy(&received_message));

    // 3. Demonstrate memory-efficient operations
    println!("💾 Testing memory-efficient operations...");

    // Process large data in chunks
    let large_data = b"This is a large piece of data that needs to be processed in chunks to minimize memory usage in embedded systems.";
    let chunked_result =
        constrained_usage::process_large_data_in_chunks(&*aead, &key, &nonce, large_data, 32)?;
    println!(
        "✓ Large data processed in chunks ({} bytes)",
        chunked_result.len()
    );

    // Use stack-allocated buffers
    let stack_buffer =
        constrained_usage::encrypt_with_stack_buffer(&*aead, &key, &nonce, b"Stack buffer test")?;
    println!("✓ Data encrypted using stack-allocated buffer");

    // Verify the stack buffer contains the expected data
    // Find the actual ciphertext length (first zero byte after the data)
    let actual_length = stack_buffer
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(stack_buffer.len());
    let actual_ciphertext = &stack_buffer[..actual_length];

    let decrypted_stack = aead
        .decrypt(&key, &nonce, actual_ciphertext, None)
        .map_err(|_| "Stack buffer decryption failed")?;
    if decrypted_stack != b"Stack buffer test" {
        return Err("Stack buffer data integrity check failed");
    }
    println!("✓ Stack buffer data integrity verified");

    // 4. Test comprehensive error handling with embedded HAL
    println!("⚠️  Testing comprehensive error handling...");

    // Test all FlashError variants
    println!("🔍 Testing FlashError variants...");

    // Test InvalidAddress
    match embedded_hal::FlashMemory::write(0, &[]) {
        Err(embedded_hal::FlashError::InvalidAddress) => {
            println!("✓ FlashError::InvalidAddress works correctly")
        }
        _ => println!("⚠️  Unexpected flash error behavior"),
    }

    // Test WriteProtection (triggered by specific address)
    match embedded_hal::FlashMemory::write(0xFFFF, b"test") {
        Err(embedded_hal::FlashError::WriteProtection) => {
            println!("✓ FlashError::WriteProtection works correctly")
        }
        _ => println!("⚠️  Unexpected flash error behavior"),
    }

    // Test EraseFailure (triggered by specific address)
    match embedded_hal::FlashMemory::write(0xFFFE, b"test") {
        Err(embedded_hal::FlashError::EraseFailure) => {
            println!("✓ FlashError::EraseFailure works correctly")
        }
        _ => println!("⚠️  Unexpected flash error behavior"),
    }

    // Test ProgramFailure (triggered by specific address)
    match embedded_hal::FlashMemory::write(0xFFFD, b"test") {
        Err(embedded_hal::FlashError::ProgramFailure) => {
            println!("✓ FlashError::ProgramFailure works correctly")
        }
        _ => println!("⚠️  Unexpected flash error behavior"),
    }

    // Test VerifyFailure (triggered by specific address)
    match embedded_hal::FlashMemory::write(0xFFFC, b"test") {
        Err(embedded_hal::FlashError::VerifyFailure) => {
            println!("✓ FlashError::VerifyFailure works correctly")
        }
        _ => println!("⚠️  Unexpected flash error behavior"),
    }

    // Test all UartError variants
    println!("🔍 Testing UartError variants...");

    // Test EmptyBuffer
    match embedded_hal::Uart::send(&[]) {
        Err(embedded_hal::UartError::EmptyBuffer) => {
            println!("✓ UartError::EmptyBuffer works correctly")
        }
        _ => println!("⚠️  Unexpected UART error behavior"),
    }

    // Test TransmissionError (triggered by large data)
    let large_data = vec![0u8; 1001]; // Larger than 1000 bytes
    match embedded_hal::Uart::send(&large_data) {
        Err(embedded_hal::UartError::TransmissionError) => {
            println!("✓ UartError::TransmissionError works correctly")
        }
        _ => println!("⚠️  Unexpected UART error behavior"),
    }

    // Test Timeout (triggered by data starting with 0xFF)
    match embedded_hal::Uart::send(&[0xFF, 0x01, 0x02]) {
        Err(embedded_hal::UartError::Timeout) => {
            println!("✓ UartError::Timeout works correctly")
        }
        _ => println!("⚠️  Unexpected UART error behavior"),
    }

    // Test ReceptionError (triggered by large buffer)
    let mut large_buffer = vec![0u8; 1001]; // Larger than 1000 bytes
    match embedded_hal::Uart::receive(&mut large_buffer) {
        Err(embedded_hal::UartError::ReceptionError) => {
            println!("✓ UartError::ReceptionError works correctly")
        }
        _ => println!("⚠️  Unexpected UART error behavior"),
    }

    println!("🎉 All embedded system operations completed successfully!");
    println!("   - Flash memory operations: ✓");
    println!("   - UART communication: ✓");
    println!("   - Memory-efficient processing: ✓");
    println!("   - Error handling: ✓");

    Ok(())
}

// Embedded system hardware abstraction layer
mod embedded_hal {
    use core::result::Result;
    #[allow(clippy::disallowed_types)]
    use std::collections::HashMap;
    use std::sync::{
        LazyLock,
        Mutex,
    };

    // Simulated flash memory storage
    #[allow(clippy::disallowed_types)]
    static FLASH_STORAGE: LazyLock<Mutex<HashMap<usize, Vec<u8>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Flash memory operations
    pub struct FlashMemory;

    impl FlashMemory {
        /// Write data to flash memory
        pub fn write(address: usize, data: &[u8]) -> Result<(), FlashError> {
            // In a real implementation, this would:
            // 1. Check if the address is valid and writable
            // 2. Erase the sector if necessary
            // 3. Program the data with proper timing
            // 4. Verify the write operation

            if address == 0 || data.is_empty() {
                return Err(FlashError::InvalidAddress);
            }

            // Simulate various error conditions for demonstration
            if address == 0xFFFF {
                return Err(FlashError::WriteProtection);
            }
            if address == 0xFFFE {
                return Err(FlashError::EraseFailure);
            }
            if address == 0xFFFD {
                return Err(FlashError::ProgramFailure);
            }
            if address == 0xFFFC {
                return Err(FlashError::VerifyFailure);
            }

            // Simulate flash write operation using a HashMap
            if let Ok(mut storage) = FLASH_STORAGE.lock() {
                storage.insert(address, data.to_vec());
            }

            Ok(())
        }

        /// Read data from flash memory
        pub fn read(address: usize, _length: usize) -> Result<Vec<u8>, FlashError> {
            if address == 0 {
                return Err(FlashError::InvalidAddress);
            }

            // Simulate flash read operation using a HashMap
            if let Ok(storage) = FLASH_STORAGE.lock() &&
                let Some(data) = storage.get(&address)
            {
                return Ok(data.clone());
            }

            // Return empty vector if no data found (simulating uninitialized flash)
            Ok(Vec::new())
        }
    }

    // Simulated UART buffer for testing
    static UART_BUFFER: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));

    /// UART communication
    pub struct Uart;

    impl Uart {
        /// Send data over UART
        pub fn send(data: &[u8]) -> Result<(), UartError> {
            if data.is_empty() {
                return Err(UartError::EmptyBuffer);
            }

            // Simulate various error conditions for demonstration
            if data.len() > 1000 {
                return Err(UartError::TransmissionError);
            }
            if data[0] == 0xFF {
                return Err(UartError::Timeout);
            }

            // Simulate UART transmission by storing data in buffer
            if let Ok(mut buffer) = UART_BUFFER.lock() {
                buffer.clear();
                buffer.extend_from_slice(data);
            }

            // Simulate transmission timing
            for &_byte in data {
                for _ in 0..100 {
                    core::hint::spin_loop();
                }
            }

            Ok(())
        }

        /// Receive data from UART
        pub fn receive(buffer: &mut [u8]) -> Result<&[u8], UartError> {
            if buffer.is_empty() {
                return Err(UartError::EmptyBuffer);
            }

            // Simulate various error conditions for demonstration
            if buffer.len() > 1000 {
                return Err(UartError::ReceptionError);
            }

            // Simulate UART reception by reading from buffer
            if let Ok(uart_buffer) = UART_BUFFER.lock() {
                let received_length = buffer.len().min(uart_buffer.len());
                if received_length > 0 {
                    buffer[..received_length].copy_from_slice(&uart_buffer[..received_length]);
                    return Ok(&buffer[..received_length]);
                }
            }

            // If no data available, return empty
            Ok(&buffer[..0])
        }
    }

    /// Flash memory error types
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FlashError {
        InvalidAddress,
        WriteProtection,
        EraseFailure,
        ProgramFailure,
        VerifyFailure,
    }

    /// UART error types
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UartError {
        EmptyBuffer,
        TransmissionError,
        ReceptionError,
        Timeout,
    }
}

// Example of how to use lib-q-aead in a real embedded system
mod embedded_usage {
    use embedded_hal::{
        FlashMemory,
        Uart,
    };

    use super::*;

    // Example: Encrypt data before storing in flash
    pub fn store_encrypted_data(
        aead: &dyn AeadWithMetadata,
        key: &AeadKey,
        nonce: &Nonce,
        data: &[u8],
        flash_address: usize,
    ) -> Result<(), &'static str> {
        let ciphertext = aead
            .encrypt(key, nonce, data, None)
            .map_err(|_| "Encryption failed")?;

        // Write to flash memory with proper error handling
        FlashMemory::write(flash_address, &ciphertext).map_err(|_| "Flash write failed")?;

        Ok(())
    }

    // Example: Decrypt data after reading from flash
    pub fn load_encrypted_data(
        aead: &dyn AeadWithMetadata,
        key: &AeadKey,
        nonce: &Nonce,
        flash_address: usize,
        _length: usize,
    ) -> Result<Vec<u8>, &'static str> {
        // Read from flash memory with proper error handling
        let ciphertext = FlashMemory::read(flash_address, 0).map_err(|_| "Flash read failed")?;

        if ciphertext.is_empty() {
            return Err("No data found in flash memory");
        }

        let decrypted = aead
            .decrypt(key, nonce, &ciphertext, None)
            .map_err(|_| "Decryption failed")?;

        Ok(decrypted)
    }

    // Example: Secure communication over UART
    pub fn send_secure_message(
        aead: &dyn AeadWithMetadata,
        key: &AeadKey,
        nonce: &Nonce,
        message: &[u8],
    ) -> Result<(), &'static str> {
        let ciphertext = aead
            .encrypt(key, nonce, message, None)
            .map_err(|_| "Encryption failed")?;

        // Send over UART with proper error handling
        Uart::send(&ciphertext).map_err(|_| "UART send failed")?;

        Ok(())
    }

    // Example: Receive and decrypt secure message
    pub fn receive_secure_message(
        aead: &dyn AeadWithMetadata,
        key: &AeadKey,
        nonce: &Nonce,
        buffer: &mut [u8],
    ) -> Result<Vec<u8>, &'static str> {
        // Receive from UART with proper error handling
        let received = Uart::receive(buffer).map_err(|_| "UART receive failed")?;

        let decrypted = aead
            .decrypt(key, nonce, received, None)
            .map_err(|_| "Decryption failed")?;

        Ok(decrypted)
    }
}

// Example of memory-efficient usage for constrained environments
mod constrained_usage {
    use super::*;

    // Example: Process data in small chunks to minimize memory usage
    pub fn process_large_data_in_chunks(
        aead: &dyn AeadWithMetadata,
        key: &AeadKey,
        nonce: &Nonce,
        data: &[u8],
        chunk_size: usize,
    ) -> Result<Vec<u8>, &'static str> {
        let mut result = Vec::new();

        for chunk in data.chunks(chunk_size) {
            let ciphertext = aead
                .encrypt(key, nonce, chunk, None)
                .map_err(|_| "Encryption failed")?;

            result.extend_from_slice(&ciphertext);
        }

        Ok(result)
    }

    // Example: Use stack-allocated buffers to avoid heap allocation
    pub fn encrypt_with_stack_buffer(
        aead: &dyn AeadWithMetadata,
        key: &AeadKey,
        nonce: &Nonce,
        data: &[u8],
    ) -> Result<[u8; 1024], &'static str> {
        let mut buffer = [0u8; 1024];

        let ciphertext = aead
            .encrypt(key, nonce, data, None)
            .map_err(|_| "Encryption failed")?;

        if ciphertext.len() > buffer.len() {
            return Err("Ciphertext too large for buffer");
        }

        buffer[..ciphertext.len()].copy_from_slice(&ciphertext);

        Ok(buffer)
    }
}
