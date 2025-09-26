use lib_q_random::new_secure_rng;

fn main() {
    let mut rng1 = new_secure_rng().expect("Failed to create RNG");
    let mut rng2 = new_secure_rng().expect("Failed to create RNG");
    
    let mut bytes1 = [0u8; 16];
    let mut bytes2 = [0u8; 16];
    
    rng1.fill_bytes(&mut bytes1);
    rng2.fill_bytes(&mut bytes2);
    
    println!("RNG1 bytes: {:?}", bytes1);
    println!("RNG2 bytes: {:?}", bytes2);
    
    if bytes1 == bytes2 {
        println!("WARNING: RNGs generated identical bytes!");
    } else {
        println!("RNGs generated different bytes - good!");
    }
    
    // Test multiple calls to same RNG
    let mut bytes3 = [0u8; 16];
    rng1.fill_bytes(&mut bytes3);
    println!("RNG1 second call: {:?}", bytes3);
    
    if bytes1 == bytes3 {
        println!("WARNING: Same RNG generated identical bytes on second call!");
    } else {
        println!("Same RNG generated different bytes on second call - good!");
    }
}
