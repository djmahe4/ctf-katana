use rayon::prelude::*;
use std::time::Instant;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn check_magic(data: &[u8], key: &[u8], magic: &[u8]) -> bool {
    for (i, &m) in magic.iter().enumerate() {
        if (data[i] ^ key[i % key.len()]) != m {
            return false;
        }
    }
    true
}

fn main() {
    // Test Setup (same as Python)
    let original = b"FLAG{B_TECH_THESIS_2026_EXPERIMENT_SUCCESS}";
    let true_key = [0xDE, 0xAD, 0xBE, 0xEF]; // 4-byte key for stress test
    
    let ciphertext: Vec<u8> = original.iter().enumerate()
        .map(|(i, &b)| b ^ true_key[i % true_key.len()])
        .collect();
    
    let magic = b"FLAG{";
    
    println!("[*] Starting Rust Parallel XOR Brute-force (4-byte key)");
    println!("[*] Ciphertext (hex): {}", hex::encode(&ciphertext));
    println!("[*] CPU Cores detected: {}", num_cpus::get());

    // 1. Single-threaded Baseline
    println!("\n[*] Running Single-threaded benchmark...");
    let start_single = Instant::now();
    let mut found_single = None;
    for i in 0..u32::MAX {
        let k = i.to_be_bytes();
        if check_magic(&ciphertext, &k, magic) {
            found_single = Some(k);
            break;
        }
    }
    let duration_single = start_single.elapsed();
    if let Some(k) = found_single {
        println!("[+] Single-thread success: {} in {:?}", hex::encode(k), duration_single);
    }

    // 2. Parallel (Rayon) Benchmark
    println!("\n[*] Running Multi-threaded (Rayon) benchmark...");
    let start_parallel = Instant::now();
    let found_flag = Arc::new(AtomicBool::new(false));
    
    let found_parallel: Option<[u8; 4]> = (0..u32::MAX).into_par_iter()
        .map(|i| i.to_be_bytes())
        .find_any(|k| {
            if found_flag.load(Ordering::Relaxed) {
                return false;
            }
            if check_magic(&ciphertext, k, magic) {
                found_flag.store(true, Ordering::Relaxed);
                return true;
            }
            false
        });
        
    let duration_parallel = start_parallel.elapsed();
    
    if let Some(k) = found_parallel {
        let decrypted = xor_decrypt(&ciphertext, &k);
        println!("[+] Parallel success: {} in {:?}", hex::encode(k), duration_parallel);
        println!("[+] Decrypted: {}", String::from_utf8_lossy(&decrypted));
    }
    
    let speedup = duration_single.as_secs_f64() / duration_parallel.as_secs_f64();
    println!("\n[!] Parallel Speedup: {:.2}x", speedup);
}
