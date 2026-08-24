//! Reads one guarded byte-string value.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = fidelity::new().start()?;
    let bytes = fidelity::guarded_bytes!(&handle, b"\x00GuardedByteSpan2408\xff");
    println!("guarded bytes: {:02x?}", &*bytes);
    Ok(())
}
