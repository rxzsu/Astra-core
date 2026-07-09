fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    let proto_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("protobuf");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto_dir.join("stream.proto")], &[proto_dir.clone()])?;
    Ok(())
}
