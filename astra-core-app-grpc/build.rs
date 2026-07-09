fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    let proto_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("protobuf");
    let out_dir_str = std::env::var("OUT_DIR").unwrap();
    let out_dir = std::path::Path::new(&out_dir_str);
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(out_dir.join("api_descriptor.bin"))
        .compile_protos(
            &[proto_dir.join("api.proto")],
            std::slice::from_ref(&proto_dir),
        )?;
    Ok(())
}
