use std::env;
use std::path::PathBuf;

fn main() {
    // Locate test-vectors/twomemo/twomemo.proto by walking up from the
    // crate manifest dir until we find the workspace root that contains
    // `test-vectors/`.
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut dir: Option<PathBuf> = None;
    for ancestor in manifest.ancestors() {
        let candidate = ancestor.join("test-vectors").join("twomemo");
        if candidate.is_dir() {
            dir = Some(candidate);
            break;
        }
    }
    let proto_dir = dir.expect("test-vectors/twomemo not found relative to crate");
    let proto_path = proto_dir.join("twomemo.proto");

    println!("cargo:rerun-if-changed={}", proto_path.display());

    // Use vendored protoc so the build does not require a system install.
    if env::var_os("PROTOC").is_none() {
        if let Ok(p) = protoc_bin_vendored::protoc_bin_path() {
            env::set_var("PROTOC", p);
        }
    }

    prost_build::compile_protos(&[&proto_path], &[&proto_dir]).expect("prost compile");
}
