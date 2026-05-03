use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut dir: Option<PathBuf> = None;
    for ancestor in manifest.ancestors() {
        let candidate = ancestor.join("test-vectors").join("oldmemo");
        if candidate.is_dir() {
            dir = Some(candidate);
            break;
        }
    }
    let proto_dir = dir.expect("test-vectors/oldmemo not found relative to crate");
    let proto_path = proto_dir.join("oldmemo.proto");

    println!("cargo:rerun-if-changed={}", proto_path.display());

    if env::var_os("PROTOC").is_none() {
        if let Ok(p) = protoc_bin_vendored::protoc_bin_path() {
            env::set_var("PROTOC", p);
        }
    }

    prost_build::compile_protos(&[&proto_path], &[&proto_dir]).expect("prost compile");
}
