use std::{fs::OpenOptions, io::{BufReader, Read}, path::PathBuf};

use clap::Parser;
use log::{debug, error, trace};
use sha2_demo::sha2_hasher::SHAState;

#[derive(Debug, Parser)]
struct Args {
    files: Vec<PathBuf>,
}

fn main() {
    pretty_env_logger::init();
    trace!("Env Logger initialized");
    let args = Args::parse();

    let mut state = SHAState::new();

    for file_name in &args.files {
        debug!("Hashing file {:?}", file_name);
        let Ok(file) = OpenOptions::new().read(true).open(file_name) else {
            error!("Failed to open file {}", file_name.to_string_lossy());
            return;
        };
        let mut buf_reader = BufReader::new(file);
        let mut buf = [0; 64];
        while let Ok(n) = buf_reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            state.update(&buf[..n]);
        }
        let hash = state.digest();
        println!("{hash} {}", file_name.to_string_lossy());
    }
}

#[cfg(test)]
mod test {

    use std::{fs::OpenOptions, io::Read};

    use crate::SHAState;

    #[test]
    fn hash_files() {
        let tests = vec![
            (
                "tests/input-01.txt",
                "8bc8a23cdb8b58f83d04507e6394d3948e150433c10f9e95bd672bc9ae4eb1aa",
                "Test-01 fits in a single 64 byte block exactly",
            ),
            (
                "tests/input-02.txt",
                "8515be2623f479fde246238f298691e22877755f1437fb0197606fcb0e51fef5",
                "Test-02 is larger than 64 bytes and fits into two blocks",
            ),
            (
                "tests/input-03.txt",
                "767c919a0950c82d9f8a3bc5a2ddd76e38fb3780ee2ed1c30fa2910845876f22",
                "Test-03 is shorter than 64 bytes, but longer after padding and fits in two blocks",
            ),
        ];
        let mut state = SHAState::new();

        for (file, expected, explanation) in tests {
            let mut file = OpenOptions::new().read(true).open(file).unwrap();

            let mut contents = Vec::new();
            file.read_to_end(&mut contents).unwrap();
            state.update(&contents);
            let hash = state.digest();
            assert_eq!(hash.to_string(), expected, "{}", explanation);
        }
    }
}
