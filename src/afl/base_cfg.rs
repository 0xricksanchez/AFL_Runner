use std::path::PathBuf;

use crate::system_utils::create_ramdisk;

#[derive(Clone, Debug, Default)]
pub struct Bcfg {
    /// Input directory for AFL
    pub input_dir: PathBuf,
    /// Output directory for AFL
    pub output_dir: PathBuf,
    /// Path to the dictionary file/directory
    pub dictionary: Option<String>,
    /// Raw AFL flags
    pub raw_afl_flags: Option<String>,
    /// Path to the AFL binary
    pub afl_binary: Option<String>,
    /// Path to the `RAMDisk`
    pub ramdisk: Option<String>,
}

impl Bcfg {
    pub fn new(input_dir: PathBuf, output_dir: PathBuf) -> Self {
        Self {
            input_dir,
            output_dir,
            ..Default::default()
        }
    }

    pub fn with_dictionary(mut self, dictionary: Option<PathBuf>) -> Self {
        self.dictionary =
            dictionary.and_then(|d| d.exists().then(|| d.to_string_lossy().into_owned()));

        self
    }

    pub fn with_raw_afl_flags(mut self, raw_afl_flags: Option<&String>) -> Self {
        self.raw_afl_flags = raw_afl_flags.cloned();
        self
    }

    pub fn with_afl_binary(mut self, afl_binary: Option<String>) -> Self {
        self.afl_binary = afl_binary;
        self
    }

    pub fn with_ramdisk(mut self, is_ramdisk: bool) -> Self {
        let rdisk = is_ramdisk
            .then(|| create_ramdisk().map_err(|e| println!("[!] Failed to create RAMDisk: {e}")))
            .transpose()
            .ok()
            .flatten();

        if let Some(ref disk) = rdisk {
            println!("[+] Using RAMDisk: {disk}");
        }

        self.ramdisk = rdisk;
        self
    }
}
