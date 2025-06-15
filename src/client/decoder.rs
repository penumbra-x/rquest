#[derive(Clone, Debug)]
pub(crate) struct Accepts {
    #[cfg(feature = "gzip")]
    pub(super) gzip: bool,
    #[cfg(feature = "brotli")]
    pub(super) brotli: bool,
    #[cfg(feature = "zstd")]
    pub(super) zstd: bool,
    #[cfg(feature = "deflate")]
    pub(super) deflate: bool,
}

// ===== impl Accepts =====

impl Accepts {
    #[cfg_attr(feature = "gzip", inline(always))]
    pub fn gzip(&mut self, enabled: bool) {
        self.gzip = enabled;
    }

    #[cfg_attr(feature = "brotli", inline(always))]
    pub fn brotli(&mut self, enabled: bool) {
        self.brotli = enabled;
    }

    #[cfg_attr(feature = "zstd", inline(always))]
    pub fn zstd(&mut self, enabled: bool) {
        self.zstd = enabled;
    }

    #[cfg_attr(feature = "deflate", inline(always))]
    pub fn deflate(&mut self, enabled: bool) {
        self.deflate = enabled;
    }
}

impl Default for Accepts {
    fn default() -> Accepts {
        Accepts {
            #[cfg(feature = "gzip")]
            gzip: true,
            #[cfg(feature = "brotli")]
            brotli: true,
            #[cfg(feature = "zstd")]
            zstd: true,
            #[cfg(feature = "deflate")]
            deflate: true,
        }
    }
}
