#[macro_export]
macro_rules! conditional_headers {
    ($with_headers:expr, $initializer:expr) => {
        if $with_headers {
            use std::borrow::Cow;
            use std::sync::LazyLock;
            static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new($initializer);
            Some(Cow::Borrowed(&*HEADER_INITIALIZER))
        } else {
            None
        }
    };
    ($with_headers:expr, $initializer:expr, $ua:expr) => {
        if $with_headers {
            use std::borrow::Cow;
            use std::sync::LazyLock;
            static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(|| $initializer($ua));
            Some(Cow::Borrowed(&*HEADER_INITIALIZER))
        } else {
            None
        }
    };
}

#[macro_export]
macro_rules! header_chrome_edge_sec_ch_ua {
    ($headers:expr, $ua:expr) => {
        $headers.insert("sec-ch-ua", HeaderValue::from_static($ua));
        $headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        $headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
    };
}

#[macro_export]
macro_rules! header_chrome_edge_sec_fetch {
    ($headers:expr) => {
        $headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        $headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        $headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        $headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    };
}

#[macro_export]
macro_rules! header_chrome_edge_ua {
    ($headers:expr, $ua:expr) => {
        $headers.insert(DNT, HeaderValue::from_static("1"));
        $headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        $headers.insert(USER_AGENT, HeaderValue::from_static($ua));
        $headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
    };
}

#[macro_export]
macro_rules! header_chrome_edge_accpet {
    ($headers:expr) => {
        $headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        $headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    };
}

#[macro_export]
macro_rules! header_chrome_edge_accpet_with_zstd {
    ($headers:expr) => {
        $headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        $headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    };
}

#[macro_export]
macro_rules! static_join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

#[macro_export]
macro_rules! chrome_mod_generator {
    ($mod_name:ident, $tls_template:expr, $http2_template:expr, $header_initializer:ident, $sec_ch_ua:tt, $ua:tt) => {
        pub(crate) mod $mod_name {
            use crate::tls::chrome::*;

            #[inline]
            pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
                ImpersonateSettings::builder()
                    .tls($tls_template)
                    .http2($http2_template)
                    .headers(conditional_headers!(with_headers, || {
                        $header_initializer($sec_ch_ua, $ua)
                    }))
                    .build()
            }
        }
    };
}

#[macro_export]
macro_rules! edge_mod_generator {
    ($mod_name:ident, $tls_template:expr, $http2_template:expr, $header_initializer:ident, $sec_ch_ua:tt, $ua:tt) => {
        pub(crate) mod $mod_name {
            use crate::tls::edge::*;

            #[inline]
            pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
                ImpersonateSettings::builder()
                    .tls($tls_template)
                    .http2($http2_template)
                    .headers(conditional_headers!(with_headers, || {
                        $header_initializer($sec_ch_ua, $ua)
                    }))
                    .build()
            }
        }
    };
}

#[macro_export]
macro_rules! okhttp_mod_generator {
    ($mod_name:ident, $cipher_list:expr, $header_initializer:ident, $ua:expr) => {
        pub(crate) mod $mod_name {
            use crate::tls::{impersonate::impersonate_imports::*, okhttp::*};

            #[inline]
            pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
                ImpersonateSettings::builder()
                    .tls(okhttp_tls_template!($cipher_list))
                    .http2(okhttp_http2_template!())
                    .headers(conditional_headers!(with_headers, $header_initializer, $ua))
                    .build()
            }
        }
    };
}

#[macro_export]
macro_rules! safari_mod_generator {
    ($mod_name:ident, $tls_template:expr, $http2_template:expr, $header_initializer:ident, $user_agent:expr) => {
        pub(crate) mod $mod_name {
            use $crate::tls::{impersonate::impersonate_imports::*, safari::*};

            #[inline]
            pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
                ImpersonateSettings::builder()
                    .tls($tls_template)
                    .http2($http2_template)
                    .headers(conditional_headers!(
                        with_headers,
                        $header_initializer,
                        $user_agent
                    ))
                    .build()
            }
        }
    };
}
