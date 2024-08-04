# Changelog

All notable changes to this project will be documented in this file.

## [0.11.93] - 2024-07-27

### 🚀 Features

- *(impersonate)* Optimize reuse of impersonate configuration (#61)
- *(connect)* Reduce unnecessary connection overhead (#62)

## [0.11.92] - 2024-07-27

### 🚀 Features

- *(connect)* Add PSK extension (#52)
- *(impersonate)* Add Edge_127 impersonate (#59)

### 🐛 Bug Fixes

- *(connector)* Fix TLS session failure when changing address (#55)

### 🚜 Refactor

- Remove unused crates (#54)
- Remove unused crates

### 🎨 Styling

- *(impersonate)* Remove dead code (#51)

### ⚙️ Miscellaneous Tasks

- 1.70 as MSRV (#53)
- 1.70 as MSRV

### Deps

- *(ipnet)* V2.9.0 (#56)
- *(mime)* V0.3.17 (#57)
- *(url)* V2.5 (#58)

## [0.11.91] - 2024-07-25

### 🎨 Styling

- *(connect)* Replace all non-refutable if let patterns with let statements (#44)

### Deps

- *(base64)* Bump version to v0.22.x (#46)
- *(cookie_store)* Bump version to v0.21.x (#47)

## [0.11.90] - 2024-07-25

### 🚀 Features

- *(impersonate)* Optimize TLS connector context handle (#37)

### ◀️ Revert

- *(impersonate)* Remove chrome99 impersonate (#38)

### Build

- *(deps)* Bump softprops/action-gh-release from 1 to 2 (#36)
- *(deps)* Bump actions/checkout from 3 to 4 (#35)

## [0.11.89] - 2024-07-25

### 🚀 Features

- *(client)* Support client proxy settings (#32)
- *(client)* Add ability to set proxies/address after client has been initialised (#34)

## [0.11.88] - 2024-07-09

### 🐛 Bug Fixes

- *(impersonate)* Add Safari17_5 from string

## [0.11.87] - 2024-07-07

### 🚀 Features

- *(impersonate)* Add Safari_17_5 impersonate (#28)
- *(impersonate)* Add Safari_17_5 impersonate

## [0.11.85] - 2024-06-24

### 🚀 Features

- *(impersonate)* Specification version number match
- *(impersonate)* Add Safari_IOS_16_5 impersonate
- *(impersonate)* Add Safari_IOS_17_4_1 impersonate
- Add zstd support

### 🚜 Refactor

- *(impersonate)* Refactor unnecessary settings
- Migrate trust-dns to hickory-dns
- Migrate trust-dns to hickory-dns
- *(impersonate)* Reuse code

### Impersonate

- Bugfix `chrome_123`, `chrome_124` headers

### Impersonate

- Chrome_123, chrome_125 - add `zstd` to Accept-Encoding header
- Add `chrome_126`

## [0.11.78] - 2024-05-08

### 🚀 Features

- *(websocket)* Export `UpgradedRequestBuilder`
- *(websocket)* Export header method
- *(websocket)* Export header method
- *(websocket)* Add upgrade with custom handshake key
- *(impersonate)* Add Chrome124 impersonate

### Deps

- *(tungstenite)* Backport dependencies

## [0.11.71] - 2024-04-30

### 🚀 Features

- *(impersonate)* Add Safari_17_4_1 impersonate

### 🧪 Testing

- Fix test_badssl_no_built_in_roots

## [0.11.69] - 2024-04-10

### 🚀 Features

- *(impersonate)* Add Safari_IOS_17_2 impersonate

## [0.11.68] - 2024-04-10

### 🚀 Features

- *(impersonate)* Improve fingerprint OkHttp fingerprint UserAgent
- *(impersonate)* Add Chrome123 impersonate

## [0.11.65] - 2024-03-05

### 🚀 Features

- *(feature)* Optional enable websocket
- *(impersonate)* Add Edge122 impersonate
- *(impersonate)* Optimize the overhead of parsing request headers at runtime

## [0.11.60] - 2024-02-27

### 🚀 Features

- *(websocket)* Support configuration websocket

## [0.11.52] - 2024-02-27

### 🚀 Features

- *(async/client)* Add try get user agent
- *(impersonate)* Optimize the overhead of parsing request headers at runtime
- *(client)* Support impersonate webSocket

## [0.11.48] - 2024-01-09

### 🚀 Features

- *(impersonate)* Add Edge99 impersonate
- *(impersonate)* Add Edge101 impersonate
- *(impersonate)* Add Safari17_2_1 impersonate

### 🐛 Bug Fixes

- Set nodelay correctly to handle when a tls feature is enabled but connection is to an http server (#2062)

### 📚 Documentation

- Remove redundant link targets (#2019)
- Add cfg notes about http3 builder methods (#2070)

### Deps

- *(hyper)* Bump version to v0.14.33

### Http3

- Upgrade dependencies (#2028)

### Proxy

- Add support for proxy authentication with user-specified header values (#2053)

### Wasm

- Add method `user_agent` to `ClientBuilder`. (#2018)

## [0.11.46] - 2023-12-23

### Deps

- *(boring-sys)* Bump version to v2.0.6

## [0.11.45] - 2023-12-22

### Deps

- *(boring-sys)* Bump version to v2.0.5

## [0.11.43] - 2023-12-21

### 🚀 Features

- *(impersonate)* Add Safari16_5 impersonate

### Deps

- *(boring-sys)* Bump version to v2.0.4

## [0.11.40] - 2023-12-18

### 🚀 Features

- *(impersonate)* Add Chrome117 impersonate

### Deps

- *(boring-sys)* Bump version to v2.0.3

## [0.11.39] - 2023-12-17

### 🚀 Features

- *(impersonate)* Add Chrome120 impersonate
- *(impersonate)* Add Chrome100 impersonate
- *(impersonate)* Add Chrome101 impersonate
- *(impersonate)* Improve safari fingerprint impersonate

### Deps

- *(hyper_imp)* Bump version to v0.14.30

## [0.11.38] - 2023-12-14

### 🚀 Features

- *(impersonate)* Add Chrome v118 Impersonate
- *(connector)* Enable encrypted client hello
- *(client)* Optional enable_ech_grease, only effective for Chrome
- *(client)* Optional enable permute_extensions
- *(impersonate)* Remove max_concurrent_streams for v118
- *(impersonate)* Use the default locations of trusted certificates for verification.
- *(impersonate)* Add Chrome v119 Impersonate
- *(impersonate)* Add Chrome v116 Impersonate
- *(impersonate)* Add Safari 15_3/15_5 Impersonate
- Update safari impersonate
- *(impersonate)* Add Safari15_6_1 impersonate
- *(impersonate)* Add Safari16 impersonate

### 🐛 Bug Fixes

- *(impersonate)* Fix v116 impersonate

## [0.11.30] - 2023-11-11

### 🚀 Features

- *(impersonate)* Add OkHttp3 Impersonate
- *(impersonate)* Add OkHttp5-alpha Impersonate
- *(impersonate)* Support more OkHttp fingerprints
- *(impersonate)* Add Safari 12 Impersonate

### Deps

- *(hyper)* Bump version to v0.14.28

## [0.11.26] - 2023-10-19

### 🚀 Features

- *(impersonate)* Support disable certs verification

## [0.11.25] - 2023-10-19

### 🚜 Refactor

- *(impersonate)* Revert to SslVerifyMode::NONE

## [0.11.24] - 2023-10-19

### 🚀 Features

- *(client)* Support configured IPv4 or IPv6 address (depending on host's preferences) before connection

### 🚜 Refactor

- *(impersonate)* Update SSL verify mode

## [0.11.22] - 2023-10-15

### 🚀 Features

- Set default headers
- Add Response::text()
- *(proxy)* Adds NO_PROXY environment variable support (#877)
- *(multipart)* Adds support for manually setting size
- Enable client to be a service without ownership (#1556)

### 🐛 Bug Fixes

- Tests::support::server
- *(response)* `copy_to()` and `text()` return `rquest::Result`
- Upgrade to http2 if the server reports that it supports it (#1166)
- Respect https_only option when redirecting (#1313)
- Wasm client: pass response header to builder by reference (#1350)
- Strip BOM in Response::text_with_charset
- Strip BOM in `Response::text_with_charset` (#1898)
- Split connect timeout for multiple IPs (#1940)

### 🚜 Refactor

- Disable ssl verify

### 📚 Documentation

- Make encoding_rs link clickable (#674)
- Build wasm32-unknown-unknown docs (#998)
- Adds amplifying note about private key formats (#1335)
- Fix some typos (#1346)
- Provide basic auth example (#1362)
- Fix some typos (#1531)
- Fix broken doc comment example. (#1584)
- Fix some typos (#1562)
- Fix wording on main docs page (#1765)
- Fix building on docs.rs (#1789)

### 🧪 Testing

- Added some trivial tests for the RequestBuilder
- Fixed up issue with reading a Body and finished RequestBuilder tests
- Use verbose output
- Add tests for setting default headers
- Response::text()
- Add more badssl tests for rustls

### ⚙️ Miscellaneous Tasks

- Update gitignore
- Fix appveyor build for backtrace-sys dependency (#526)
- *(docs)* Fix missing link for 'blocking'
- Update changelog for 0.11.15
- A few simple cleanups/lints (#1849)

### Body

- Don't call poll_ready on tx when 0 bytes remaining. (#479)

### CI

- Check documentation (#1246)
- Make a single final job that depends on all others (#1291)
- Enable dependabot for GitHub Action Workflow (#1831)

### Doc

- `stream` feature is needed for `wrap_stream` and `From<File>` for `Body` (#1456)

### Error

- Add functions to check more error types. (#945)

### Examples

- Allow passing URL via CLI

### Feature

- Auto detect MacOS proxy settings (#1955)

### From<http

- :Response> for Response (#360)

### Lint

- Fix unused `Identity` if only using `default-tls` (#1164)

### Response.copy_to

- Fix docs markup

### WASM

- Set RequestCredentials to None by default (#1249)
- Add `try_clone` implementations to `Request` and `RequestBuilder` (#1286)

### [#1095]

- Implement `basic_auth` for WASM

### Actions

- Remove --all flag from rustfmt (#795)

### Async

- Add conversions from static slices to Body

### Async/client

- Return a impl Future on execute()

### Async/reponse

- Return a impl Future on json()

### Async/request

- Return a impl Future on send()
- Add a basic example for send()
- Add methods to split and reassemble a RequestBuilder (#1770)

### Blocking

- Opt-out CPUs auto-detection in debug mode (#807)
- Add tcp_keepalive option (#1100)

### Boring

- Upgrade latest version

### Boringssl

- Add SSL_set_permute_extensions

### Bug

- Fix custom content-type overidden by json method
- Fix custom content-type overidden by json method (#1833)

### Cargo

- Update to rustls 0.16

### Client

- Add convenience method for DELETE

### Dep

- Upgrade trust-dns-resolver from v0.22 to v0.23 (#1965)

### Dependencies

- Upgrade base64 to latest version (#692)

### Deps

- *(chore)* Update to the latest rustls (#969)
- Update async-compression v0.3.13 => v0.4.0 (#1828)
- Update rustls v0.20.1 -> v0.21.0 (#1791)
- Update winrege 0.10 -> 0.50 (#1869)

### Example

- Update usage doc for blocking example (#1112)

### Fmt

- Wasm body (#1359)

### Http3

- Don't force `webpki` when experiemental `http3` is enabled (#1845)
- Enable `runtime-tokio` for `quinn` (#1846)

### Msrv

- Bump to 1.63 (#1947)

### Multipart

- Force a CRLF at the end of request

### Native-tls

- Add Identiy::from_pkcs8_pem (#1655)

### Proxy

- Refactor a collapsible_match (#1214)

### Request

- Test adding duplicate headers to the request (#519)

### Tmp

- Use upstream git repo for hyper-native-tls

### Wasm

- Translate over response headers (#689)
- Add bytes method to wasm response (#694)
- Add request body in the form of Bytes (#696)
- Add url function to wasm response (#777)
- Add error_for_status to wasm response (#779)
- Impl TryFrom<HttpRequest<T>> for Request (#997)
- Omit request body if it's empty (#1012)
- Avoid dependency on serde-serialize feature (#1337)
- Add missing `as_bytes` method to `Body` implementation (#1270)
- Don't send request body as plain uint8 array (#1358)
- Fix standalone/multipart body conversion to JsValue (#1364)
- Fix premature abort for streaming bodies (#1782)
- Blob url support (#1797)

<!-- generated by git-cliff -->
