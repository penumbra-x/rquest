# Changelog

All notable changes to this project will be documented in this file.

## [0.11.77] - 2024-05-06

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

## [0.11.21] - 2023-10-02

### 🐛 Bug Fixes

- Split connect timeout for multiple IPs (#1940)

### Feature

- Auto detect MacOS proxy settings (#1955)

### Dep

- Upgrade trust-dns-resolver from v0.22 to v0.23 (#1965)

## [0.11.19] - 2023-08-21

### 🐛 Bug Fixes

- Strip BOM in `Response::text_with_charset` (#1898)

### ⚙️ Miscellaneous Tasks

- A few simple cleanups/lints (#1849)

### Deps

- Update winrege 0.10 -> 0.50 (#1869)

### Http3

- Don't force `webpki` when experiemental `http3` is enabled (#1845)
- Enable `runtime-tokio` for `quinn` (#1846)

### Msrv

- Bump to 1.63 (#1947)

## [0.11.18] - 2023-05-16

### CI

- Enable dependabot for GitHub Action Workflow (#1831)

### Bug

- Fix custom content-type overidden by json method (#1833)

### Deps

- Update async-compression v0.3.13 => v0.4.0 (#1828)
- Update rustls v0.20.1 -> v0.21.0 (#1791)

## [0.11.17] - 2023-04-28

### Wasm

- Blob url support (#1797)

## [0.11.16] - 2023-03-27

### 📚 Documentation

- Fix building on docs.rs (#1789)

### ⚙️ Miscellaneous Tasks

- Update changelog for 0.11.15

## [0.11.15] - 2023-03-20

### 📚 Documentation

- Fix wording on main docs page (#1765)

### Async/request

- Add methods to split and reassemble a RequestBuilder (#1770)

### Wasm

- Fix premature abort for streaming bodies (#1782)

## [0.11.14] - 2023-01-19

### 🐛 Bug Fixes

- Strip BOM in Response::text_with_charset

### 🚜 Refactor

- Disable ssl verify

### Boring

- Upgrade latest version

### Boringssl

- Add SSL_set_permute_extensions

### Bug

- Fix custom content-type overidden by json method

## [0.11.13] - 2022-11-16

### 📚 Documentation

- Fix some typos (#1562)

### Native-tls

- Add Identiy::from_pkcs8_pem (#1655)

## [0.11.12] - 2022-09-20

### 📚 Documentation

- Fix broken doc comment example. (#1584)

## [0.11.11] - 2022-06-13

### 🚀 Features

- Enable client to be a service without ownership (#1556)

### 📚 Documentation

- Fix some typos (#1531)

### [#1095]

- Implement `basic_auth` for WASM

## [0.11.10] - 2022-03-14

### Doc

- `stream` feature is needed for `wrap_stream` and `From<File>` for `Body` (#1456)

## [0.11.9] - 2022-01-10

### Examples

- Allow passing URL via CLI

## [0.11.7] - 2021-11-30

### 📚 Documentation

- Provide basic auth example (#1362)

### Wasm

- Fix standalone/multipart body conversion to JsValue (#1364)

## [0.11.6] - 2021-10-18

### 🐛 Bug Fixes

- Wasm client: pass response header to builder by reference (#1350)

### 📚 Documentation

- Fix some typos (#1346)

### Fmt

- Wasm body (#1359)

### Wasm

- Don't send request body as plain uint8 array (#1358)

## [0.11.5] - 2021-10-07

### 🐛 Bug Fixes

- Respect https_only option when redirecting (#1313)

### 📚 Documentation

- Adds amplifying note about private key formats (#1335)

### CI

- Make a single final job that depends on all others (#1291)

### Wasm

- Avoid dependency on serde-serialize feature (#1337)
- Add missing `as_bytes` method to `Body` implementation (#1270)

## [0.11.4] - 2021-06-21

### CI

- Check documentation (#1246)

### WASM

- Set RequestCredentials to None by default (#1249)
- Add `try_clone` implementations to `Request` and `RequestBuilder` (#1286)

## [0.11.3] - 2021-04-12

### Proxy

- Refactor a collapsible_match (#1214)

## [0.11.1] - 2021-02-18

### 🐛 Bug Fixes

- Upgrade to http2 if the server reports that it supports it (#1166)

### Lint

- Fix unused `Identity` if only using `default-tls` (#1164)

## [0.11.0] - 2021-01-05

### Example

- Update usage doc for blocking example (#1112)

## [0.10.10] - 2020-12-14

### 🚀 Features

- *(multipart)* Adds support for manually setting size

### Blocking

- Add tcp_keepalive option (#1100)

## [0.10.9] - 2020-11-20

### ⚙️ Miscellaneous Tasks

- *(docs)* Fix missing link for 'blocking'

## [0.10.8] - 2020-08-25

### 📚 Documentation

- Build wasm32-unknown-unknown docs (#998)

### Wasm

- Impl TryFrom<HttpRequest<T>> for Request (#997)
- Omit request body if it's empty (#1012)

## [0.10.7] - 2020-07-24

### 🚀 Features

- *(proxy)* Adds NO_PROXY environment variable support (#877)

### Error

- Add functions to check more error types. (#945)

### Deps

- *(chore)* Update to the latest rustls (#969)

## [0.10.2] - 2020-02-21

### Actions

- Remove --all flag from rustfmt (#795)

### Blocking

- Opt-out CPUs auto-detection in debug mode (#807)

### Wasm

- Add error_for_status to wasm response (#779)

## [0.10.1] - 2020-01-09

### Wasm

- Add url function to wasm response (#777)

## [0.10.0-alpha.2] - 2019-11-12

### 📚 Documentation

- Make encoding_rs link clickable (#674)

### Dependencies

- Upgrade base64 to latest version (#692)

### Wasm

- Translate over response headers (#689)
- Add bytes method to wasm response (#694)
- Add request body in the form of Bytes (#696)

## [0.10.0-alpha.1] - 2019-10-08

### 🧪 Testing

- Add more badssl tests for rustls

### Cargo

- Update to rustls 0.16

## [0.9.18] - 2019-06-06

### ⚙️ Miscellaneous Tasks

- Fix appveyor build for backtrace-sys dependency (#526)

## [0.9.17] - 2019-05-15

### Request

- Test adding duplicate headers to the request (#519)

## [0.9.13] - 2019-04-02

### Body

- Don't call poll_ready on tx when 0 bytes remaining. (#479)

## [0.9.11] - 2019-03-04

### Async/client

- Return a impl Future on execute()

## [0.9.10] - 2019-02-18

### Async/reponse

- Return a impl Future on json()

### Async/request

- Return a impl Future on send()
- Add a basic example for send()

## [0.9.6] - 2019-01-07

### Response.copy_to

- Fix docs markup

## [0.9.3] - 2018-10-17

### From<http

- :Response> for Response (#360)

## [0.9.0] - 2018-09-18

### Multipart

- Force a CRLF at the end of request

## [0.8.1] - 2017-11-07

### 🚀 Features

- Set default headers
- Add Response::text()

### 🐛 Bug Fixes

- Tests::support::server
- *(response)* `copy_to()` and `text()` return `reqwest::Result`

### 🧪 Testing

- Use verbose output
- Add tests for setting default headers
- Response::text()

### ⚙️ Miscellaneous Tasks

- Update gitignore

## [0.8.0] - 2017-10-02

### Async

- Add conversions from static slices to Body

## [0.7.0] - 2017-07-11

### Tmp

- Use upstream git repo for hyper-native-tls

## [0.5.0] - 2017-03-24

### Client

- Add convenience method for DELETE

## [0.2.0] - 2016-12-14

### 🧪 Testing

- Added some trivial tests for the RequestBuilder
- Fixed up issue with reading a Body and finished RequestBuilder tests

<!-- generated by git-cliff -->
