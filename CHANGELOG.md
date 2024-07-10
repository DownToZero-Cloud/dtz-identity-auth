# 1.0.5 2024-07-10

* use DTZ specific identifier instead of generic Uuids

# 1.0.4 2024-05-29

* implement get_profile from bearer token

# 1.0.3 2024-04-17

* support multiple cookies

# 1.0.2 2024-04-01

* deps

# 1.0.1 2024-03-21

* fail authentication if backend is ont available

# 1.0.0 2024-02-28

* update to hyper 1
* add MSRV (minimum supported rust version)

# 0.7.9 2024-01-08

* deps

# 0.7.8 2023-12-27

* allow basic auth for authentication

# 0.7.7 2023-12-26

* remove boring dependency

# 0.7.6 2023-12-16

* update to axum 0.7

# 0.7.5 2023-05-31

* use unpadded Base64 for JWT decode

# 0.7.4 2023-05-10

* internally return String instead of &str

# 0.7.3 2023-04-23

* check for empty string on x-dtz-context

# 0.7.2 2023-04-23

* allow http2

# 0.7.1 2023-04-06

* fix subject retrieval

# 0.7.0 2023-04-06

* remove openssl depedency

# 0.6.1 2023-03-04

* deps

# 0.6.0 2022-11-26

* upgrade to axum 0.6

# 0.5.0 2022-10-01

* avoid const generic
* implement role check through impl function

# 0.4.11 2022-09-23

* pass through raw token as part of the user profile

# 0.4.10 2022-04-30

* fix unparsable cookie

# 0.4.9 2022-04-20

* fail on invalid jwts

# 0.4.8 2022-04-17

* add verify_role functions

# 0.4.7 2022-03-11

* support foreign cookies

# 0.4.6 2022-03-11

* update deps

# 0.4.4 2022-03-11

* cache api keys
* add x-dtz-source header

# 0.4.1 2022-03-07

* unify auth methods

# 0.4.0 2022-03-04

* support api key authentication