# BOLA with Actix-web in Rust 🦀

- Testing the Endpoints:

> If you don't have Rust installed in your env:

```rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

// https://www.rust-lang.org/tools/install
```

---

## Run the app

```rust
cargo run
```

> Vulnerable Endpoint (/vulnerable/users/{user_id}):

```bash
curl http://127.0.0.1:8080/vulnerable/users/alice_cooper
# (gets Alice's data)
```

```bash
curl http://127.0.0.1:8080/vulnerable/users/bob_marley
#  (gets Bob's data - BOLA exploited if you are not Bob)
```

> Secure Endpoint (/secure/users/{user_id}):
> Requires X-Authenticated-User-ID header.

```bash
curl -H "X-Authenticated-User-ID: alice_cooper" http://127.0.0.1:8080/secure/users/alice_cooper
# (Success: Alice gets own data)

curl -H "X-Authenticated-User-ID: alice_cooper" http://127.0.0.1:8080/secure/users/bob_marley 
#(# (Fail: 403 Forbidden, Alice tries to get Bob's data)

curl http://127.0.0.1:8080/secure/users/alice_cooper
#(Fail: 401 Unauthorized, missing auth header)
```

__This setup provides a clear demonstration of the vulnerability and how a basic authorization check can mitigate it.__