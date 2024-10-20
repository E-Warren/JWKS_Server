#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>


// FUNCTION: data type conversion --> input = openssl BIGNUM, output = string
std::string bignum_to_raw_string(const BIGNUM *bn) {
    int bn_size = BN_num_bytes(bn);
    std::string raw(bn_size, 0);
    BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&raw[0]));
    return raw;
}

// FUNCTION: reformat --> input = openssl public key, output = string in PEM format
std::string extract_pub_key(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// FUNCTION: reformat --> input = openssl private key, output = string in PEM format
std::string extract_priv_key(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// FUNCTION: db save --> input = db and key info, output = void/insertion
void save_private_key(sqlite3 *db, const std::string &priv_key, int exp) {
    const char *sql = "INSERT INTO keys (key, exp) VALUES (?, ?)";
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_blob(stmt, 1, priv_key.data(), priv_key.size(), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, exp);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// FUNCTION: db get --> input = db and exp info, output = private key string
std::string get_private_key(sqlite3 *db, bool expired) {
    const char *sql = "SELECT key FROM keys WHERE exp < ? LIMIT 1";
    sqlite3_stmt *stmt;
    std::string priv_key;

    time_t now = time(nullptr);
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, expired ? now : now + 3600); // check for expired or valid key

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *data = sqlite3_column_blob(stmt, 0);
        int size = sqlite3_column_bytes(stmt, 0);
        priv_key.assign(static_cast<const char*>(data), size);
    }

    sqlite3_finalize(stmt);
    return priv_key;
}

// FUNCTION: string conversion --> input: binary string, output = base64-encoded string 
std::string base64_url_encode(const std::string &data) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t n = 0; n < data.size(); n++) {
        char_array_3[i++] = data[n];

        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++) {
                ret += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; (j < i + 1); j++) {
            ret += base64_chars[char_array_4[j]];
        }
    }

    std::replace(ret.begin(), ret.end(), '+', '-');
    std::replace(ret.begin(), ret.end(), '/', '_');
    ret.erase(std::remove(ret.begin(), ret.end(), '='), ret.end());

    return ret;
} // end base64_url_encode function

// FUNCTION: create database --> input: blank db ptr,  output: void/creation
void create_database(sqlite3** db){
    if (sqlite3_open("totally_not_my_privateKeys.db", db) != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(*db) << std::endl;
        return;
    }

    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    )";

    char* errMsg;
    if (sqlite3_exec(*db, sql, 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "Error creating table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}


int main() {
    // open SQLite database
    sqlite3 *db;
    create_database(&db);

    // create table if not exists
    const char *create_table_sql = "CREATE TABLE IF NOT EXISTS keys("
                                    "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
                                    "key BLOB NOT NULL,"
                                    "exp INTEGER NOT NULL)";
    sqlite3_exec(db, create_table_sql, 0, 0, 0);

    // generate RSA key pair
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // extract private key and save to DB with expiration times
    std::string priv_key = extract_priv_key(pkey);
    save_private_key(db, priv_key, time(nullptr) - 1); // Expired key
    save_private_key(db, priv_key, time(nullptr) + 3600); // Valid key

    std::string pub_key = extract_pub_key(pkey);

    // start HTTP server
    httplib::Server svr;

    // authentication/POST endpoint; creates JWT token
    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res) {
        if (req.method != "POST") {
            res.status = 405;  // method not allowed
            res.set_content("Method Not Allowed", "text/plain");
            return;
        }

        bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";
        std::string private_key = get_private_key(db, expired);

        if (private_key.empty()) {
            res.status = 404;
            res.set_content("No key found", "text/plain");
            return;
        }

        // create JWT token
        auto now = std::chrono::system_clock::now();
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_type("JWT")
            .set_payload_claim("sample", jwt::claim(std::string("test")))
            .set_issued_at(now)
            .set_expires_at(expired ? now - std::chrono::seconds{1} : now + std::chrono::hours{24})
            .set_key_id(expired ? "expiredKID" : "goodKID")
            .sign(jwt::algorithm::rs256(pub_key, private_key));

        res.set_content(token, "text/plain");
    });

// retrieval/GET endpoint; returns encoded data (JSON)
svr.Get("/.well-known/jwks.json", [&](const httplib::Request &, httplib::Response &res) {
    const char *sql = "SELECT key FROM keys WHERE exp > ?";
    sqlite3_stmt *stmt;

    time_t now = time(nullptr);
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, now);

    std::string jwks = R"({"keys": [)";
    bool first = true;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *data = sqlite3_column_blob(stmt, 0);
        int size = sqlite3_column_bytes(stmt, 0);
        std::string priv_key(static_cast<const char*>(data), size);

        // extract public key from the private key for JWKS
        BIO *bio = BIO_new_mem_buf(priv_key.data(), priv_key.size());
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

        BIGNUM *n = BN_new();
        BIGNUM *e = BN_new();
        EVP_PKEY_get_bn_param(pkey, "n", &n);
        EVP_PKEY_get_bn_param(pkey, "e", &e);

        std::string n_encoded = base64_url_encode(bignum_to_raw_string(n));
        std::string e_encoded = base64_url_encode(bignum_to_raw_string(e));

        BN_free(n);
        BN_free(e);
        BIO_free(bio);

        if (!first) jwks += ",";
        jwks += R"({
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": "goodKID",
            "n": ")" + n_encoded + R"(",
            "e": ")" + e_encoded + R"("
        })";
        first = false;
    }

    jwks += "]}";
    sqlite3_finalize(stmt);

    res.set_content(jwks, "application/json");
});

    // catch-all handlers for other methods
    auto methodNotAllowedHandler = [](const httplib::Request &req, httplib::Response &res) {
        if (req.path == "/auth" || req.path == "/.well-known/jwks.json") {
            res.status = 405;
            res.set_content("Method Not Allowed", "text/plain");
        } else {
            res.status = 404;
            res.set_content("Not Found", "text/plain");
        }
    };

    // all additional requests blocked
    svr.Get(".*", methodNotAllowedHandler);
    svr.Post(".*", methodNotAllowedHandler);
    svr.Put(".*", methodNotAllowedHandler);
    svr.Delete(".*", methodNotAllowedHandler);
    svr.Patch(".*", methodNotAllowedHandler);

    svr.listen("127.0.0.1", 8080);

    // get current time and calculate expiration (1 hour from now)
    time_t now = time(nullptr);
    int expiration = now + 3600; // Expiration in 1 hour

    // save private key to the database
    save_private_key(db, priv_key, expiration);

    // cleanup
    sqlite3_close(db);
    EVP_PKEY_free(pkey);

    return 0;
}
