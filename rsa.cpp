#include <vector>
#include <unordered_set>
#include <numeric>
#include <iostream>

using namespace std;

typedef long long ll;
typedef vector<ll> vll;
typedef pair<ll, ll> pll;

const ll MAX_PRIME_VALUE = 1000;

unordered_set<ll> generate_primes() {
    unordered_set < ll > primes;
    // Sieve of Erasthotenes, all numbers start out as prime
    // and we cancel possibilities
    vector<bool> sieve(MAX_PRIME_VALUE, true);
    for (ll i = 2; i < MAX_PRIME_VALUE; ++i) {
        // Cancel values 2i, 3i, 4i, ...
        for (ll j = i * 2; j < MAX_PRIME_VALUE; j += i) {
            sieve[j] = false;
        }
    }
    for (ll i = 2; i < MAX_PRIME_VALUE; ++i) {
        if (sieve[i]) {
            primes.insert(i);
        }
    }
    return primes;
}

pll generate_factors_random() {
    unordered_set < ll > primes = generate_primes();
    // find p
    ll randpos1 = rand() % primes.size();
    auto it = primes.begin();
    for (ll i = 0; i < randpos1; ++i) {
        ++it;
    }
    ll p = *it;
    primes.erase(it);

    // find q
    ll randpos2 = rand() % primes.size();
    auto it2 = primes.begin();
    for (ll i = 0; i < randpos2; ++i) {
        ++it2;
    }
    ll q = *it2;
    return make_pair(p, q);
}


ll generate_public_key(ll p, ll q) {
    ll e = 2;
    ll euler = (p - 1) * (q - 1);
    while (gcd(e, euler) != 1) {
        e++;
    }
    return e;
}


pll find_inverse_aux(ll a, ll b) {
    if (a == 0) {
        return make_pair(0, 1);
    }
    pll next = find_inverse_aux(b % a, a);
    return make_pair(next.second - (b / a) * next.first, next.first);
}

ll find_inverse(ll a, ll b) {
    ll inverse = find_inverse_aux(a, b).first;
    return (inverse + b) % b;
}

ll generate_private_key(ll p, ll q, ll e) {
    ll eulerfun = (p - 1) * (q - 1);
    return find_inverse(e, eulerfun);
}

ll exp_mod(ll a, ll b, ll mod) {
    if (b == 0) {
        return 1;
    }
    ll tmp = exp_mod(a, b / 2, mod);
    tmp = (tmp * tmp) % mod;
    if (b % 2 == 1) {
        tmp = (tmp * a) % mod;
    }
    return tmp % mod;
}

struct RSAEncryption {
    vll data;
    pll private_key{};
    pll public_key{};
};


RSAEncryption encrypt_rsa(const string &s) {
    /*
     * Receives an unencrypted string
     * Returns an object containing:
     * - Encrypted data
     * - Private key
     * - Public key
     */

    // Step 1: Generate two random primes
    pll factors = generate_factors_random();
    ll p = factors.first;
    ll q = factors.second;
    // Step 2: Consider the product of both numbers
    ll n = p * q;
    // Step 3: Find a number coprime to phi(n) (euler's totient function)
    ll e = generate_public_key(p, q);
    // Step 4: Calculate the modular multiplicative inverse of e mod phi(n)
    ll d = generate_private_key(p, q, e);
    // Step 5: Encrypt the message M using the rule E(M) = M^e mod n
    vll data;
    for (ll i = 0; i < s.length(); ++i) {
        ll encrypted = exp_mod(s[i], e, n);
        data.push_back(encrypted);
    }
    RSAEncryption encryption;
    encryption.data = data;
    encryption.private_key = make_pair(d, n);
    encryption.public_key = make_pair(e, d);
    return encryption;
}

string decrypt_rsa(const RSAEncryption &encryption) {
    string data;
    for (ll i = 0; i < encryption.data.size(); ++i) {
        char decrypted = (char) exp_mod(encryption.data[i], encryption.private_key.first,
                                        encryption.private_key.second);
        data += decrypted;
    }
    return data;
}

int main() {
    string s;
    cout << "Ingrese la cadena a encriptar: ";
    getline(cin, s);
    RSAEncryption encryption = encrypt_rsa(s);
    cout << "La cadena encriptada es: ";
    for (ll i = 0; i < encryption.data.size(); ++i) {
        cout << encryption.data[i] << " ";
    }
    cout << endl << "Clave pública: " << "(" << encryption.public_key.first << ", " << encryption.public_key.second
         << ")" << endl;
    cout << "Clave privada: " << "(" << encryption.private_key.first << ", " << encryption.private_key.second << ")"
         << endl;
    string decryption = decrypt_rsa(encryption);
    cout << "La cadena desencriptada es: " << decryption << endl;
    return 0;
}
