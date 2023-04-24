#include "algos.h"
#include <array>
#include <iostream>
#include <cmath>
#include <utility>
#include <algorithm>
#include <iostream>
#include <random>
#include <exception>
#include <fmt/core.h>

/* naive implementation */
uint_least64_t CalculateHammingWeight(const char *data, size_t len)
{
    uint_least64_t weight;
    for (size_t i = 0; i < len; i++)
        for (uint_fast8_t j = 1; j < sizeof(char); j++)
            weight += (data[i] & (1 << j)) >> j;
    
    return weight;
}

std::tuple<int_fast64_t, int_fast64_t> ExtendedGCDRec(int_fast64_t a, int_fast64_t b, int_fast64_t x1, int_fast64_t x2, int_fast64_t y1, int_fast64_t y2)
{
    if (b == 0)
        return std::tie(a, x2);
    
    int_fast64_t q = a / b;

    return ExtendedGCDRec(b, a % b, x2 - q * x1, x1, y2 - q * y1, y1);
}

std::tuple<int_fast64_t, int_fast64_t> ExtendedGCD(int_fast64_t a, int_fast64_t b)
{
    if (a < b)
        std::swap(a, b);

    return ExtendedGCDRec(a, b, 1, 0, 0, 1);
}

int_fast64_t InverseMod(int_fast64_t num, int_fast64_t mod)
{
    int_fast64_t inverse = std::get<1>(ExtendedGCD(num, mod));
    return inverse >= 0 ? inverse : mod + inverse;
}

int_fast64_t GCD(int_fast64_t num, int_fast64_t mod)
{
    return std::get<0>(ExtendedGCD(num, mod));
}

int_fast64_t ModExp(int_fast64_t num, int_fast64_t power, int_fast64_t mod)
{
    int_fast64_t prev = num % mod;
    int_fast64_t result = (power & 1) ? prev : 1;

    for (int_fast64_t i = 1; i < 64; i++)
    {
        prev = (prev * prev) % mod;
        if (power & (1L << i))
            result = (prev * result) % mod;
    }

    return result;
}

int_fast64_t PositiveMod(int_fast64_t num, int_fast64_t mod)
{
    return (num >= 0) ? (num % mod) : ((num % mod) + mod);
}

std::tuple<int_fast64_t, int_fast64_t> DoFermantFactorization(int_fast64_t number, std::string *steps)
{
    int_fast64_t t = (int_fast64_t)std::ceil(std::sqrt(number));
    
    if (steps)
        *steps = fmt::format("t0 = sqrt({}) = {}\n", number, t);
    
    if (t * t == number)
        return std::tie(t, t);

    int_fast64_t s = 0;
    int counter = 0;
    while (true)
    {
        int_fast64_t z = (t * t) - number;
        s = (int_fast64_t)std::floor(std::sqrt(z));
        
        if  (steps)
            *steps = fmt::format("z = {}^2 - {} = {}\n", t, number, z);
        
        if (s * s == z)
            break;

        t = t + 1;

        if (steps)
            *steps = fmt::format("\nt{} = {} + 1 = {}\n", ++counter, t - 1, t);
    }
    
    return std::make_tuple<int_fast64_t, int_fast64_t>(t + s, t - s);
}

std::tuple<int_fast64_t, int_fast64_t> DoRhoFactorization(int_fast64_t number, int_fast64_t rndNumber, std::string *steps)
{
    int_fast64_t x1 = ((rndNumber * rndNumber) - 1) % number;
    int_fast64_t x2 = ((x1 * x1) - 1) % number;
    int_fast64_t result = 0;

    int counter = 3;

    while(true)
    {
        if (steps)
            *steps += fmt::format("i = {}\nx{} = {}\nx{} = {}\n", (counter / 2) - 1, counter - 2, x1, counter - 1, x2);

        int_fast64_t xDelta = std::abs(x2 - x1);
        result = GCD(xDelta, number);

        if (steps)
        {
            *steps += fmt::format("|x{} - x{}| = |{} - {}| = |{}|\n", counter - 1, counter - 2, x2, x1, xDelta);
            *steps += fmt::format("gcd({}, {}) = {}\n\n", xDelta, number, result);
        }

        if (result > 1)
            break;

        x1 = ((x1 * x1) - 1) % number;
        int_fast64_t x3 = ((x2 * x2) - 1) % number;
        x2 = ((x3 * x3) - 1) % number;
        
        counter += 2;
    }


    return std::make_tuple(result, number / result);
}

LehmanPeraltResult LehmanPeralt(const std::vector<int_fast64_t> &numbers, int_fast64_t examinedNumber, std::string *steps)
{
    if (numbers.size() == 0)
        return {};

    LehmanPeraltResult out;

    int_fast64_t power = (examinedNumber - 1) / 2;
    
    for (size_t i = 0; i < numbers.size(); i++)
    {
        int_fast64_t result = ModExp(numbers[i], power, examinedNumber);

        if (result == 1)
            out.flags |= LehmanPeraltFlags::ONE_OCCURED;
        else if (result == examinedNumber - 1)
        {
            out.flags |= LehmanPeraltFlags::MINUS_ONE_OCCURED;
            result = -1;
        }
        else
            out.flags |= LehmanPeraltFlags::NOT_PRIME;

        if (steps)
            *steps += fmt::format("d{} = {} ^ {} mod {} = {}\n", i + 1, numbers[i], power, examinedNumber, result);
    }

    if (!(out.flags & LehmanPeraltFlags::NOT_PRIME))
        out.chance = 1.0 - std::pow(2.0, -(double)numbers.size());

    return out;
}

ElGamalData ElGamalEncrypt(const ElGamalPublicKey &pubKey, const ElGamalPrivateKey &privKey, int_fast64_t message, std::string *steps)
{
    int_fast64_t sharedSecret = ModExp(pubKey.y, privKey.k, pubKey.p);
    int_fast64_t y = ModExp(pubKey.q, privKey.k, pubKey.p);    
    int_fast64_t encrypted = (message * sharedSecret) % pubKey.p;

    if (steps)
    {
        std::string &str = *steps;
        str = fmt::format("sharedSecret = {} ^ {} mod {} = {}\n", pubKey.y, privKey.k, pubKey.p, sharedSecret);
        str += fmt::format("y = {} ^ {} mod {} = {}\n", pubKey.q, privKey.k, pubKey.p, y);
        str += fmt::format("encryptedMsg = ({} * {}) mod {} = {}", message, sharedSecret, pubKey.p, encrypted);
    }

    return { y, encrypted };
}

int_fast64_t ElGamalDecrypt(const ElGamalData &data, const ElGamalPrivateKey &privKey, std::string *steps)
{
    int_fast64_t sharedSecret = ModExp(data.y, privKey.k, privKey.p);
    int_fast64_t inverse = InverseMod(sharedSecret, privKey.p);
    int_fast64_t decrypted = (inverse * data.encData) % privKey.p;

    if (steps)
    {
        std::string &str = *steps;
        str = fmt::format("sharedSecret = {} ^ {} mod {} = {}\n", data.y, privKey.k, privKey.p, sharedSecret);
        str += fmt::format("sharedSecret^(-1) = {}^(-1) = {}\n", sharedSecret, inverse);
        str += fmt::format("decryptedMsg = ({} * {}) mod {} = {}", inverse, data.encData, privKey.p, decrypted);
    }

    return decrypted;
}

ElGamalPublicKey ElGamalDerivePublicKey(const ElGamalPrivateKey &privKey, std::string *steps)
{
    int_fast64_t publicPart = ModExp(privKey.q, privKey.k, privKey.p);
    if (steps)
        *steps = fmt::format("y = {}^{} mod {} = {}", privKey.q, privKey.k, privKey.p, publicPart);

    return ElGamalPublicKey{ privKey.p, privKey.q, publicPart };
}

bool ECAlignsOn(const ECCurve &curve, const ECPoint &p)
{
    return (p.y * p.y) % curve.p == PositiveMod((p.x * p.x * p.x) + curve.a * p.x + curve.b, curve.p);
}

ECPoint ECDoubling(const ECCurve &curve, const ECPoint &p, std::string *steps)
{
    if (p.y == 0)
        throw std::invalid_argument("p.y must be highier than 0");

    //s = slope
    
    int_fast64_t s = ((3 * (p.x * p.x) + curve.a) * InverseMod(PositiveMod(2 * p.y, curve.p), curve.p)) % curve.p;
    
    ECPoint newPoint;
    newPoint.x = PositiveMod((s * s) - 2 * p.x, curve.p);
    newPoint.y = PositiveMod((s * (p.x - newPoint.x) - p.y), curve.p);

    if (steps)
    {
        std::string &str = *steps;
        str = fmt::format("s = (3 * {}^2 + {}) * ((2 * {})^-1) mod {} = {}\n", p.x, curve.a, p.y, curve.p, s);
        str += fmt::format("xr = {}^2 - 2 * {} mod {} = {}\n", s, p.x, curve.p, newPoint.x);
        str += fmt::format("yr = {} * ({} - {}) - {} mod {} = {}", s, p.x, newPoint.x, p.y, curve.p, newPoint.y);
    }

    return newPoint;
}

ECPoint ECSum(const ECCurve &curve, const ECPoint &p, const ECPoint &q, std::string *steps)
{
    /*Point doubling*/
    if (p == q)
        return ECDoubling(curve, p, steps);

    //s = slope
    int_fast64_t s = ((p.y - q.y) * InverseMod(PositiveMod(p.x - q.x, curve.p), curve.p)) % curve.p;
    ECPoint newPoint;
    
    newPoint.x = PositiveMod(((s * s) - p.x - q.x), curve.p);

    /* 
     * y_-r(inverse y) = y_p + z
     * w(width) = x_r - x_p
     * z(height) = w * s = (x_r - x_p); 
     * y_-r(inverse y) = y_p + s (x_r - x_p)
     * y_r = -y_p + s * (x_p - x_r)
     */
    newPoint.y = PositiveMod((s * (p.x - newPoint.x) - p.y), curve.p);

    if (steps)
    {
        std::string &str = *steps;
        str = fmt::format("s = ({} - {}) * (({} - {})^-1) mod {} = {}\n", p.y, q.y, p.x, q.x, curve.p, s);
        str += fmt::format("xr = {}^2 - {} - {} mod {} = {}\n", s, p.x, q.x, curve.p, newPoint.x);
        str += fmt::format("yr = {} * ({} - {}) - {} mod {} = {}", s, p.x, newPoint.x, p.y, curve.p, newPoint.y);
    }

    return newPoint;
}
