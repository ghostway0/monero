// Copyright (c) 2022, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "generators.h"

#include "crypto.h"
extern "C"
{
#include "crypto-ops.h"
#include "mx25519.h"
}
#include "cryptonote_config.h"
#include "hash.h"
#include "x25519.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace crypto
{

/// constexpr assert for old gcc bug: https://stackoverflow.com/questions/34280729/throw-in-constexpr-function
/// - this function won't compile in a constexpr function if b == false
constexpr void constexpr_assert(const bool b) { b ? 0 : throw std::runtime_error("constexpr assert failed"); };

/// constexpr paste bytes into an array-of-bytes type
template<typename T>
constexpr T bytes_to(const std::initializer_list<unsigned char> bytes)
{
    T out{}; // zero-initialize trailing bytes

    auto current = std::begin(out.data);
    constexpr_assert(static_cast<long>(bytes.size()) <= std::end(out.data) - current);

    for (const unsigned char byte : bytes)
        *current++ = byte;
    return out;
}

// generators
//standard ed25519 generator G: {x, 4/5} (positive x when decompressing y = 4/5)
constexpr public_key G = bytes_to<public_key>({ 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 });
//pedersen commitment generator H: toPoint(cn_fast_hash(G))
constexpr public_key H = bytes_to<public_key>({ 0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1,
    0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94 });
//seraphis generator X: keccak_to_pt(keccak("seraphis_X"))
constexpr public_key X = bytes_to<public_key>({ 0xa4, 0xfb, 0x43, 0xca, 0x69, 0x5e, 0x12, 0x99, 0x88, 0x02, 0xa2, 0x0a, 0x15,
    0x8f, 0x12, 0xea, 0x79, 0x47, 0x4f, 0xb9, 0x01, 0x21, 0x16, 0x95, 0x6a, 0x69, 0x76, 0x7c, 0x4d, 0x41, 0x11, 0x0f });
//seraphis generator U: keccak_to_pt(keccak("seraphis_U"))
constexpr public_key U = bytes_to<public_key>({ 0x10, 0x94, 0x8b, 0x00, 0xd2, 0xde, 0x50, 0xb5, 0x76, 0x99, 0x8c, 0x11, 0xe8,
    0x3c, 0x59, 0xa7, 0x96, 0x84, 0xd2, 0x5c, 0x9f, 0x8a, 0x0d, 0xc6, 0x86, 0x45, 0x70, 0xd7, 0x97, 0xb9, 0xc1, 0x6e });
static ge_p3 G_p3;
static ge_p3 H_p3;
static ge_p3 X_p3;
static ge_p3 U_p3;
static ge_cached G_cached;
static ge_cached H_cached;
static ge_cached X_cached;
static ge_cached U_cached;
//X25519 generator: x = 9
static const x25519_pubkey x25519_G{ mx25519_pubkey{ .data = { 9 } } };

// misc
static std::once_flag init_gens_once_flag;

//-------------------------------------------------------------------------------------------------------------------
// hash-to-point: H_p(x) = 8*point_from_bytes(keccak(x))
//-------------------------------------------------------------------------------------------------------------------
static void hash_to_point(const hash &x, crypto::ec_point &point_out)
{
    hash h;
    ge_p3 temp_p3;
    ge_p2 temp_p2;
    ge_p1p1 temp_p1p1;

    cn_fast_hash(reinterpret_cast<const unsigned char*>(&x), sizeof(hash), h);
    ge_fromfe_frombytes_vartime(&temp_p2, reinterpret_cast<const unsigned char*>(&h));
    ge_mul8(&temp_p1p1, &temp_p2);
    ge_p1p1_to_p3(&temp_p3, &temp_p1p1);
    ge_p3_tobytes(to_bytes(point_out), &temp_p3);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static public_key reproduce_generator_G()
{
    // G = {x, 4/5 mod q}
    fe four, five, inv_five, y;
    fe_0(four);
    fe_0(five);
    four[0] = 4;
    five[0] = 5;
    fe_invert(inv_five, five);
    fe_mul(y, four, inv_five);

    public_key reproduced_G;
    fe_tobytes(to_bytes(reproduced_G), y);

    return reproduced_G;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static public_key reproduce_generator_H()
{
    // H = 8*to_point(keccak(G))
    // note: this does not use the point_from_bytes() function found in H_p(), instead directly interpreting the
    //       input bytes as a compressed point (this can fail, so should not be used generically)
    // note2: to_point(keccak(G)) is known to succeed for the canonical value of G (it will fail 7/8ths of the time
    //        normally)
    ge_p3 temp_p3;
    ge_p2 temp_p2;
    ge_p1p1 temp_p1p1;

    hash H_temp_hash{cn_fast_hash(to_bytes(G), sizeof(ec_point))};
    (void)H_temp_hash;  //suppress unused warning
    assert(ge_frombytes_vartime(&temp_p3, reinterpret_cast<const unsigned char*>(&H_temp_hash)) == 0);
    ge_p3_to_p2(&temp_p2, &temp_p3);
    ge_mul8(&temp_p1p1, &temp_p2);
    ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

    public_key reproduced_H;
    ge_p3_tobytes(to_bytes(reproduced_H), &temp_p3);

    return reproduced_H;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static public_key reproduce_generator_X()
{
    // X = H_p(keccak("seraphis_X"))
    const std::string X_salt{config::HASH_KEY_SERAPHIS_X};
    hash X_temp_hash{cn_fast_hash(X_salt.data(), X_salt.size())};
    public_key reproduced_X;
    hash_to_point(X_temp_hash, reproduced_X);

    return reproduced_X;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static public_key reproduce_generator_U()
{
    // U = H_p(keccak("seraphis_U"))
    const std::string U_salt{config::HASH_KEY_SERAPHIS_U};
    hash U_temp_hash{cn_fast_hash(U_salt.data(), U_salt.size())};
    public_key reproduced_U;
    hash_to_point(U_temp_hash, reproduced_U);

    return reproduced_U;
}
//-------------------------------------------------------------------------------------------------------------------
// Make generators, but only once
//-------------------------------------------------------------------------------------------------------------------
static void init_gens()
{
    std::call_once(init_gens_once_flag,
        [&](){

        // sanity check the generators
        static_assert(static_cast<unsigned char>(G.data[0]) == 0x58, "compiletime constant sanity check");
        static_assert(static_cast<unsigned char>(H.data[0]) == 0x8b, "compiletime constant sanity check");
        static_assert(static_cast<unsigned char>(X.data[0]) == 0xa4, "compiletime constant sanity check");
        static_assert(static_cast<unsigned char>(U.data[0]) == 0x10, "compiletime constant sanity check");

        // build ge_p3 representations of generators
        const int G_deserialize = ge_frombytes_vartime(&G_p3, to_bytes(G));
        const int H_deserialize = ge_frombytes_vartime(&H_p3, to_bytes(H));
        const int X_deserialize = ge_frombytes_vartime(&X_p3, to_bytes(X));
        const int U_deserialize = ge_frombytes_vartime(&U_p3, to_bytes(U));

        (void)G_deserialize; assert(G_deserialize == 0);
        (void)H_deserialize; assert(H_deserialize == 0);
        (void)X_deserialize; assert(X_deserialize == 0);
        (void)U_deserialize; assert(U_deserialize == 0);

        // get cached versions
        ge_p3_to_cached(&G_cached, &G_p3);
        ge_p3_to_cached(&H_cached, &H_p3);
        ge_p3_to_cached(&X_cached, &X_p3);
        ge_p3_to_cached(&U_cached, &U_p3);

        // in debug mode, check that generators are reproducible
        (void)reproduce_generator_G; assert(reproduce_generator_G() == G);
        (void)reproduce_generator_H; assert(reproduce_generator_H() == H);
        (void)reproduce_generator_X; assert(reproduce_generator_X() == X);
        (void)reproduce_generator_U; assert(reproduce_generator_U() == U);

    });
}
//-------------------------------------------------------------------------------------------------------------------
public_key get_G()
{
    return G;
}
//-------------------------------------------------------------------------------------------------------------------
public_key get_H()
{
    return H;
}
//-------------------------------------------------------------------------------------------------------------------
public_key get_X()
{
    return X;
}
//-------------------------------------------------------------------------------------------------------------------
public_key get_U()
{
    return U;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_G_p3()
{
    init_gens();
    return G_p3;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_H_p3()
{
    init_gens();
    return H_p3;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_X_p3()
{
    init_gens();
    return X_p3;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_U_p3()
{
    init_gens();
    return U_p3;
}
//-------------------------------------------------------------------------------------------------------------------
ge_cached get_G_cached()
{
    init_gens();
    return G_cached;
}
//-------------------------------------------------------------------------------------------------------------------
ge_cached get_H_cached()
{
    init_gens();
    return H_cached;
}
//-------------------------------------------------------------------------------------------------------------------
ge_cached get_X_cached()
{
    init_gens();
    return X_cached;
}
//-------------------------------------------------------------------------------------------------------------------
ge_cached get_U_cached()
{
    init_gens();
    return U_cached;
}
//-------------------------------------------------------------------------------------------------------------------
x25519_pubkey get_x25519_G()
{
    return x25519_G;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace crypto
