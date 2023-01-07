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

// NOT FOR PRODUCTION

//paired header
#include "tx_extra.h"

//local headers
#include "common/varint.h"
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "span.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// get an extra field element at the specified position
// - returns false if could not get an element
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_extra_field_element(const epee::span<const unsigned char> &tx_extra,
    std::size_t &element_position_inout,
    ExtraFieldElement &element_out)
{
    //TODO: simplify this function?
    if (element_position_inout >= tx_extra.size())
        return false;

    int parse_result;

    // parse the type
    parse_result = tools::read_varint(tx_extra.data() + element_position_inout, tx_extra.end(), element_out.m_type);

    if (parse_result <= 0)  //could not get a type
        return false;

    element_position_inout += parse_result;

    // parse the length
    std::uint64_t length{0};
    parse_result = tools::read_varint(tx_extra.data() + element_position_inout, tx_extra.end(), length);

    if (parse_result <= 0)  //could not get the length
        return false;

    element_position_inout += parse_result;

    // parse the value
    if (element_position_inout + length > tx_extra.size())  //value extends past the end
        return false;

    element_out.m_value.resize(length);
    memcpy(element_out.m_value.data(), tx_extra.data() + element_position_inout, length);
    element_position_inout += length;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
// convert an element to bytes and append to the input variable: varint(type) || varint(length) || value
//-------------------------------------------------------------------------------------------------------------------
static void append_bytes(const ExtraFieldElement &element, std::vector<unsigned char> &bytes_inout)
{
    //TODO: simplify this function?
    // varint(type) || varint(length) || bytes
    bytes_inout.reserve(bytes_inout.size() + 18 + element.m_value.size());

    unsigned char v_variable[(sizeof(std::size_t) * 8 + 6) / 7];
    unsigned char *v_variable_end = v_variable;
    std::size_t v_length;

    // type
    tools::write_varint(v_variable_end, element.m_type);
    assert(v_variable_end <= v_variable + sizeof(v_variable));
    v_length = v_variable_end - v_variable;
    bytes_inout.resize(bytes_inout.size() + v_length);
    memcpy(bytes_inout.data() + bytes_inout.size() - v_length, v_variable, v_length);

    // length
    v_variable_end = v_variable;
    tools::write_varint(v_variable_end, element.m_value.size());
    assert(v_variable_end <= v_variable + sizeof(v_variable));
    v_length = v_variable_end - v_variable;
    bytes_inout.resize(bytes_inout.size() + v_length);
    memcpy(bytes_inout.data() + bytes_inout.size() - v_length, v_variable, v_length);

    // value
    bytes_inout.resize(bytes_inout.size() + element.m_value.size());
    memcpy(bytes_inout.data() + bytes_inout.size() - element.m_value.size(),
        element.m_value.data(),
        element.m_value.size());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool operator<(const ExtraFieldElement &a, const ExtraFieldElement &b)
{
    if (a.m_type < b.m_type)
        return true;
    if (a.m_type > b.m_type)
        return false;
    if (a.m_value.size() < b.m_value.size())
        return true;
    if (a.m_value.size() > b.m_value.size())
        return false;
    return a.m_value < b.m_value;  //same type, same length
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t length(const ExtraFieldElement &element)
{
    return element.m_value.size();
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_extra(std::vector<ExtraFieldElement> elements, TxExtra &tx_extra_out)
{
    tx_extra_out.clear();

    // tx_extra should be sorted
    std::sort(elements.begin(), elements.end());

    for (const ExtraFieldElement &element : elements)
        append_bytes(element, tx_extra_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_extra_field_elements(const TxExtra &tx_extra, std::vector<ExtraFieldElement> &elements_out)
{
    elements_out.clear();

    // extract elements from the tx extra field
    std::size_t element_position{0};
    const epee::span<const unsigned char> tx_extra_span{epee::to_span(tx_extra)};

    while (element_position < tx_extra.size())
    {
        elements_out.emplace_back();

        if (!try_get_extra_field_element(tx_extra_span, element_position, elements_out.back()))
        {
            elements_out.pop_back();
            return false;
        }
    }

    // if we didn't consume all bytes, then the field is malformed
    if (element_position != tx_extra.size())
        return false;

    // if the elements in a tx extra are not sorted, then the field is malformed
    if (!std::is_sorted(elements_out.begin(), elements_out.end()))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void accumulate_extra_field_elements(const std::vector<ExtraFieldElement> &elements_to_add,
    std::vector<ExtraFieldElement> &elements_inout)
{
    elements_inout.reserve(elements_inout.size() + elements_to_add.size());
    elements_inout.insert(elements_inout.end(), elements_to_add.begin(), elements_to_add.end());
}
//-------------------------------------------------------------------------------------------------------------------
void accumulate_extra_field_elements(const TxExtra &partial_memo,
    std::vector<ExtraFieldElement> &elements_inout)
{
    std::vector<ExtraFieldElement> temp_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(partial_memo, temp_memo_elements),
        "Could not accumulate extra field elements: malformed partial memo.");
    accumulate_extra_field_elements(temp_memo_elements, elements_inout);
}
//-------------------------------------------------------------------------------------------------------------------
ExtraFieldElement gen_extra_field_element()
{
    ExtraFieldElement temp;
    temp.m_type = crypto::rand_idx(static_cast<std::size_t>(-1));
    temp.m_value.resize(crypto::rand_idx(static_cast<std::size_t>(101)));  //limit random field to 100 bytes for performance
    crypto::rand(temp.m_value.size(), temp.m_value.data());
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
