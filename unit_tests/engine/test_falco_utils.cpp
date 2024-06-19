// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <gtest/gtest.h>
#include <engine/falco_utils.h>

TEST(FalcoUtils, is_unix_scheme)
{
	/* Wrong prefix */
	ASSERT_EQ(falco::utils::network::is_unix_scheme("something:///run/falco/falco.sock"), false);

	/* Similar prefix, but wrong */
	ASSERT_EQ(falco::utils::network::is_unix_scheme("unix///falco.sock"), false);

	/* Right prefix, passed as an `rvalue` */
	ASSERT_EQ(falco::utils::network::is_unix_scheme("unix:///falco.sock"), true);

	/* Right prefix, passed as a `std::string` */
	std::string url_string("unix:///falco.sock");
	ASSERT_EQ(falco::utils::network::is_unix_scheme(url_string), true);

	/* Right prefix, passed as a `char[]` */
	char url_char[] = "unix:///falco.sock";
	ASSERT_EQ(falco::utils::network::is_unix_scheme(url_char), true);
}

TEST(FalcoUtils, parse_prometheus_interval)
{
	/* Test matrix around correct time conversions. */
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1ms"), 1UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1s"), 1000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1m"), 60000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1h"), 3600000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1d"), 86400000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1w"), 604800000UL);	
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1y"), (unsigned long)31536000000UL);

	ASSERT_EQ(falco::utils::parse_prometheus_interval("300ms"), 300UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("255s"), 255000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("5m"), 300000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("15m"), 900000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("30m"), 1800000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("60m"), 3600000UL);

	/* Test matrix for concatenated time interval examples. */
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1h3m2s1ms"), 3600000UL + 3 * 60000UL + 2 * 1000UL + 1UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1y1w1d1h1m1s1ms"),(unsigned long) 31536000000UL + 604800000UL + 86400000UL + 3600000UL + 60000UL + 1000UL + 1UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("2h5m"), 2 * 3600000UL + 5 * 60000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("2h 5m"), 2 * 3600000UL + 5 * 60000UL);

	/* Invalid, non prometheus compliant time ordering will result in 0ms. */
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1ms1y"), 0UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1t1y"), 0UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1t"), 0UL);

	/* Deprecated option to pass a numeric value in ms without prometheus compliant time unit,
	 * will result in 0ms and as a result the end user will receive an error warning.
	 */
	ASSERT_EQ(falco::utils::parse_prometheus_interval("200"), 0UL);
}

TEST(FalcoUtils, sanitize_metric_name)
{
	ASSERT_EQ(falco::utils::sanitize_metric_name("Testing rule   2 (CVE-2244)"), "Testing_rule_2_CVE_2244");
	ASSERT_EQ(falco::utils::sanitize_metric_name("Testing rule__:2)"), "Testing_rule_:2");
	ASSERT_EQ(falco::utils::sanitize_metric_name("This@is_a$test rule123"), "This_is_a_test_rule123");
	ASSERT_EQ(falco::utils::sanitize_metric_name("RULEwith:special#characters"), "RULEwith:special_characters");
}

TEST(FalcoUtils, matches_wildcard)
{
	ASSERT_TRUE(falco::utils::matches_wildcard("*", "anything"));
	ASSERT_TRUE(falco::utils::matches_wildcard("**", "anything"));
	ASSERT_TRUE(falco::utils::matches_wildcard("*", ""));
	ASSERT_TRUE(falco::utils::matches_wildcard("no star", "no star"));
	ASSERT_TRUE(falco::utils::matches_wildcard("", ""));
	ASSERT_TRUE(falco::utils::matches_wildcard("hello*world", "hello new world"));
	ASSERT_TRUE(falco::utils::matches_wildcard("hello*world*", "hello new world yes"));
	ASSERT_TRUE(falco::utils::matches_wildcard("*hello*world", "come on hello this world"));
	ASSERT_TRUE(falco::utils::matches_wildcard("*hello*****world", "come on hello this world"));

	ASSERT_FALSE(falco::utils::matches_wildcard("no star", ""));
	ASSERT_FALSE(falco::utils::matches_wildcard("", "no star"));
	ASSERT_FALSE(falco::utils::matches_wildcard("star", "no star"));
	ASSERT_FALSE(falco::utils::matches_wildcard("hello*world", "hello new thing"));
	ASSERT_FALSE(falco::utils::matches_wildcard("hello*world", "hello new world yes"));
	ASSERT_FALSE(falco::utils::matches_wildcard("*hello*world", "come on hello this world yes"));
	ASSERT_FALSE(falco::utils::matches_wildcard("*hello*world*", "come on hello this yes"));
}

#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
TEST(FalcoUtils, ipv4addr_to_string)
{
	ASSERT_EQ(falco::utils::network::ipv4addr_to_string(0x0101A8C0), "192.168.1.1");
	ASSERT_EQ(falco::utils::network::ipv4addr_to_string(0x0100007F), "127.0.0.1");
	ASSERT_EQ(falco::utils::network::ipv4addr_to_string(0xFFFFFFFF), "255.255.255.255");
	ASSERT_EQ(falco::utils::network::ipv4addr_to_string(0x00000000), "0.0.0.0");
}

TEST(FalcoUtils, ipv6addr_to_string)
{
	ipv6addr addr1("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
	ASSERT_EQ(falco::utils::network::ipv6addr_to_string(addr1), "2001:db8:85a3:0:0:8a2e:370:7334");

	ipv6addr addr2("fe80:0:0:0:2aa:ff:fe9a:4ca3");
	ASSERT_EQ(falco::utils::network::ipv6addr_to_string(addr2), "fe80:0:0:0:2aa:ff:fe9a:4ca3");

	ipv6addr addr3("0:0:0:0:0:0:0:0");
	ASSERT_EQ(falco::utils::network::ipv6addr_to_string(addr3), "0:0:0:0:0:0:0:0");

	ipv6addr addr4("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
	ASSERT_EQ(falco::utils::network::ipv6addr_to_string(addr4), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}
#endif
