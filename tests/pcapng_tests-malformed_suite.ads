--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Malformed-input + truncation-semantics suite
--  (ported from test_malformed.adb, plus caplen/origlen + snaplen cases).

with AUnit.Test_Suites;

package Pcapng_Tests.Malformed_Suite is

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end Pcapng_Tests.Malformed_Suite;
