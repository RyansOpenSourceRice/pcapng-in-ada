--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  v0.2 feature suite (ported from test_v02.adb): BE writers,
--  single-option writers, NRB/ISB views, Stream chunking, Diag.

with AUnit.Test_Suites;

package Pcapng_Tests.V02_Suite is

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end Pcapng_Tests.V02_Suite;
