--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Root of the AUnit suite tree for pcapng_in_ada.

with AUnit.Test_Suites;

package Pcapng_Tests is

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end Pcapng_Tests;
