--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

with AUnit.Test_Suites; use AUnit.Test_Suites;
with Pcapng_Tests.Reader_Suite;
with Pcapng_Tests.Malformed_Suite;
with Pcapng_Tests.V02_Suite;

package body Pcapng_Tests is

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      S : constant Access_Test_Suite := New_Suite;
   begin
      S.Add_Test (Reader_Suite.Suite);
      S.Add_Test (Malformed_Suite.Suite);
      S.Add_Test (V02_Suite.Suite);
      return S;
   end Suite;

end Pcapng_Tests;
