--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  AUnit runner: runs the full suite, exits 1 on any failure so that
--  `alr test` and CI fail loudly.

with AUnit; use AUnit;
with AUnit.Run;
with AUnit.Reporter.Text;
with GNAT.OS_Lib;
with Pcapng_Tests;

procedure Aunit_Runner is
   function Run is new AUnit.Run.Test_Runner_With_Status (Pcapng_Tests.Suite);
   Reporter : AUnit.Reporter.Text.Text_Reporter;
   Result : AUnit.Status;
begin
   Result := Run (Reporter);
   if Result = AUnit.Failure then
      GNAT.OS_Lib.OS_Exit (1);
   end if;
end Aunit_Runner;
