--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Diagnostics: byte offsets and block/section counters that travel
--  alongside Reader.Next without changing its API. The core stays
--  exception-free; callers use Location to report "what failed, where".

pragma SPARK_Mode (On);

with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.Diag is

   type Location is record
      Block_Index   : Natural;
      Byte_Offset   : Natural;
      Section_Index : Positive;
      Valid         : Boolean;
   end record;

   type Tracker is record
      Next_Block   : Natural;
      Next_Section : Positive;
      Started      : Boolean;
   end record;

   function Init return Tracker is
     ((Next_Block => 1, Next_Section => 1, Started => False));

   --  Call once per Reader.Next result. Offset is the start of the
   --  block just returned (Cur.Pos before the call is easiest: pass
   --  Curr.Next - Curr.Total_Length when Error = None).
   procedure Note_Block
     (T         : in out Tracker;
      Kind      : Block_Kind;
      Had_Error : Boolean;
      Offset    : Natural;
      Loc       : out Location)
   with
     Pre  => True,
     Post => Loc.Valid and then Loc.Byte_Offset = Offset;

end Pcapng_In_Ada.Diag;
