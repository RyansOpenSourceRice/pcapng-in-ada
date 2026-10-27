--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Pcapng_In_Ada; use Pcapng_In_Ada;

package body Pcapng_In_Ada.Diag is

   procedure Note_Block
     (T         : in out Tracker;
      Kind      : Block_Kind;
      Had_Error : Boolean;
      Offset    : Natural;
      Loc       : out Location)
   is
   begin
      if not T.Started then
         T.Started := True;
      elsif Kind = Kind_SHB and then not Had_Error then
         --  A later SHB starts a new section: it belongs to the new
         --  section, so bump before stamping its location.
         if T.Next_Section < Positive'Last then
            T.Next_Section := T.Next_Section + 1;
         end if;
      end if;
      Loc := (Block_Index   => T.Next_Block,
              Byte_Offset   => Offset,
              Section_Index => T.Next_Section,
              Valid         => True);
      if not Had_Error then
         if T.Next_Block < Natural'Last then
            T.Next_Block := T.Next_Block + 1;
         end if;
      end if;
   end Note_Block;

end Pcapng_In_Ada.Diag;
