--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  TLV option iterator shared by every block type. Options are
--  (Code:16, Length:16, Value:Length, padding-to-32). Code 0 (endofopt)
--  and code 0 handling stop the walk.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.Options is

   End_Of_Opt : constant Unsigned_16 := 0;
   Comment_Opt : constant Unsigned_16 := 1;

   type Option_View is record
      Code   : Unsigned_16;
      Length : Natural;
      First  : Natural;
      Last   : Natural;
      Valid  : Boolean;
   end record;

   --  Read the option starting at Pos inside Body_First .. Body_Last.
   --  Next is the offset of the following option (or Body_Last + 1).
   procedure Next_Option
     (Buf        : Byte_Buffer;
      Pos : Buffer_Index;
      Body_First : Buffer_Index;
      Body_Last  : Natural;
      Order      : Byte_Order;
      Opt        : out Option_View;
      Next       : out Natural;
      Error      : out Error_Kind)
    with
     Pre => Pos >= Buf'First
       and then Body_First >= Buf'First
       and then Body_First - 1 <= Buf'Last
       and then Body_Last <= Buf'Last,
     Post => True;

   function Options_Byte_Size (Body_Len : Natural) return Boolean is
     (Body_Len mod 4 = 0);

end Pcapng_In_Ada.Options;
