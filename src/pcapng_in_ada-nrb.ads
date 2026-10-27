--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Name Resolution Block (NRB): typed view over the record list.
--  Records are (type:16, len:16, value, pad32); type 0 / len 0 ends.
--  Unknown record types are accepted and counted; malformed lengths
--  are Bad_Length, short buffers are Truncated.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.NRB is

   NRB_End_Record  : constant Unsigned_16 := 0;
   NRB_IPv4_Record : constant Unsigned_16 := 1;
   NRB_IPv6_Record : constant Unsigned_16 := 2;

   type NRB_View is record
      Record_Count : Natural;
      Body_First   : Buffer_Index;
      Body_Last    : Natural;
      Opt_First    : Natural;
      Total_Length : Natural;
      Valid        : Boolean;
   end record;

   procedure Parse_NRB
     (Buf   : Byte_Buffer;
      Pos   : Buffer_Index;
      Order : Byte_Order;
      View  : out NRB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last,
     Post => (if Error = None then Next > Pos
              and then Next - 1 <= Buf'Last and then View.Valid);

end Pcapng_In_Ada.NRB;
