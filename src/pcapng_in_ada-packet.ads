--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Packet blocks: Enhanced Packet Block (EPB) and Simple Packet Block
--  (SPB). Views point into the caller buffer; no copies, no heap.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.Packet is

   type EPB_View is record
      If_Index     : Unsigned_32;
      Ts_High      : Unsigned_32;
      Ts_Low       : Unsigned_32;
      Cap_Len      : Unsigned_32;
      Orig_Len     : Unsigned_32;
      Data_First   : Buffer_Index;
      Data_Last    : Natural;
      Opt_First    : Natural;
      Total_Length : Natural;
      Valid        : Boolean;
   end record;

   type SPB_View is record
      Orig_Len     : Unsigned_32;
      Data_First   : Buffer_Index;
      Data_Last    : Natural;
      Total_Length : Natural;
      Valid        : Boolean;
   end record;

   procedure Parse_EPB
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      Order : Byte_Order;
      View  : out EPB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last,
     Post => (if Error = None then Next > Pos and then Next - 1 <= Buf'Last and then View.Valid);

   procedure Parse_SPB
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      Order : Byte_Order;
      View  : out SPB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last,
     Post => (if Error = None then Next > Pos and then Next - 1 <= Buf'Last and then View.Valid);

   function Timestamp_64 (View : EPB_View) return Unsigned_64 is
     (Shift_Left (Unsigned_64 (View.Ts_High), 32)
      or Unsigned_64 (View.Ts_Low));

end Pcapng_In_Ada.Packet;
