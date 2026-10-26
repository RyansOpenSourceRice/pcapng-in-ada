--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Interface Statistics Block (ISB): typed view over if_index +
--  64-bit timestamp + options region. Counters live in options, so
--  the view points at them instead of copying.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.ISB is

   ISB_Min_Size : constant Positive := 24;

   --  Common ISB option codes (IETF draft, plus opt_comment = 1).
   ISB_Starttime    : constant Unsigned_16 := 2;
   ISB_Endtime      : constant Unsigned_16 := 3;
   ISB_IfRecv       : constant Unsigned_16 := 4;
   ISB_IfDrop       : constant Unsigned_16 := 5;
   ISB_FilterAccept : constant Unsigned_16 := 6;
   ISB_OsDrop       : constant Unsigned_16 := 7;
   ISB_UsrDeliv     : constant Unsigned_16 := 8;

   type ISB_View is record
      If_Index     : Unsigned_32;
      Ts_High      : Unsigned_32;
      Ts_Low       : Unsigned_32;
      Body_First   : Buffer_Index;
      Body_Last    : Natural;
      Opt_First    : Natural;
      Total_Length : Natural;
      Valid        : Boolean;
   end record;

   procedure Parse_ISB
     (Buf   : Byte_Buffer;
      Pos   : Buffer_Index;
      Order : Byte_Order;
      View  : out ISB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last,
     Post => (if Error = None then Next > Pos
              and then Next - 1 <= Buf'Last and then View.Valid);

   function Timestamp_64 (View : ISB_View) return Unsigned_64 is
     (Shift_Left (Unsigned_64 (View.Ts_High), 32)
      or Unsigned_64 (View.Ts_Low));

end Pcapng_In_Ada.ISB;
