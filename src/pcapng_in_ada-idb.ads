--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Interface Description Block (IDB): link type, snap length, timestamp
--  resolution, and the options region.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.IDB is

   type IDB_View is record
      Link_Type      : Unsigned_16;
      Snap_Len       : Unsigned_32;
      Ts_Resol       : Unsigned_8;
      Ts_Is_Binary   : Boolean;
      Body_First     : Buffer_Index;
      Body_Last      : Natural;
      Options_First  : Natural;
      Total_Length   : Natural;
      Valid          : Boolean;
   end record;

   procedure Parse_IDB
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      Order : Byte_Order;
      View  : out IDB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   with
     Pre  => Pos >= Buf'First and then Pos <= Buf'Last,
     Post => (if Error = None then Next > Pos and then Next - 1 <= Buf'Last and then View.Valid);

   --  Decode the tsresol option byte per the spec: MSB set means binary
   --  (2**LSB), otherwise decimal (10**value).
   function Ts_Ticks_Per_Second
     (Resol_Byte : Unsigned_8) return Unsigned_64
   with Post => Ts_Ticks_Per_Second'Result > 0;

end Pcapng_In_Ada.IDB;
