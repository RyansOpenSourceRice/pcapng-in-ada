--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Little-endian writer. Appends SHB / IDB / EPB / SPB into a caller
--  buffer; every append is bounds-checked and reports No_Space instead
--  of raising. Output always uses section byte order LE and version 1.0.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.Writer is

   Default_Snap_Len : constant Unsigned_32 := 262_144;
   Ethernet_Link    : constant Unsigned_16 := 1;

   --  Append a Section Header Block (no options). Advances Last.
   procedure Append_SHB
     (Buf   : in out Byte_Buffer;
      Last  : in out Natural;
      Error : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   --  Append an Interface Description Block for Ethernet + default snap.
   procedure Append_IDB
     (Buf       : in out Byte_Buffer;
      Last      : in out Natural;
      Link_Type : Unsigned_16 := Ethernet_Link;
      Snap_Len  : Unsigned_32 := Default_Snap_Len;
      Error     : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   --  Append an Enhanced Packet Block with the given payload slice.
   procedure Append_EPB
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      If_Index : Unsigned_32;
      Ts       : Unsigned_64;
      Data     : Byte_Buffer;
      Error    : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   --  Total bytes written so far (0 when Last < Buf'First).
   function Written (Buf : Byte_Buffer; Last : Natural) return Natural is
     (if Last < Buf'First then 0 else Last - Buf'First + 1);

end Pcapng_In_Ada.Writer;
