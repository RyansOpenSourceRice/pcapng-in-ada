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

   Max_Comment_Len : constant Natural := 512;
   Max_Name_Len    : constant Natural := 256;

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

   --  Byte-order-explicit writers (v0.3). Same framing as above but
   --  honor Order on the wire; existing Append_* stay LE for compat.
   procedure Append_SHB_Ex
     (Buf          : in out Byte_Buffer;
      Last         : in out Natural;
      Order        : Byte_Order;
      Section_Len  : Integer_64 := -1;
      Error        : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   procedure Append_IDB_Ex
     (Buf       : in out Byte_Buffer;
      Last      : in out Natural;
      Order     : Byte_Order;
      Link_Type : Unsigned_16 := Ethernet_Link;
      Snap_Len  : Unsigned_32 := Default_Snap_Len;
      Error     : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   procedure Append_EPB_Ex
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      Order    : Byte_Order;
      If_Index : Unsigned_32;
      Ts       : Unsigned_64;
      Data     : Byte_Buffer;
      Error    : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   procedure Append_SPB_Ex
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      Order    : Byte_Order;
      Orig_Len : Unsigned_32;
      Data     : Byte_Buffer;
      Error    : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   --  Single-option convenience writers. Comment/Name are raw UTF-8
   --  bytes without NUL; over-long input returns Bad_Length.
   procedure Append_SHB_With_Comment
     (Buf     : in out Byte_Buffer;
      Last    : in out Natural;
      Order   : Byte_Order;
      Comment : Byte_Buffer;
      Error   : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   procedure Append_IDB_With_Name
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      Order    : Byte_Order;
      Link     : Unsigned_16 := Ethernet_Link;
      Snap     : Unsigned_32 := Default_Snap_Len;
      If_Name  : Byte_Buffer;
      Error    : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   procedure Append_EPB_With_Comment
     (Buf      : in out Byte_Buffer;
      Last     : in out Natural;
      Order    : Byte_Order;
      If_Index : Unsigned_32;
      Ts       : Unsigned_64;
      Data     : Byte_Buffer;
      Comment  : Byte_Buffer;
      Error    : out Error_Kind)
   with
     Pre  => Last <= Buf'Last,
     Post => True;

   --  Total bytes written so far (0 when Last < Buf'First, when the
   --  bounds are insane, or when nothing was written yet).
   function Written (Buf : Byte_Buffer; Last : Natural) return Natural is
     (if Last < Buf'First or else Last > Buf'Last or else Buf'First < 1 then 0
      else Last - Buf'First + 1);

end Pcapng_In_Ada.Writer;
