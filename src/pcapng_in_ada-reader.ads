--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Forward cursor over a pcapng image. Detects the SHB byte order,
--  walks block by block, and surfaces typed views for SHB / IDB /
--  EPB / SPB. Unknown blocks are skipped, never rejected.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.SHB;
with Pcapng_In_Ada.IDB;
with Pcapng_In_Ada.Packet;

package Pcapng_In_Ada.Reader is

   type Cursor is record
      Pos     : Positive;
      Order   : Byte_Order;
      Started : Boolean;
      At_End  : Boolean;
   end record;

   function First (Start_At : Buffer_Index := 1) return Cursor is
     ((Pos => Start_At, Order => Little_Endian,
       Started => False, At_End => False));

   type Current_Block is record
      Kind         : Block_Kind;
      Block_Type   : Unsigned_32;
      Total_Length : Natural;
      Next         : Natural;
      Error        : Error_Kind;
   end record;

   --  Advance one block. First call must land on an SHB.
   --  Cur.Pos one past Buf'Last is accepted (empty At_End step).
   --  Written with subtraction so the check itself cannot overflow.
   --  The cursor never rewinds before Buf'First.
   procedure Next
     (Buf    : Byte_Buffer;
      Cur    : in out Cursor;
      Curr   : out Current_Block)
   with
     Pre  => Cur.Pos >= Buf'First and then Cur.Pos - 1 <= Buf'Last,
     Post => Cur.Pos >= Buf'First;

   function Has_Interfaces return Boolean is (True);

    --  Convenience decoders that re-parse the block at Pos.
    procedure Read_SHB_At
      (Buf   : Byte_Buffer;
       Pos : Buffer_Index;
       View  : out SHB.SHB_View;
       Next  : out Natural;
       Error : out Error_Kind)
    with
      Pre => Pos >= Buf'First and then Pos <= Buf'Last;

    procedure Read_IDB_At
      (Buf   : Byte_Buffer;
       Pos : Buffer_Index;
       Order : Byte_Order;
       View  : out IDB.IDB_View;
       Next  : out Natural;
       Error : out Error_Kind)
    with
      Pre => Pos >= Buf'First and then Pos <= Buf'Last;

    procedure Read_EPB_At
      (Buf   : Byte_Buffer;
       Pos : Buffer_Index;
       Order : Byte_Order;
       View  : out Packet.EPB_View;
       Next  : out Natural;
       Error : out Error_Kind)
    with
      Pre => Pos >= Buf'First and then Pos <= Buf'Last;

   function Block_Count
     (Buf : Byte_Buffer; Limit : Natural := 1_000_000) return Natural
   with
     Pre => Limit > 0;

end Pcapng_In_Ada.Reader;
