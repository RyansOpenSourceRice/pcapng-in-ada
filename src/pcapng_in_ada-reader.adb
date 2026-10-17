--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;
with Pcapng_In_Ada.SHB;
with Pcapng_In_Ada.IDB;
with Pcapng_In_Ada.Packet;

package body Pcapng_In_Ada.Reader is

   procedure Read_SHB_At
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      View  : out SHB.SHB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
   begin
      SHB.Parse_SHB (Buf, Pos, View, Next, Error);
   end Read_SHB_At;

   procedure Read_IDB_At
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      Order : Byte_Order;
      View  : out IDB.IDB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
   begin
      IDB.Parse_IDB (Buf, Pos, Order, View, Next, Error);
   end Read_IDB_At;

   procedure Read_EPB_At
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      Order : Byte_Order;
      View  : out Packet.EPB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
   begin
      Packet.Parse_EPB (Buf, Pos, Order, View, Next, Error);
   end Read_EPB_At;

   procedure Next
     (Buf  : Byte_Buffer;
      Cur  : in out Cursor;
      Curr : out Current_Block)
   is
      Sh : SHB.SHB_View;
      Nx : Natural;
      Er : Error_Kind;
      Hdr   : Block_Header;
      H_Nx  : Natural;
      H_Err : Error_Kind;
   begin
      Curr :=
        (Kind => Kind_Unknown, Block_Type => 0, Total_Length => 0,
         Next => Cur.Pos, Error => Truncated);

      if Cur.At_End then
         Curr.Error := None;
         Curr.Next := Cur.Pos;
         return;
      end if;
      if Cur.Pos < Buf'First or else Cur.Pos > Buf'Last then
         Cur.At_End := True;
         Curr.Error := None;
         return;
      end if;

      if not Cur.Started then
         SHB.Parse_SHB (Buf, Cur.Pos, Sh, Nx, Er);
         if Er /= None then
            Curr.Error := Er;
            return;
         end if;
         Cur.Order := Sh.Order;
         Cur.Started := True;
         Cur.Pos := Nx;
         Curr :=
           (Kind => Kind_SHB, Block_Type => SHB_Type,
            Total_Length => Sh.Total_Length, Next => Nx, Error => None);
         if Nx > Buf'Last then
            Cur.At_End := True;
         end if;
         return;
      end if;

      Parse_Header (Buf, Cur.Pos, Cur.Order, Hdr, H_Nx, H_Err);
      if H_Err /= None then
         Curr.Error := H_Err;
         return;
      end if;

      --  A fresh SHB restarts the section and may flip byte order.
      if Hdr.Block_Type = SHB_Type then
         SHB.Parse_SHB (Buf, Cur.Pos, Sh, Nx, Er);
         if Er /= None then
            Curr.Error := Er;
            return;
         end if;
         Cur.Order := Sh.Order;
         Cur.Pos := Nx;
         Curr :=
           (Kind => Kind_SHB, Block_Type => SHB_Type,
            Total_Length => Sh.Total_Length, Next => Nx, Error => None);
      else
         Curr :=
           (Kind => Block_Kind_Of (Hdr.Block_Type),
            Block_Type => Hdr.Block_Type,
            Total_Length => Hdr.Total_Length,
            Next => H_Nx, Error => None);
         Cur.Pos := H_Nx;
         --  Track section-local interface count implicitly: IDB blocks
         --  simply advance; callers map If_Index via their own table.
      end if;

      if Cur.Pos > Buf'Last then
         Cur.At_End := True;
      end if;
   end Next;

   function Block_Count
     (Buf : Byte_Buffer; Limit : Natural := 1_000_000) return Natural
   is
      Cur   : Cursor := First (1);
      Curr  : Current_Block;
      Count : Natural := 0;
   begin
      --  Reject insane bounds up front so the Buffer_Index conversions
      --  and cursor arithmetic below are provably safe; a short image
      --  simply holds no complete blocks.
      if Buf'First < Buffer_Index'First
        or else Buf'Last > Buffer_Index'Last
        or else Buf'Length < Min_Block_Size
      then
         return 0;
      end if;
      Cur := First (Buf'First);
      for I in 1 .. Limit loop
         pragma Loop_Invariant (Count < I);
         pragma Loop_Invariant (Cur.Pos >= Buf'First);
         --  Re-establish Next's precondition locally: the cursor may
         --  rest one past the end after a block (At_End), which the
         --  checks below treat as a normal stop.
         if Cur.Pos < Buf'First or else Cur.Pos > Buf'Last then
            return Count;
         end if;
         Next (Buf, Cur, Curr);
         if Curr.Error /= None then
            return Count;
         end if;
         if Cur.At_End and then Curr.Error = None and then Curr.Total_Length = 0 then
            return Count;
         end if;
         Count := Count + 1;
         if Cur.At_End then
            return Count;
         end if;
         if Curr.Next <= 0 then
            return Count;
         end if;
      end loop;
      return Count;
   end Block_Count;

end Pcapng_In_Ada.Reader;
