--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;

package body Pcapng_In_Ada.IDB is

   function Ts_Ticks_Per_Second
     (Resol_Byte : Unsigned_8) return Unsigned_64
   is
      Low : constant Unsigned_8 := Resol_Byte and 16#7F#;
      Acc : Unsigned_64 := 1;
   begin
      if (Resol_Byte and 16#80#) /= 0 then
         --  Binary: 2 ** Low, Low <= 127 but loop is bounded by spec
         --  values (real captures use <= 30). Clamp defensively.
         if Low > 60 then
            return 1;
         end if;
         for I in 1 .. Natural (Low) loop
            pragma Loop_Invariant (Acc >= 1);
            Acc := Acc * 2;
         end loop;
         return Acc;
      else
         if Low > 19 then
            return 1_000_000;
         end if;
         for I in 1 .. Natural (Low) loop
            pragma Loop_Invariant (Acc >= 1);
            Acc := Acc * 10;
         end loop;
         if Acc = 0 then
            return 1;
         end if;
         return Acc;
      end if;
   end Ts_Ticks_Per_Second;

   procedure Parse_IDB
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      Order : Byte_Order;
      View  : out IDB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
      Hdr   : Block_Header;
      H_Nx  : Natural;
      H_Err : Error_Kind;
      Link  : Unsigned_16;
      Snap  : Unsigned_32;
   begin
      View :=
        (Link_Type => 0, Snap_Len => 0, Ts_Resol => 6,
         Ts_Is_Binary => False, Body_First => Pos, Body_Last => Pos - 1,
         Options_First => 0, Total_Length => 0, Valid => False);
      Next := Pos;
      Error := Truncated;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < IDB_Min_Size then
         return;
      end if;

      Parse_Header (Buf, Pos, Order, Hdr, H_Nx, H_Err);
      if H_Err /= None then
         Error := H_Err;
         return;
      end if;
      if Hdr.Block_Type /= IDB_Type then
         Error := Bad_Magic;
         return;
      end if;
      if Hdr.Total_Length < IDB_Min_Size then
         Error := Bad_Length;
         return;
      end if;
      if Pos > Buf'Last - 15 then
         Error := Truncated;
         return;
      end if;

      case Order is
         when Little_Endian =>
            Link := Decode_U16_LE (Buf, Pos + 8);
            Snap := Decode_U32_LE (Buf, Pos + 12);
         when Big_Endian =>
            Link := Decode_U16_BE (Buf, Pos + 8);
            Snap := Decode_U32_BE (Buf, Pos + 12);
      end case;

      --  Reserved bytes at Pos+10..Pos+11 must be zero per spec; be
      --  lenient on read (Wireshark ignores them) but snaplen 0
      --  means "no limit", keep as-is.
      View :=
        (Link_Type => Link, Snap_Len => Snap, Ts_Resol => 6,
         Ts_Is_Binary => False, Body_First => Pos + 8,
         Body_Last => Pos + Hdr.Total_Length - Block_Trailer_Size - 1,
         Options_First => Pos + 16,
         Total_Length => Hdr.Total_Length, Valid => True);
      Next := H_Nx;
      Error := None;
   end Parse_IDB;

end Pcapng_In_Ada.IDB;
