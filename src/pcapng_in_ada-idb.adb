--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;
with Pcapng_In_Ada.Options;

package body Pcapng_In_Ada.IDB is

   function Ts_Ticks_Per_Second
     (Resol_Byte : Unsigned_8) return Unsigned_64
   is
      Low : constant Unsigned_8 := Resol_Byte and 16#7F#;
      --  Exact powers of ten; index 0 .. 19 covers every unclamped
      --  decimal tsresol value without a multiply loop (nonlinear
      --  arithmetic the prover cannot discharge).
      Pow10 : constant array (0 .. 19) of Unsigned_64 :=
        (1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000,
         100_000_000, 1_000_000_000, 10_000_000_000, 100_000_000_000,
         1_000_000_000_000, 10_000_000_000_000, 100_000_000_000_000,
         1_000_000_000_000_000, 10_000_000_000_000_000,
         100_000_000_000_000_000, 1_000_000_000_000_000_000,
         10_000_000_000_000_000_000);
   begin
      if (Resol_Byte and 16#80#) /= 0 then
         --  Binary: 2 ** Low via a single shift (Low <= 60 keeps it
         --  exact and free of overflow checks).
         if Low > 60 then
            return 1;
         end if;
         return Shift_Left (Unsigned_64'(1), Natural (Low));
      else
         if Low > 19 then
            return 1_000_000;
         end if;
         return Pow10 (Natural (Low));
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

   procedure Get_Option
     (Buf   : Byte_Buffer;
      View  : IDB_View;
      Order : Byte_Order;
      Code  : Unsigned_16;
      First : out Natural;
      Last  : out Natural;
      Found : out Boolean)
   is
      use Pcapng_In_Ada.Options;
      O : Option_View;
   begin
      First := 1;
      Last := 0;
      Found := False;
      if not View.Valid then
         return;
      end if;
      if View.Options_First = 0
        or else View.Options_First > Buf'Last
        or else View.Body_Last < View.Options_First
        or else View.Options_First < Buffer_Index'First
        or else View.Options_First > Buffer_Index'Last
      then
         return;
      end if;
      Find_Option (Buf, View.Options_First, View.Body_Last,
                   Order, Code, O, Found);
      if Found and then O.Valid then
         First := O.First;
         Last := O.Last;
      else
         Found := False;
      end if;
   end Get_Option;

end Pcapng_In_Ada.IDB;
