--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;

package body Pcapng_In_Ada.Packet is

   function Dec32
     (Buf : Byte_Buffer; Pos : Buffer_Index; Order : Byte_Order)
      return Unsigned_32
   with Pre => Pos >= Buf'First and then Pos <= Buf'Last - 3
   is
   begin
      case Order is
         when Little_Endian => return Decode_U32_LE (Buf, Pos);
         when Big_Endian    => return Decode_U32_BE (Buf, Pos);
      end case;
   end Dec32;

   procedure Parse_EPB
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      Order : Byte_Order;
      View  : out EPB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
      Hdr   : Block_Header;
      H_Nx  : Natural;
      H_Err : Error_Kind;
      Ifx   : Unsigned_32;
      Tsh   : Unsigned_32;
      Tsl   : Unsigned_32;
      Cap   : Unsigned_32;
      Orig  : Unsigned_32;
      Pad   : Natural;
      D_End : Natural;
   begin
      View :=
        (If_Index => 0, Ts_High => 0, Ts_Low => 0, Cap_Len => 0,
         Orig_Len => 0, Data_First => Pos, Data_Last => Pos - 1,
         Opt_First => 0, Total_Length => 0, Valid => False);
      Next := Pos;
      Error := Truncated;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < EPB_Min_Size then
         return;
      end if;

      Parse_Header (Buf, Pos, Order, Hdr, H_Nx, H_Err);
      if H_Err /= None then
         Error := H_Err;
         return;
      end if;
      if Hdr.Block_Type /= EPB_Type then
         Error := Bad_Magic;
         return;
      end if;
      if Hdr.Total_Length < EPB_Min_Size then
         Error := Bad_Length;
         return;
      end if;
      if Pos > Buf'Last - 27 then
         Error := Truncated;
         return;
      end if;

      Ifx := Dec32 (Buf, Pos + 8, Order);
      Tsh := Dec32 (Buf, Pos + 12, Order);
      Tsl := Dec32 (Buf, Pos + 16, Order);
      Cap := Dec32 (Buf, Pos + 20, Order);
      Orig := Dec32 (Buf, Pos + 24, Order);

      if Cap > Unsigned_32 (Max_Block_Size) then
         Error := Bad_Length;
         return;
      end if;
      --  caplen must fit inside the block body.
      if Natural (Cap) + EPB_Min_Size > Hdr.Total_Length
        and then Cap /= 0
      then
         --  Allow trailing options of zero length only via exact math
         --  below; this early check catches gross overflows.
         if Hdr.Total_Length < EPB_Min_Size + Natural (Cap) then
            Error := Bad_Length;
            return;
         end if;
      end if;

      Pad := Padding_For (Natural (Cap));
      if Natural (Cap) + Pad + EPB_Min_Size > Hdr.Total_Length then
         Error := Bad_Length;
         return;
      end if;
      if Cap = 0 then
         D_End := Pos + 27;
      else
         if Pos + 28 + Natural (Cap) - 1 > Buf'Last then
            Error := Truncated;
            return;
         end if;
         D_End := Pos + 28 + Natural (Cap) - 1;
      end if;

      View :=
        (If_Index => Ifx, Ts_High => Tsh, Ts_Low => Tsl,
         Cap_Len => Cap, Orig_Len => Orig,
         Data_First => Pos + 28,
         Data_Last  => D_End,
         Opt_First  => Pos + 28 + Natural (Cap) + Pad,
         Total_Length => Hdr.Total_Length, Valid => True);
      Next := H_Nx;
      Error := None;
   end Parse_EPB;

   procedure Parse_SPB
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      Order : Byte_Order;
      View  : out SPB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
      Hdr   : Block_Header;
      H_Nx  : Natural;
      H_Err : Error_Kind;
      Orig  : Unsigned_32;
      Frame_Body  : Natural;
      Cap   : Natural;
   begin
      View :=
        (Orig_Len => 0, Data_First => Pos, Data_Last => Pos - 1,
         Total_Length => 0, Valid => False);
      Next := Pos;
      Error := Truncated;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < SPB_Min_Size then
         return;
      end if;

      Parse_Header (Buf, Pos, Order, Hdr, H_Nx, H_Err);
      if H_Err /= None then
         Error := H_Err;
         return;
      end if;
      if Hdr.Block_Type /= SPB_Type then
         Error := Bad_Magic;
         return;
      end if;
      --  The fixed fields (header + orig_len + trailer) need 16 bytes;
      --  checking first keeps the arithmetic below from underflowing on
      --  short Totals (12 .. 15 would otherwise raise).
      if Hdr.Total_Length < SPB_Min_Size then
         Error := Bad_Length;
         return;
      end if;
      Orig := Dec32 (Buf, Pos + 8, Order);
      Frame_Body := Hdr.Total_Length - Block_Header_Size - Block_Trailer_Size - 4;
      --  Body after orig_len must be a whole number of 32-bit words
      --  (data + zero padding); anything else is malformed, and the
      --  1 .. 3 remainders would underflow the padding subtraction.
      if Frame_Body mod 4 /= 0 then
         Error := Bad_Length;
         return;
      end if;
      pragma Assert (Padding_For (Frame_Body) = 0);
      Cap := Frame_Body - Padding_For (Frame_Body);
      pragma Assert (Cap = Frame_Body);
      pragma Assert (Cap <= Buf'Last - Pos - 15);

      if Pos + 12 + Cap - 1 > Buf'Last and then Cap > 0 then
         Error := Truncated;
         return;
      end if;

      View :=
        (Orig_Len => Orig,
         Data_First => Pos + 12,
         Data_Last  => (if Cap = 0 then Pos + 11 else Pos + 12 + Cap - 1),
         Total_Length => Hdr.Total_Length, Valid => True);
      Next := H_Nx;
      Error := None;
   end Parse_SPB;

end Pcapng_In_Ada.Packet;
