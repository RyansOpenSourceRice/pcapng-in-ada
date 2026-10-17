--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;

package body Pcapng_In_Ada.Packet is

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
      Iface : Unsigned_32;
      Stamp_Hi : Unsigned_32;
      Stamp_Lo : Unsigned_32;
      Cap : Unsigned_32;
      Orig : Unsigned_32;
      Frame : Natural;
   begin
      View :=
        (Iface_Id => 0, Ts_High => 0, Ts_Low => 0, Cap_Len => 0,
         Orig_Len => 0, Data_First => Pos, Data_Last => Pos - 1,
         Total_Length => 0, Valid => False);
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

      case Order is
         when Little_Endian =>
            Iface := Decode_U32_LE (Buf, Pos + 8);
            Stamp_Hi := Decode_U32_LE (Buf, Pos + 12);
            Stamp_Lo := Decode_U32_LE (Buf, Pos + 16);
            Cap := Decode_U32_LE (Buf, Pos + 20);
            Orig := Decode_U32_LE (Buf, Pos + 24);
         when Big_Endian =>
            Iface := Decode_U32_BE (Buf, Pos + 8);
            Stamp_Hi := Decode_U32_BE (Buf, Pos + 12);
            Stamp_Lo := Decode_U32_BE (Buf, Pos + 16);
            Cap := Decode_U32_BE (Buf, Pos + 20);
            Orig := Decode_U32_BE (Buf, Pos + 24);
      end case;

      --  caplen may not exceed origlen, and caplen + padding must fit
      --  the remaining body after the 28 fixed bytes.
      if Cap > Orig then
         Error := Bad_Length;
         return;
      end if;
      if Cap > Interfaces.Unsigned_32 (Natural'Last - Block_Header_Size
                                        - Block_Trailer_Size - 28)
        or else Pos + 28 + Natural (Cap)
                  + Natural (Padding_For (Natural (Cap))) > H_Nx
      then
         Error := Bad_Length;
         return;
      end if;
      Frame := Natural (Cap);
      pragma Assert (Frame = Natural (Cap));
      pragma Assert (Frame <= Max_Block_Size);
      pragma Assert (Padding_For (Frame) <= 3);
      pragma Assert (Frame <= Hdr.Total_Length - Block_Header_Size
                              - Block_Trailer_Size - 28);
      pragma Assert (Pos <= H_Nx - 28 - Frame
                              - Natural (Padding_For (Frame)));
      pragma Assert (Frame <= Buf'Last - Pos - 28
                              - Natural (Padding_For (Frame)));

      View :=
        (Iface_Id => Iface,
         Ts_High => Stamp_Hi, Ts_Low => Stamp_Lo,
         Cap_Len => Cap, Orig_Len => Orig,
         Data_First => Pos + 28,
         Data_Last  => (if Frame = 0 then Pos + 27 else Pos + 28 + Frame - 1),
         Total_Length => Hdr.Total_Length, Valid => True);
      Next := H_Nx;
      Error := None;
   end Parse_EPB;

   function Frame_Body_Length
     (Total : Natural) return Natural
   is
   begin
      if Total < SPB_Min_Size then
         return 0;
      end if;
      return Total - Block_Header_Size - Block_Trailer_Size - 4;
   end Frame_Body_Length;

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
