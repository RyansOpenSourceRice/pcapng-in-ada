--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;

package body Pcapng_In_Ada.ISB is

   procedure Parse_ISB
     (Buf   : Byte_Buffer;
      Pos   : Buffer_Index;
      Order : Byte_Order;
      View  : out ISB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
      Hdr : Block_Header;
      H_Nx : Natural;
      H_Err : Error_Kind;
      Ifx : Unsigned_32;
      Tsh : Unsigned_32;
      Tsl : Unsigned_32;
   begin
      View :=
        (If_Index => 0, Ts_High => 0, Ts_Low => 0,
         Body_First => Pos, Body_Last => Pos - 1, Opt_First => 0,
         Total_Length => 0, Valid => False);
      Next := Pos;
      Error := Truncated;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < ISB_Min_Size then
         return;
      end if;

      Parse_Header (Buf, Pos, Order, Hdr, H_Nx, H_Err);
      if H_Err /= None then
         Error := H_Err;
         return;
      end if;
      if Hdr.Block_Type /= ISB_Type then
         Error := Bad_Magic;
         return;
      end if;
      if Hdr.Total_Length < ISB_Min_Size then
         Error := Bad_Length;
         return;
      end if;
      if Pos > Buf'Last - 19 then
         Error := Truncated;
         return;
      end if;

      case Order is
         when Little_Endian =>
            Ifx := Decode_U32_LE (Buf, Pos + 8);
            Tsh := Decode_U32_LE (Buf, Pos + 12);
            Tsl := Decode_U32_LE (Buf, Pos + 16);
         when Big_Endian =>
            Ifx := Decode_U32_BE (Buf, Pos + 8);
            Tsh := Decode_U32_BE (Buf, Pos + 12);
            Tsl := Decode_U32_BE (Buf, Pos + 16);
      end case;

      View :=
        (If_Index => Ifx, Ts_High => Tsh, Ts_Low => Tsl,
         Body_First => Pos + 8,
         Body_Last  => Pos + Hdr.Total_Length - Block_Trailer_Size - 1,
         Opt_First  => Pos + 20,
         Total_Length => Hdr.Total_Length, Valid => True);
      Next := H_Nx;
      Error := None;
   end Parse_ISB;

end Pcapng_In_Ada.ISB;
