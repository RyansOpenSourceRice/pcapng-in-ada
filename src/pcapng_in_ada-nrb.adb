--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;

package body Pcapng_In_Ada.NRB is

   function Dec16
     (Buf : Byte_Buffer; Pos : Buffer_Index; Order : Byte_Order)
      return Unsigned_16
   with Pre => Pos >= Buf'First and then Pos + 1 <= Buf'Last
   is
   begin
      case Order is
         when Little_Endian => return Decode_U16_LE (Buf, Pos);
         when Big_Endian    => return Decode_U16_BE (Buf, Pos);
      end case;
   end Dec16;

   procedure Parse_NRB
     (Buf   : Byte_Buffer;
      Pos   : Buffer_Index;
      Order : Byte_Order;
      View  : out NRB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
      Hdr   : Block_Header;
      H_Nx  : Natural;
      H_Err : Error_Kind;
      Count : Natural := 0;
      P     : Natural;
      Limit : Natural;
   begin
      View :=
        (Record_Count => 0, Body_First => Pos, Body_Last => Pos - 1,
         Opt_First => 0, Total_Length => 0, Valid => False);
      Next := Pos;
      Error := Truncated;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;

      Parse_Header (Buf, Pos, Order, Hdr, H_Nx, H_Err);
      if H_Err /= None then
         Error := H_Err;
         return;
      end if;
      if Hdr.Block_Type /= NRB_Type then
         Error := Bad_Magic;
         return;
      end if;
      if Hdr.Total_Length < Min_Block_Size then
         Error := Bad_Length;
         return;
      end if;

      P := Pos + Block_Header_Size;
      Limit := Pos + Hdr.Total_Length - Block_Trailer_Size;
      --  Walk records; each step consumes >= 4 bytes so this always
      --  terminates. Cap iterations by remaining bytes for the prover.
      for I in 1 .. Max_Block_Size loop
         pragma Loop_Invariant (P >= Pos + Block_Header_Size);
         pragma Loop_Invariant (Limit <= Buf'Last or else Limit > Buf'Last);
         pragma Loop_Invariant (Count < I);
         exit when P >= Limit;
         if P + 3 > Limit - 1 and then P + 3 >= Limit then
            --  Need at least a 4-byte record header inside the body.
            if P + 3 > Limit - 1 then
               Error := Bad_Length;
               return;
            end if;
         end if;
         if P < Buf'First or else P + 3 > Buf'Last then
            Error := Truncated;
            return;
         end if;
         declare
            R_Type : constant Unsigned_16 := Dec16 (Buf, P, Order);
            R_Len  : constant Unsigned_16 := Dec16 (Buf, P + 2, Order);
            Vlen   : constant Natural := Natural (R_Len);
            Pad    : constant Natural := Padding_For (Vlen);
            Total  : Natural;
         begin
            if Vlen > Max_Block_Size then
               Error := Bad_Length;
               return;
            end if;
            Total := 4 + Vlen + Pad;
            if Total > Max_Block_Size then
               Error := Bad_Length;
               return;
            end if;
            if P + Total > Limit then
               Error := Bad_Length;
               return;
            end if;
            if P + Total - 1 > Buf'Last then
               Error := Truncated;
               return;
            end if;
            if Count < Natural'Last then
               Count := Count + 1;
            end if;
            P := P + Total;
            if R_Type = NRB_End_Record and then R_Len = 0 then
               exit;
            end if;
         end;
         exit when P >= Limit;
      end loop;

      View :=
        (Record_Count => Count,
         Body_First   => Pos + Block_Header_Size,
         Body_Last    => Limit - 1,
         Opt_First    => 0,
         Total_Length => Hdr.Total_Length, Valid => True);
      Next := H_Nx;
      Error := None;
   end Parse_NRB;

end Pcapng_In_Ada.NRB;
