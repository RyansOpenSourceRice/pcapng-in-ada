--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;

package body Pcapng_In_Ada.Blocks is

   function Decode_Ordered
     (Buf : Byte_Buffer; Pos : Buffer_Index; Order : Byte_Order)
      return Unsigned_32
   with Pre => Pos >= Buf'First and then Pos + 3 <= Buf'Last
   is
   begin
      case Order is
         when Little_Endian => return Decode_U32_LE (Buf, Pos);
         when Big_Endian    => return Decode_U32_BE (Buf, Pos);
      end case;
   end Decode_Ordered;

   procedure Encode_Ordered
     (Buf : in out Byte_Buffer; Pos : Buffer_Index;
      Order : Byte_Order; Value : Unsigned_32)
   with Pre => Pos >= Buf'First and then Pos + 3 <= Buf'Last
   is
   begin
      case Order is
         when Little_Endian => Encode_U32_LE (Buf, Pos, Value);
         when Big_Endian    => Encode_U32_BE (Buf, Pos, Value);
      end case;
   end Encode_Ordered;

   function Length_Fits
     (Buf : Byte_Buffer; Pos : Buffer_Index; Total : Natural) return Boolean
   is
      Avail : Natural;
   begin
      if Pos < Buf'First or else Pos > Buf'Last then
         return False;
      end if;
      Avail := Buf'Last - Pos + 1;
      if Total < Min_Block_Size then
         return False;
      end if;
      if Total > Avail then
         return False;
      end if;
      if Total > Max_Block_Size then
         return False;
      end if;
      return True;
   end Length_Fits;

   procedure Parse_Header
     (Buf    : Byte_Buffer;
      Pos : Buffer_Index;
      Order  : Byte_Order;
      Header : out Block_Header;
      Next   : out Natural;
      Error  : out Error_Kind)
   is
      Raw_Type  : Unsigned_32;
      Raw_Len   : Unsigned_32;
      Raw_Trail : Unsigned_32;
      Total     : Natural;
      Last_Idx  : Natural;
   begin
      Header := (Block_Type => 0, Total_Length => 0, Swapped => False);
      Next := Pos;
      Error := Truncated;

      if Pos < Buf'First or else Pos > Buf'Last then
         Error := Truncated;
         return;
      end if;
      if Buf'Last - Pos + 1 < Min_Block_Size then
         Error := Truncated;
         return;
      end if;
      if Pos > Buf'Last - 7 then
         Error := Truncated;
         return;
      end if;

      Raw_Type := Decode_Ordered (Buf, Pos, Order);
      Raw_Len := Decode_Ordered (Buf, Pos + 4, Order);

      if Raw_Len < Unsigned_32 (Min_Block_Size)
        or else Raw_Len > Unsigned_32 (Max_Block_Size)
      then
         Error := Bad_Length;
         return;
      end if;

      Total := Natural (Raw_Len);
      if not Length_Fits (Buf, Pos, Total) then
         Error := Truncated;
         return;
      end if;
      --  Length_Fits guarantees Total in [12 .. Buf'Last - Pos + 1],
      --  so the index math below cannot overflow or underflow.
      pragma Assert (Total >= Min_Block_Size);
      pragma Assert (Total <= Buf'Last - Pos + 1);
      pragma Assert (Pos + Total - 1 <= Buf'Last);

      Last_Idx := Pos + Total - 1;
      pragma Assert (Last_Idx >= Pos + Min_Block_Size - 1);
      pragma Assert (Last_Idx - 3 >= Pos);
      pragma Assert (Last_Idx <= Buf'Last);
      Raw_Trail := Decode_Ordered (Buf, Last_Idx - 3, Order);
      if Raw_Trail /= Raw_Len then
         Error := Bad_Trailer;
         return;
      end if;

      Header := (Block_Type => Raw_Type,
                 Total_Length => Total,
                 Swapped => False);
      Next := Pos + Total;
      Error := None;
   end Parse_Header;

   procedure Encode_Envelope
     (Buf        : in out Byte_Buffer;
      Pos : Buffer_Index;
      Block_Type : Unsigned_32;
      Body_Len   : Natural;
      Order      : Byte_Order;
      Next       : out Natural;
      Error      : out Error_Kind)
   is
      Total : Natural;
   begin
      Next := Pos;
      Error := No_Space;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Body_Len > Max_Block_Size then
         Error := Bad_Length;
         return;
      end if;

      Total := Body_Len + Block_Header_Size + Block_Trailer_Size;
      if Total < Min_Block_Size or else Total > Max_Block_Size then
         Error := Bad_Length;
         return;
      end if;
      if Buf'Last - Pos + 1 < Total then
         Error := No_Space;
         return;
      end if;
      if Pos > Buf'Last - 7 then
         Error := No_Space;
         return;
      end if;

      Encode_Ordered (Buf, Pos, Order, Block_Type);
      Encode_Ordered (Buf, Pos + 4, Order, Unsigned_32 (Total));

      --  Total <= Buf'Last - Pos + 1 (checked above), so the trailer
      --  sits inside Buf and the index math cannot overflow.
      pragma Assert (Total >= Min_Block_Size);
      pragma Assert (Total <= Buf'Last - Pos + 1);
      pragma Assert (Pos + Total - 1 <= Buf'Last);
      declare
         Trail_Pos : constant Buffer_Index := Pos + Total - 4;
      begin
         pragma Assert (Trail_Pos >= Pos);
         pragma Assert (Trail_Pos <= Buf'Last - 3);
         Encode_Ordered (Buf, Trail_Pos, Order, Unsigned_32 (Total));
      end;

      Next := Pos + Total;
      Error := None;
   end Encode_Envelope;

end Pcapng_In_Ada.Blocks;
