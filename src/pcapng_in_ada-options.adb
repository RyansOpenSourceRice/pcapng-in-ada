--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;

package body Pcapng_In_Ada.Options is

   function Decode_16
     (Buf : Byte_Buffer; Pos : Buffer_Index; Order : Byte_Order)
      return Unsigned_16
   with Pre => Pos >= Buf'First and then Pos + 1 <= Buf'Last
   is
   begin
      case Order is
         when Little_Endian => return Decode_U16_LE (Buf, Pos);
         when Big_Endian    => return Decode_U16_BE (Buf, Pos);
      end case;
   end Decode_16;

   procedure Next_Option
     (Buf        : Byte_Buffer;
      Pos : Buffer_Index;
      Body_First : Buffer_Index;
      Body_Last  : Natural;
      Order      : Byte_Order;
      Opt        : out Option_View;
      Next       : out Natural;
      Error      : out Error_Kind)
   is
      pragma Unreferenced (Body_First);
      Code : Unsigned_16;
      Len  : Unsigned_16;
      Vlen : Natural;
      Pad  : Natural;
      Total : Natural;
   begin
      Opt := (Code => 0, Length => 0, First => 1, Last => 0, Valid => False);
      Next := Pos;
      Error := Truncated;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Body_Last < Pos then
         Error := None;
         return;
      end if;
      if Pos > Buf'Last - 3 then
         Error := Truncated;
         return;
      end if;
      if Pos + 3 > Body_Last then
         Error := Truncated;
         return;
      end if;

      Code := Decode_16 (Buf, Pos, Order);
      Len := Decode_16 (Buf, Pos + 2, Order);
      Vlen := Natural (Len);
      Pad := Padding_For (Vlen);

      if Vlen > Max_Block_Size then
         Error := Bad_Option;
         return;
      end if;
      Total := 4 + Vlen + Pad;
      if Total > Max_Block_Size then
         Error := Bad_Option;
         return;
      end if;
      if Body_Last - Pos + 1 < Total then
         Error := Truncated;
         return;
      end if;

      if Code = End_Of_Opt then
         Opt := (Code => Code, Length => 0,
                 First => Pos, Last => Pos - 1, Valid => True);
         Next := Pos + 4;
         if Next < Pos then
            Error := Bad_Option;
            return;
         end if;
         Error := None;
         return;
      end if;

      if Vlen = 0 then
         Opt := (Code => Code, Length => 0,
                 First => Pos + 4, Last => Pos + 3, Valid => True);
      else
         if Pos > Buf'Last - 4 or else Pos + 4 + Vlen - 1 > Buf'Last then
            Error := Truncated;
            return;
         end if;
         if Pos + 4 + Vlen - 1 > Body_Last then
            Error := Truncated;
            return;
         end if;
         Opt := (Code => Code, Length => Vlen,
                 First => Pos + 4, Last => Pos + 4 + Vlen - 1,
                 Valid => True);
      end if;
      Next := Pos + Total;
      Error := None;
   end Next_Option;

end Pcapng_In_Ada.Options;
