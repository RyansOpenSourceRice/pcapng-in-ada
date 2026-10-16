--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Common; use Pcapng_In_Ada.Common;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;

package body Pcapng_In_Ada.SHB is

   function Looks_Like_SHB
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Boolean
   is
   begin
      if Pos < Buf'First or else Pos > Buf'Last then
         return False;
      end if;
      if Buf'Last - Pos + 1 < SHB_Min_Size then
         return False;
      end if;
      if Pos > Buf'Last - 7 then
         return False;
      end if;
      declare
         T_LE : constant Unsigned_32 := Decode_U32_LE (Buf, Pos);
         T_BE : constant Unsigned_32 := Decode_U32_BE (Buf, Pos);
      begin
         return T_LE = SHB_Type or else T_BE = SHB_Type;
      end;
   end Looks_Like_SHB;

   procedure Parse_SHB
     (Buf   : Byte_Buffer;
      Pos : Buffer_Index;
      View  : out SHB_View;
      Next  : out Natural;
      Error : out Error_Kind)
   is
      Order      : Byte_Order := Little_Endian;
      Magic_Raw  : Unsigned_32;
      Hdr        : Block_Header;
      H_Next     : Natural;
      H_Err      : Error_Kind;
      Major      : Unsigned_16;
      Minor      : Unsigned_16;
      Sec_Len    : Unsigned_64;
      Body_First : Buffer_Index;
      Body_Last  : Natural;
   begin
      View :=
        (Order => Little_Endian, Swapped => False, Major => 0, Minor => 0,
         Section_Length => -1, Body_First => Pos, Body_Last => Pos - 1,
         Total_Length => 0, Valid => False);
      Next := Pos;
      Error := Truncated;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Buf'Last - Pos + 1 < SHB_Min_Size then
         return;
      end if;
      if Pos > Buf'Last - 11 then
         return;
      end if;

      --  Byte order is decided by the magic at Pos + 8, read raw LE.
      Magic_Raw := Decode_U32_LE (Buf, Pos + 8);
      if Magic_Raw = Byte_Order_Magic then
         Order := Little_Endian;
      elsif Magic_Raw = 16#4D3C_2B1A# then
         Order := Big_Endian;
      else
         Error := Bad_Magic;
         return;
      end if;

      Parse_Header (Buf, Pos, Order, Hdr, H_Next, H_Err);
      if H_Err /= None then
         Error := H_Err;
         return;
      end if;
      if Hdr.Block_Type /= SHB_Type then
         Error := Bad_Magic;
         return;
      end if;
      if Hdr.Total_Length < SHB_Min_Size then
         Error := Bad_Length;
         return;
      end if;

      if Pos > Buf'Last - 15 then
         Error := Truncated;
         return;
      end if;
      if Pos > Buf'Last - 23 then
         Error := Truncated;
         return;
      end if;

      case Order is
         when Little_Endian =>
            Major := Decode_U16_LE (Buf, Pos + 12);
            Minor := Decode_U16_LE (Buf, Pos + 14);
            Sec_Len := Decode_U64_LE (Buf, Pos + 16);
         when Big_Endian =>
            Major := Decode_U16_BE (Buf, Pos + 12);
            Minor := Decode_U16_BE (Buf, Pos + 14);
            declare
               Hi : constant Unsigned_32 := Decode_U32_BE (Buf, Pos + 16);
               Lo : constant Unsigned_32 := Decode_U32_BE (Buf, Pos + 20);
            begin
               Sec_Len :=
                 Shift_Left (Unsigned_64 (Hi), 32) or Unsigned_64 (Lo);
            end;
      end case;

      --  Accept major 1 with minor 0 or 2 (writers shipped minor 2
      --  without an incompatible change). Anything else is rejected.
      if Major /= 1 or else (Minor /= 0 and then Minor /= 2) then
         Error := Bad_Version;
         return;
      end if;

      Body_First := Pos + 24;
      --  Total >= 28 and Total <= Buf'Last - Pos + 1 (via Parse_Header),
      --  so Pos + 24 <= Buf'Last - 3: the body start is in range.
      pragma Assert (Hdr.Total_Length >= SHB_Min_Size);
      pragma Assert (Hdr.Total_Length <= Buf'Last - Pos + 1);
      pragma Assert (Body_First <= Buf'Last - 3);
      if Hdr.Total_Length < Block_Header_Size + Block_Trailer_Size then
         Error := Bad_Length;
         return;
      end if;
      Body_Last := Pos + Hdr.Total_Length - Block_Trailer_Size - 1;
      if Body_First - 1 > Buf'Last or else Body_Last > Buf'Last then
         Error := Truncated;
         return;
      end if;

      View :=
        (Order          => Order,
         Swapped        => (Order = Big_Endian),
         Major          => Major,
         Minor          => Minor,
         Section_Length =>
           (if Sec_Len = 16#FFFF_FFFF_FFFF_FFFF# then -1
            else (if Sec_Len > Unsigned_64 (Integer_64'Last) then -1
                  else Integer_64 (Sec_Len))),
         Body_First     => Body_First,
         Body_Last      => Body_Last,
         Total_Length   => Hdr.Total_Length,
         Valid          => True);
      Next := H_Next;
      Error := None;
   end Parse_SHB;

end Pcapng_In_Ada.SHB;
