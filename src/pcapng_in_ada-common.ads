--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Endian codecs, padding arithmetic, and 64-bit timestamp helpers.
--  Every routine is bounds-checked so GNATprove Silver can show AoRTE.

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.Common is

   function Decode_U16_LE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_16
   with
     Pre  => Pos >= Buf'First and then Pos + 1 <= Buf'Last,
     Post => True;

   function Decode_U16_BE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_16
   with
     Pre  => Pos >= Buf'First and then Pos + 1 <= Buf'Last,
     Post => True;

   function Decode_U32_LE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_32
   with
     Pre  => Pos >= Buf'First and then Pos + 3 <= Buf'Last,
     Post => True;

   function Decode_U32_BE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_32
   with
     Pre  => Pos >= Buf'First and then Pos + 3 <= Buf'Last,
     Post => True;

   function Decode_U64_LE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_64
   with
     Pre  => Pos >= Buf'First and then Pos + 7 <= Buf'Last,
     Post => True;

   procedure Encode_U16_LE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_16)
   with
     Pre  => Pos >= Buf'First and then Pos + 1 <= Buf'Last,
     Post => True;

   procedure Encode_U16_BE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_16)
   with
     Pre  => Pos >= Buf'First and then Pos + 1 <= Buf'Last,
     Post => True;

   procedure Encode_U32_LE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_32)
   with
     Pre  => Pos >= Buf'First and then Pos + 3 <= Buf'Last,
     Post => True;

   procedure Encode_U32_BE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_32)
   with
     Pre  => Pos >= Buf'First and then Pos + 3 <= Buf'Last,
     Post => True;

   procedure Encode_U64_LE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_64)
   with
     Pre  => Pos >= Buf'First and then Pos + 7 <= Buf'Last,
     Post => True;

   procedure Encode_U64_BE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_64)
   with
     Pre  => Pos >= Buf'First and then Pos + 7 <= Buf'Last,
     Post => True;

   function Padding_For (Length : Natural) return Natural is
     ((4 - (Length mod 4)) mod 4)
   with
     Post => Padding_For'Result < 4;

   function Padded_Length (Length : Natural) return Natural is
     (Length + Padding_For (Length))
   with
     Pre  => Length <= Max_Block_Size,
     Post => Padded_Length'Result >= Length
       and then Padded_Length'Result < Length + 4;

   --  Swap a 32-bit word (used when the section byte order is big-endian
   --  on a little-endian host parse and vice versa).
   function Swap_32 (Value : Unsigned_32) return Unsigned_32
   with Post => True;

end Pcapng_In_Ada.Common;
