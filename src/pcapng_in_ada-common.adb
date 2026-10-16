--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;

package body Pcapng_In_Ada.Common is

   function Decode_U16_LE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_16
   is
      Lo : constant Unsigned_16 := Unsigned_16 (Buf (Pos));
      Hi : constant Unsigned_16 := Unsigned_16 (Buf (Pos + 1));
   begin
      return Lo or Shift_Left (Hi, 8);
   end Decode_U16_LE;

   function Decode_U16_BE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_16
   is
      Hi : constant Unsigned_16 := Unsigned_16 (Buf (Pos));
      Lo : constant Unsigned_16 := Unsigned_16 (Buf (Pos + 1));
   begin
      return Shift_Left (Hi, 8) or Lo;
   end Decode_U16_BE;

   function Decode_U32_LE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_32
   is
      B0 : constant Unsigned_32 := Unsigned_32 (Buf (Pos));
      B1 : constant Unsigned_32 := Unsigned_32 (Buf (Pos + 1));
      B2 : constant Unsigned_32 := Unsigned_32 (Buf (Pos + 2));
      B3 : constant Unsigned_32 := Unsigned_32 (Buf (Pos + 3));
   begin
      return B0
        or Shift_Left (B1, 8)
        or Shift_Left (B2, 16)
        or Shift_Left (B3, 24);
   end Decode_U32_LE;

   function Decode_U32_BE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_32
   is
      B0 : constant Unsigned_32 := Unsigned_32 (Buf (Pos));
      B1 : constant Unsigned_32 := Unsigned_32 (Buf (Pos + 1));
      B2 : constant Unsigned_32 := Unsigned_32 (Buf (Pos + 2));
      B3 : constant Unsigned_32 := Unsigned_32 (Buf (Pos + 3));
   begin
      return Shift_Left (B0, 24)
        or Shift_Left (B1, 16)
        or Shift_Left (B2, 8)
        or B3;
   end Decode_U32_BE;

   function Decode_U64_LE
     (Buf : Byte_Buffer; Pos : Buffer_Index) return Unsigned_64
   is
      Lo : constant Unsigned_32 := Decode_U32_LE (Buf, Pos);
      Hi : constant Unsigned_32 := Decode_U32_LE (Buf, Pos + 4);
   begin
      return Unsigned_64 (Lo) or Shift_Left (Unsigned_64 (Hi), 32);
   end Decode_U64_LE;

   procedure Encode_U16_LE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_16)
   is
   begin
      Buf (Pos)     := Unsigned_8 (Value and 16#FF#);
      Buf (Pos + 1) := Unsigned_8 (Shift_Right (Value, 8) and 16#FF#);
   end Encode_U16_LE;

   procedure Encode_U16_BE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_16)
   is
   begin
      Buf (Pos)     := Unsigned_8 (Shift_Right (Value, 8) and 16#FF#);
      Buf (Pos + 1) := Unsigned_8 (Value and 16#FF#);
   end Encode_U16_BE;

   procedure Encode_U32_LE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_32)
   is
   begin
      Buf (Pos)     := Unsigned_8 (Value and 16#FF#);
      Buf (Pos + 1) := Unsigned_8 (Shift_Right (Value, 8) and 16#FF#);
      Buf (Pos + 2) := Unsigned_8 (Shift_Right (Value, 16) and 16#FF#);
      Buf (Pos + 3) := Unsigned_8 (Shift_Right (Value, 24) and 16#FF#);
   end Encode_U32_LE;

   procedure Encode_U32_BE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_32)
   is
   begin
      Buf (Pos)     := Unsigned_8 (Shift_Right (Value, 24) and 16#FF#);
      Buf (Pos + 1) := Unsigned_8 (Shift_Right (Value, 16) and 16#FF#);
      Buf (Pos + 2) := Unsigned_8 (Shift_Right (Value, 8) and 16#FF#);
      Buf (Pos + 3) := Unsigned_8 (Value and 16#FF#);
   end Encode_U32_BE;

   procedure Encode_U64_LE
     (Buf : in out Byte_Buffer; Pos : Buffer_Index; Value : Unsigned_64)
   is
      Lo : constant Unsigned_32 :=
        Unsigned_32 (Value and 16#FFFF_FFFF#);
      Hi : constant Unsigned_32 :=
        Unsigned_32 (Shift_Right (Value, 32) and 16#FFFF_FFFF#);
   begin
      Encode_U32_LE (Buf, Pos, Lo);
      Encode_U32_LE (Buf, Pos + 4, Hi);
   end Encode_U64_LE;

   function Swap_32 (Value : Unsigned_32) return Unsigned_32 is
      B0 : constant Unsigned_32 := Value and 16#FF#;
      B1 : constant Unsigned_32 :=
        Shift_Right (Value, 8) and 16#FF#;
      B2 : constant Unsigned_32 :=
        Shift_Right (Value, 16) and 16#FF#;
      B3 : constant Unsigned_32 := Shift_Right (Value, 24);
   begin
      return Shift_Left (B0, 24)
        or Shift_Left (B1, 16)
        or Shift_Left (B2, 8)
        or B3;
   end Swap_32;

end Pcapng_In_Ada.Common;
